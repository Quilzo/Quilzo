// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/plaintext"
)

// The index: every record as one small fixed row.
//
// # Why not the generic index
//
// The generic record index decodes each record into a map of its fields. For
// a site's data that is right, and for the register it does not fit: a
// hundred and fifty thousand test runs and pieces of evidence held as maps
// measured about 200 MB, and the question asked of them most, how each
// control stands, reads four fields of each.
//
// So a register record is indexed as a Row: its identifier, the two records
// it points at, a moment, two counts, a state and a grade. Eighty bytes,
// with no pointer in it, in a slice per kind sorted by identifier. The same
// hundred and fifty thousand rows are 12 MB, and counting how a thousand
// controls stand is one pass over one slice. What each kind puts in a row's
// fields is said beside the kind, in its index method.
//
// # Built from commits, and only as much as changed
//
// The index is a function of the register's tree and of nothing else. The
// store names every tree by the hash of what is in it, so a part of the tree
// whose name has not changed has not changed, and its rows are carried over
// from the index before. A write to one record re-reads the records that
// share the first two characters of its identifier, one part in 256, and no
// others.
//
// # Kept on disk, and checked
//
// Reading a hundred and fifty thousand records to start a process takes
// seconds, so the index is kept in a file beside the store. The file ends
// with the SHA-256 of everything before it. A file that does not match its
// digest, was cut short, or is of a version this program does not write is
// thrown away and the index is built again from the store, which is always
// possible because the store is the record and this is only a view of it.
//
// The digest finds damage. It is not a signature: somebody who can write the
// file can write its digest. Anything that has to stand up to that reader,
// a bundle or a verification, calls Rebuild, which reads the store itself.

// Row is one record as the index holds it. What About, Via, At, N, M, State
// and Grade mean is the kind's own: for Evidence they are the control, the
// test run, the moment, nothing, nothing, the outcome and the grade.
type Row struct {
	// ID is the record's identifier.
	ID [16]byte
	// About and Via are the identifiers of two records this one points at.
	About, Via [16]byte
	// At is the moment the record is about, in seconds since 1970.
	At int64
	// N and M are two counts.
	N, M uint32
	// State is a status or a type, as the position of its value in the
	// enumeration's list, counted from one. Zero is not set.
	State uint8
	// Grade is a grade, or a second small enumeration, counted the same way.
	Grade uint8
	// Flags are the yes-or-no facts below.
	Flags uint16
	// Sum is the start of the stored record's own hash.
	Sum [8]byte
}

// The flags of a row.
const (
	// FlagAlone is a decision approved by the only person eligible.
	FlagAlone uint16 = 1 << iota
	// FlagWrite is a source that holds a write scope.
	FlagWrite
	// FlagIndependent is a population whose source is not the tool measured.
	FlagIndependent
	// FlagAttested is evidence that is a person's statement.
	FlagAttested
	// FlagPrivileged is a record kept under legal privilege.
	FlagPrivileged
)

// rowDisk is how many bytes a row takes in the index file: its fields, with
// no padding. In memory a row is eighty bytes.
const (
	rowDisk   = 76
	rowMemory = 80
)

// indexer is a kind that puts something of itself in its row. A kind that
// does not is indexed by identifier alone.
type indexer interface{ index(*Row) }

// ordinal is an enumeration's value as a row holds it: its place in the
// list of values, from one, and zero for a value not in the list.
func ordinal[E interface {
	~string
	Values() []string
}](e E) uint8 {
	for i, v := range e.Values() {
		if v == string(e) {
			return uint8(i + 1)
		}
	}
	return 0
}

// clamp32 is a count as a row holds it. A count past four thousand million
// is held as that; nothing in a register is counted so high.
func clamp32(n int64) uint32 {
	switch {
	case n < 0:
		return 0
	case n > int64(^uint32(0)):
		return ^uint32(0)
	}
	return uint32(n)
}

// Index is the register at one commit, as rows.
type Index struct {
	// Head is the commit the index is of.
	Head string
	// Reused is how many rows were carried over from the index before, and
	// Read how many records were read from the store to make the rest.
	Reused, Read int
	// Discarded says why the index kept on disk was thrown away, when it
	// was: the damage that was found.
	Discarded string

	kinds map[Kind]*kindRows
}

// kindRows is one kind's rows, with the names of the trees they were read
// from.
type kindRows struct {
	// tree is the kind's collection, and shards each of the up to 256
	// trees directly under it, by name.
	tree   string
	shards map[string]string
	rows   []Row
}

// Rows is one kind's rows, in the order of their identifiers. The slice is
// the index's own: read it, do not change it.
func (ix *Index) Rows(k Kind) []Row {
	if kr := ix.kinds[k]; kr != nil {
		return kr.rows
	}
	return nil
}

// Find is the row of one record of a kind.
func (ix *Index) Find(k Kind, id ID) (Row, bool) {
	rows, want := ix.Rows(k), id.bytes()
	i := sort.Search(len(rows), func(i int) bool { return bytes.Compare(rows[i].ID[:], want[:]) >= 0 })
	if i < len(rows) && rows[i].ID == want {
		return rows[i], true
	}
	return Row{}, false
}

// Len is how many rows the index holds, over every kind.
func (ix *Index) Len() int {
	n := 0
	for _, kr := range ix.kinds {
		n += len(kr.rows)
	}
	return n
}

// Bytes is how much memory the index takes: its rows, and the names of the
// trees it remembers.
func (ix *Index) Bytes() int {
	n := 0
	for _, kr := range ix.kinds {
		n += len(kr.rows)*rowMemory + len(kr.shards)*(64+2+16) + 64
	}
	return n
}

// Equal reports whether two indexes hold the same rows of the same commit.
func (ix *Index) Equal(other *Index) bool {
	if ix.Head != other.Head || len(ix.kinds) != len(other.kinds) {
		return false
	}
	for k, a := range ix.kinds {
		b := other.kinds[k]
		if b == nil || a.tree != b.tree || len(a.rows) != len(b.rows) {
			return false
		}
		for i := range a.rows {
			if a.rows[i] != b.rows[i] {
				return false
			}
		}
	}
	return true
}

// shard is the rows whose identifiers begin with the byte a shard is named
// for: a run of the sorted slice, found by search.
func (kr *kindRows) shard(name string) ([]Row, bool) {
	var b [1]byte
	if len(name) != 2 {
		return nil, false
	}
	if _, err := hex.Decode(b[:], []byte(name)); err != nil {
		return nil, false
	}
	lo := sort.Search(len(kr.rows), func(i int) bool { return kr.rows[i].ID[0] >= b[0] })
	hi := sort.Search(len(kr.rows), func(i int) bool { return kr.rows[i].ID[0] > b[0] })
	return kr.rows[lo:hi], true
}

// Index is the register as rows, at the commit it stands at now. The first
// call in a process reads the file kept beside the store; each call after a
// write reads only what the write changed.
func (r *Register) Index() (*Index, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	head := r.Store.GetRef(Ref)
	if r.ix != nil && r.ix.Head == head {
		return r.ix, nil
	}
	prev, discarded := r.ix, ""
	if prev == nil {
		prev, discarded = r.loadIndex()
	}
	if prev != nil && prev.Head == head {
		r.ix = prev
		return prev, nil
	}
	ix, err := r.build(head, prev)
	if err != nil {
		return nil, err
	}
	ix.Discarded = discarded
	// Kept for the next process. A store on a disk that cannot be written
	// is still read: the index is then built each time, and is as right.
	_ = r.saveIndex(ix)
	r.ix = ix
	return ix, nil
}

// Rebuild is the index made from the store alone, with nothing carried over
// from memory or from the file. It is what the index must equal, and what a
// reader who cannot take a cache on trust asks for.
func (r *Register) Rebuild() (*Index, error) {
	return r.build(r.Store.GetRef(Ref), nil)
}

// build makes the index of a commit, carrying over from prev the rows of
// every tree whose name is the same.
func (r *Register) build(commit string, prev *Index) (*Index, error) {
	ix := &Index{Head: commit, kinds: map[Kind]*kindRows{}}
	if commit == "" {
		return ix, nil
	}
	c, err := r.Store.GetCommit(commit)
	if err != nil {
		return nil, fmt.Errorf("the register's head cannot be read: %w", err)
	}
	root, err := r.Store.GetTree(c.Tree)
	if err != nil {
		return nil, err
	}
	if root["data"] == "" {
		return ix, nil
	}
	data, err := r.Store.GetTree(root["data"])
	if err != nil {
		return nil, err
	}
	for _, spec := range Kinds() {
		coll := data[spec.Collection]
		if coll == "" {
			continue
		}
		var was *kindRows
		if prev != nil {
			was = prev.kinds[spec.Kind]
		}
		if was != nil && was.tree == coll {
			ix.kinds[spec.Kind] = was
			ix.Reused += len(was.rows)
			continue
		}
		kr := &kindRows{tree: coll, shards: map[string]string{}}
		top, err := r.Store.GetTree(coll)
		if err != nil {
			return nil, err
		}
		for _, name := range sortedKeys(top) {
			kr.shards[name] = top[name]
			if was != nil && was.shards[name] == top[name] {
				if rows, ok := was.shard(name); ok {
					kr.rows = append(kr.rows, rows...)
					ix.Reused += len(rows)
					continue
				}
			}
			n, err := r.readShard(kinds[spec.Kind], top[name], &kr.rows)
			if err != nil {
				return nil, err
			}
			ix.Read += n
		}
		// The shards were read in the order of their names and each leaf
		// in the order of its identifiers, which is the order of the
		// identifiers; a store that files a record under a name its
		// identifier does not begin with is put right here.
		if !sort.SliceIsSorted(kr.rows, func(i, j int) bool { return bytes.Compare(kr.rows[i].ID[:], kr.rows[j].ID[:]) < 0 }) {
			sort.Slice(kr.rows, func(i, j int) bool { return bytes.Compare(kr.rows[i].ID[:], kr.rows[j].ID[:]) < 0 })
		}
		ix.kinds[spec.Kind] = kr
	}
	return ix, nil
}

// readShard reads every record under one first-level shard into rows.
func (r *Register) readShard(spec *Spec, shard string, rows *[]Row) (int, error) {
	second, err := r.Store.GetTree(shard)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range sortedKeys(second) {
		leaf, err := r.Store.GetTree(second[name])
		if err != nil {
			return n, err
		}
		for _, id := range sortedKeys(leaf) {
			row, err := r.rowAt(spec, ID(id), leaf[id])
			if err != nil {
				return n, err
			}
			*rows = append(*rows, row)
			n++
		}
	}
	return n, nil
}

// rowAt is the row of the record stored at an object.
func (r *Register) rowAt(spec *Spec, id ID, oid string) (Row, error) {
	e, st, err := r.entryAt(spec, oid)
	if err != nil {
		return Row{}, fmt.Errorf("the %s %s cannot be read: %w", spec.Kind, id, err)
	}
	if ID(st.ID) != id || !id.Valid() {
		return Row{}, fmt.Errorf("the store holds a %s filed under %s that says it is %s", spec.Kind, id, clipped(st.ID))
	}
	return rowOf(e.Record, id, oid), nil
}

// rowOf is a record's row.
func rowOf(rec Record, id ID, oid string) Row {
	row := Row{ID: id.bytes()}
	if ixr, ok := rec.(indexer); ok {
		ixr.index(&row)
	}
	if a := approvalOf(rec); a != nil && a.Alone {
		row.Flags |= FlagAlone
	}
	if len(oid) >= 16 {
		hex.Decode(row.Sum[:], []byte(oid[:16]))
	}
	return row
}

// The file.
//
//	"QZRIDX1\n"                       eight bytes
//	the head commit                   64 bytes of hexadecimal, or 64 zero bytes
//	how many kinds                    uint32
//	for each kind, in order:
//	  the kind's name                 uint16 length, then the name
//	  its collection's tree           64 bytes
//	  how many shards, then each      uint32; a 2-byte name and a 64-byte tree
//	  how many rows, then each        uint32; 76 bytes
//	SHA-256 of everything above       32 bytes
//
// Numbers are little-endian.

var indexMagic = []byte("QZRIDX1\n")

func (r *Register) indexPath() string {
	return filepath.Join(r.Store.Root(), "register", "index")
}

func (r *Register) saveIndex(ix *Index) error {
	var b bytes.Buffer
	b.Write(indexMagic)
	b.WriteString(oid64(ix.Head))
	names := make([]string, 0, len(ix.kinds))
	for k := range ix.kinds {
		names = append(names, string(k))
	}
	sort.Strings(names)
	put32 := func(n int) { binary.Write(&b, binary.LittleEndian, uint32(n)) }
	put32(len(names))
	for _, name := range names {
		kr := ix.kinds[Kind(name)]
		binary.Write(&b, binary.LittleEndian, uint16(len(name)))
		b.WriteString(name)
		b.WriteString(oid64(kr.tree))
		put32(len(kr.shards))
		for _, s := range sortedKeys(kr.shards) {
			b.WriteString(pad(s, 2))
			b.WriteString(oid64(kr.shards[s]))
		}
		put32(len(kr.rows))
		var row [rowDisk]byte
		for i := range kr.rows {
			encodeRow(&row, &kr.rows[i])
			b.Write(row[:])
		}
	}
	sum := sha256.Sum256(b.Bytes())
	b.Write(sum[:])
	if err := os.MkdirAll(filepath.Dir(r.indexPath()), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(r.indexPath(), b.Bytes(), 0o600)
}

// loadIndex reads the file. It answers nil with a reason when the file is
// damaged, and nil with no reason when there is none yet.
func (r *Register) loadIndex() (*Index, string) {
	data, err := os.ReadFile(r.indexPath())
	if os.IsNotExist(err) {
		return nil, ""
	}
	if err != nil {
		return nil, "the index file could not be read: " + err.Error()
	}
	if len(data) < len(indexMagic)+64+4+32 || !bytes.Equal(data[:len(indexMagic)], indexMagic) {
		return nil, "the index file is not one this program wrote"
	}
	body, trailer := data[:len(data)-32], data[len(data)-32:]
	if sum := sha256.Sum256(body); !bytes.Equal(sum[:], trailer) {
		return nil, "the index file does not match its digest"
	}
	rd := bytes.NewReader(body[len(indexMagic):])
	short := "the index file ends before it should"
	take := func(n int) ([]byte, bool) {
		if n < 0 || n > rd.Len() {
			return nil, false
		}
		out := make([]byte, n)
		rd.Read(out)
		return out, true
	}
	get32 := func() (int, bool) {
		b, ok := take(4)
		if !ok {
			return 0, false
		}
		return int(binary.LittleEndian.Uint32(b)), true
	}
	head, ok := take(64)
	if !ok {
		return nil, short
	}
	ix := &Index{Head: unpad(head), kinds: map[Kind]*kindRows{}}
	nk, ok := get32()
	if !ok {
		return nil, short
	}
	for i := 0; i < nk; i++ {
		l, ok := take(2)
		if !ok {
			return nil, short
		}
		name, ok := take(int(binary.LittleEndian.Uint16(l)))
		if !ok {
			return nil, short
		}
		tree, ok := take(64)
		if !ok {
			return nil, short
		}
		kr := &kindRows{tree: unpad(tree), shards: map[string]string{}}
		ns, ok := get32()
		if !ok || ns > rd.Len()/66 {
			return nil, short
		}
		for j := 0; j < ns; j++ {
			s, _ := take(2)
			t, ok := take(64)
			if !ok {
				return nil, short
			}
			kr.shards[unpad(s)] = unpad(t)
		}
		nr, ok := get32()
		if !ok || nr > rd.Len()/rowDisk {
			return nil, short
		}
		kr.rows = make([]Row, nr)
		for j := range kr.rows {
			b, _ := take(rowDisk)
			decodeRow(&kr.rows[j], b)
		}
		if _, known := kinds[Kind(name)]; known {
			ix.kinds[Kind(name)] = kr
		}
	}
	if rd.Len() != 0 {
		return nil, "the index file holds more than its rows"
	}
	return ix, ""
}

func encodeRow(b *[rowDisk]byte, r *Row) {
	copy(b[0:16], r.ID[:])
	copy(b[16:32], r.About[:])
	copy(b[32:48], r.Via[:])
	binary.LittleEndian.PutUint64(b[48:56], uint64(r.At))
	binary.LittleEndian.PutUint32(b[56:60], r.N)
	binary.LittleEndian.PutUint32(b[60:64], r.M)
	b[64], b[65] = r.State, r.Grade
	binary.LittleEndian.PutUint16(b[66:68], r.Flags)
	copy(b[68:76], r.Sum[:])
}

func decodeRow(r *Row, b []byte) {
	copy(r.ID[:], b[0:16])
	copy(r.About[:], b[16:32])
	copy(r.Via[:], b[32:48])
	r.At = int64(binary.LittleEndian.Uint64(b[48:56]))
	r.N = binary.LittleEndian.Uint32(b[56:60])
	r.M = binary.LittleEndian.Uint32(b[60:64])
	r.State, r.Grade = b[64], b[65]
	r.Flags = binary.LittleEndian.Uint16(b[66:68])
	copy(r.Sum[:], b[68:76])
}

// oid64 is an object's name as the file holds it: its 64 characters, or 64
// zero bytes for none.
func oid64(oid string) string { return pad(oid, 64) }

// pad is a name as the file holds it, in n bytes: zero-filled when it is
// shorter, and cut when it is longer, which no name the index writes is,
// since each is a store object's 64 characters or a shard's two.
func pad(s string, n int) string {
	if len(s) >= n {
		return plaintext.Clip(s, n, "")
	}
	return s + string(bytes.Repeat([]byte{0}, n-len(s)))
}

func unpad(b []byte) string { return string(bytes.TrimRight(b, "\x00")) }
