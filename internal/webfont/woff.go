// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webfont

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// WOFF 1.0, read and written with nothing but zlib.
//
// # Why a second format
//
// WOFF2 is what every browser in use reads best, and its tables are Brotli,
// which the standard library does not have and this program will not take a
// dependency for. So a customer holding a TrueType or OpenType file had no
// route in at all: there was nothing here to make a WOFF2 with, and a .ttf in
// templates/fonts/ was refused. WOFF 1.0 is the same tables, each compressed
// with zlib, which the standard library does have — and every browser that
// reads WOFF2 reads it too. It is a few kilobytes larger for a latin subset,
// which is the whole cost.
//
// # Why every table is inflated before it is served
//
// Because the bytes are served from the site's own origin, the same argument
// the package comment makes for WOFF2 applies with more force: this format can
// be read here, so it is. A file is refused unless its header agrees with its
// length, its tables lie inside it in order without overlapping, each one
// inflates to exactly the size it declares, the sizes add up to the total the
// header claims, and the tables a browser's font sanitiser insists on are all
// present. That is not an audit of a font parser's input, and it is not
// pretending to be; it is making sure that what reaches a reader's font
// parser is a font and the size it says it is, rather than whatever somebody
// renamed.

// signatureWOFF is WOFF 1.0's magic: "wOFF".
var signatureWOFF = []byte{0x77, 0x4F, 0x46, 0x46}

// The flavours a WOFF or an sfnt may carry: TrueType outlines, CFF outlines,
// and the old Apple TrueType tag. A collection ("ttcf") is not one: WOFF 1.0
// cannot hold one, and a .ttc is several faces where this wants one.
const (
	flavourTrueType = 0x00010000
	flavourCFF      = 0x4F54544F // "OTTO"
	flavourApple    = 0x74727565 // "true"
	flavourTTC      = 0x74746366 // "ttcf"
)

// MaxSourceBytes bounds a TrueType or OpenType file handed to Convert.
//
// Larger than MaxBytes because the point of converting is that the result is
// smaller: zlib takes a typical face to between half and two thirds of its
// size, so a source over two megabytes cannot become a face under the served
// limit, and refusing it at the door says so before any work is done.
const MaxSourceBytes = 2 << 20

// maxSfntBytes bounds what a WOFF may say it inflates to.
//
// A zlib stream can expand a thousandfold, so a half-megabyte file could
// otherwise ask for half a gigabyte of memory to be checked. Eight megabytes
// is several times the largest face anybody serves to a browser.
const maxSfntBytes = 8 << 20

// maxTables bounds the table directory. A face has a dozen or two; a header
// claiming thousands is not a face.
const maxTables = 128

// The tables Chromium's and Firefox's font sanitiser refuse a face without,
// so a face missing one is refused here, where the operator is, rather than
// by every reader's browser, silently, as a page in the fallback stack.
var requiredTables = []string{"cmap", "head", "hhea", "hmtx", "maxp", "name", "OS/2", "post"}

// table is one sfnt table, uncompressed.
type table struct {
	tag  string
	data []byte
}

// checkWOFF validates a WOFF 1.0 file and returns its tables.
func checkWOFF(b []byte) ([]table, error) {
	if len(b) < 44 || !bytes.Equal(b[:4], signatureWOFF) {
		return nil, fmt.Errorf("this is not a WOFF file — the signature is missing")
	}
	be := binary.BigEndian
	if declared := be.Uint32(b[8:12]); int(declared) != len(b) {
		return nil, fmt.Errorf(
			"the file declares %d bytes and is %d. It is truncated or it is "+
				"not the file it claims to be", declared, len(b))
	}
	if err := checkFlavour(be.Uint32(b[4:8])); err != nil {
		return nil, err
	}
	n := int(be.Uint16(b[12:14]))
	if n == 0 || n > maxTables {
		return nil, fmt.Errorf("the header lists %d tables; a face has between one and %d", n, maxTables)
	}
	if be.Uint16(b[14:16]) != 0 {
		return nil, fmt.Errorf("the header's reserved field is not zero, so this was not written by a WOFF encoder")
	}
	totalSfnt := uint64(be.Uint32(b[16:20]))
	if totalSfnt > maxSfntBytes {
		return nil, fmt.Errorf("the face says it inflates to %d bytes, and the most this will inflate is %d", totalSfnt, maxSfntBytes)
	}
	dirEnd := 44 + 20*n
	if dirEnd > len(b) {
		return nil, fmt.Errorf("the table directory runs past the end of the file")
	}

	type entry struct {
		tag                     string
		offset, comp, orig, sum uint32
	}
	entries := make([]entry, n)
	for i := range entries {
		e := b[44+20*i:]
		entries[i] = entry{tag: string(e[0:4]), offset: be.Uint32(e[4:8]),
			comp: be.Uint32(e[8:12]), orig: be.Uint32(e[12:16]), sum: be.Uint32(e[16:20])}
	}
	// The directory is in ascending tag order, as the format requires: a
	// decoder that bisects it finds nothing in one that is not.
	for i := 1; i < n; i++ {
		if entries[i].tag <= entries[i-1].tag {
			return nil, fmt.Errorf("the table directory is not in tag order (%q after %q)", entries[i].tag, entries[i-1].tag)
		}
	}

	// Every table inside the file, after the directory, on a four-byte
	// boundary, and not overlapping another: two tables sharing bytes are a
	// file built to be read two ways.
	byOffset := make([]entry, n)
	copy(byOffset, entries)
	sort.Slice(byOffset, func(i, j int) bool { return byOffset[i].offset < byOffset[j].offset })
	end := uint64(dirEnd)
	var sum uint64 = 12 + 16*uint64(n)
	for _, e := range byOffset {
		start := uint64(e.offset)
		if start%4 != 0 {
			return nil, fmt.Errorf("the %q table does not start on a four-byte boundary", e.tag)
		}
		if start < end {
			return nil, fmt.Errorf("the %q table overlaps the directory or another table", e.tag)
		}
		stop := start + uint64(e.comp)
		if stop > uint64(len(b)) {
			return nil, fmt.Errorf("the %q table runs past the end of the file", e.tag)
		}
		if e.comp > e.orig {
			return nil, fmt.Errorf("the %q table is larger compressed than it says it is uncompressed", e.tag)
		}
		end = stop
		sum += pad4(uint64(e.orig))
	}
	if sum != totalSfnt {
		return nil, fmt.Errorf("the tables add up to %d bytes and the header says %d", sum, totalSfnt)
	}
	if err := checkBlocks(b, be, end); err != nil {
		return nil, err
	}

	tables := make([]table, 0, n)
	for _, e := range entries {
		raw := b[e.offset : e.offset+e.comp]
		data := raw
		if e.comp < e.orig {
			inflated, err := inflate(raw, int(e.orig))
			if err != nil {
				return nil, fmt.Errorf("the %q table does not inflate: %v", e.tag, err)
			}
			data = inflated
		}
		tables = append(tables, table{tag: e.tag, data: data})
	}
	if err := checkTables(tables, be.Uint32(b[4:8])); err != nil {
		return nil, err
	}
	return tables, nil
}

// checkBlocks bounds the optional metadata and private blocks.
//
// Neither is read: the metadata is XML for font tools and the private block
// is the vendor's. Both still have to lie inside the file after the tables,
// so a header cannot point a reader at bytes the tables already claimed.
func checkBlocks(b []byte, be binary.ByteOrder, tablesEnd uint64) error {
	for _, blk := range []struct {
		name   string
		offset uint32
		length uint32
	}{
		{"metadata", be.Uint32(b[24:28]), be.Uint32(b[28:32])},
		{"private", be.Uint32(b[36:40]), be.Uint32(b[40:44])},
	} {
		if blk.offset == 0 && blk.length == 0 {
			continue
		}
		start, stop := uint64(blk.offset), uint64(blk.offset)+uint64(blk.length)
		if start < tablesEnd || stop > uint64(len(b)) {
			return fmt.Errorf("the %s block lies outside the space after the tables", blk.name)
		}
	}
	return nil
}

// inflate decompresses one table to exactly the size it declares.
//
// Read through a limit one byte past the declaration, so a stream that keeps
// going is caught after one byte rather than after it has filled memory.
func inflate(raw []byte, want int) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, int64(want)+1))
	if err != nil {
		return nil, err
	}
	if len(out) != want {
		return nil, fmt.Errorf("it inflates to %d bytes and declares %d", len(out), want)
	}
	return out, nil
}

// checkFlavour accepts the outline formats a WOFF may carry.
func checkFlavour(v uint32) error {
	switch v {
	case flavourTrueType, flavourCFF, flavourApple:
		return nil
	case flavourTTC:
		return fmt.Errorf("this is a font collection, several faces in one file. " +
			"Take the face you want out of it first; a web font is one face")
	}
	return fmt.Errorf("this is not a TrueType or OpenType face (its version tag is %08x)", v)
}

// checkTables is what makes a set of tables a face a browser will draw.
//
// The tables the sanitisers require; the outlines its flavour promises; the
// head table's magic number, which is the one constant every face carries;
// and the face's own statement of whether it may be embedded at all.
func checkTables(tables []table, flavour uint32) error {
	have := map[string][]byte{}
	for _, t := range tables {
		have[t.tag] = t.data
	}
	for _, tag := range requiredTables {
		if _, ok := have[tag]; !ok {
			return fmt.Errorf("the face has no %q table, and a browser's font "+
				"sanitiser refuses a face without one: it would be dropped and "+
				"every page drawn in the fallback stack", tag)
		}
	}
	if flavour == flavourCFF {
		_, cff := have["CFF "]
		_, cff2 := have["CFF2"]
		if !cff && !cff2 {
			return fmt.Errorf("the face says it has PostScript outlines and has no CFF table")
		}
	} else {
		_, glyf := have["glyf"]
		_, loca := have["loca"]
		if !glyf || !loca {
			return fmt.Errorf("the face says it has TrueType outlines and is missing glyf or loca")
		}
	}
	head := have["head"]
	if len(head) < 54 || binary.BigEndian.Uint32(head[12:16]) != 0x5F0F3CF5 {
		return fmt.Errorf("the head table is not a head table: its magic number is wrong")
	}
	return checkEmbedding(have["OS/2"])
}

// checkEmbedding reads the face's own licence flag.
//
// OS/2 fsType is how a foundry says whether a face may travel with a
// document. Serving it from /fonts/ is exactly that, to every reader. A face
// marked "restricted licence embedding" says it may not be, and a site that
// serves one anyway has published something its licence forbids; refusing it
// here is cheaper than the letter. Every other value permits it, at least for
// viewing, which is what a web page does.
func checkEmbedding(os2 []byte) error {
	if len(os2) < 10 {
		return fmt.Errorf("the OS/2 table is too short to say whether the face may be embedded")
	}
	fsType := binary.BigEndian.Uint16(os2[8:10])
	if fsType&0x000F == 0x0002 {
		return fmt.Errorf("the face's own licence flag (OS/2 fsType) says " +
			"\"restricted licence embedding\": it may not be embedded in a document or " +
			"served with one, and a web font is both. Ask its foundry for a web licence")
	}
	return nil
}

// sfntTables reads a TrueType or OpenType file into its tables.
func sfntTables(b []byte) ([]table, uint32, error) {
	be := binary.BigEndian
	if len(b) < 12 {
		return nil, 0, fmt.Errorf("the file is too short to be a font")
	}
	flavour := be.Uint32(b[0:4])
	if err := checkFlavour(flavour); err != nil {
		return nil, 0, err
	}
	n := int(be.Uint16(b[4:6]))
	if n == 0 || n > maxTables {
		return nil, 0, fmt.Errorf("the font lists %d tables; a face has between one and %d", n, maxTables)
	}
	if 12+16*n > len(b) {
		return nil, 0, fmt.Errorf("the table directory runs past the end of the file")
	}
	seen := map[string]bool{}
	tables := make([]table, 0, n)
	// What the tables come to uncompressed, counted before any is
	// compressed. The directory may point several tables at the same bytes,
	// so the file's own size bounds nothing: a hundred tables over one
	// megabyte of outlines is a hundred megabytes to compress, which took a
	// processor eleven seconds to refuse when this was counted afterwards.
	var total uint64 = 12 + 16*uint64(n)
	for i := 0; i < n; i++ {
		rec := b[12+16*i:]
		tag := string(rec[0:4])
		offset, length := uint64(be.Uint32(rec[8:12])), uint64(be.Uint32(rec[12:16]))
		if seen[tag] {
			return nil, 0, fmt.Errorf("the font has two %q tables", tag)
		}
		seen[tag] = true
		if offset+length > uint64(len(b)) {
			return nil, 0, fmt.Errorf("the %q table runs past the end of the file", tag)
		}
		if total += pad4(length); total > maxSfntBytes {
			return nil, 0, fmt.Errorf("the face's tables come to more than %d bytes "+
				"uncompressed, the most this serves", maxSfntBytes)
		}
		tables = append(tables, table{tag: tag, data: b[offset : offset+length]})
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].tag < tables[j].tag })
	if err := checkTables(tables, flavour); err != nil {
		return nil, 0, err
	}
	return tables, flavour, nil
}

// Convert makes a WOFF from a TrueType or OpenType file, and checks it.
//
// Each table is compressed with zlib where that makes it smaller and stored
// as it is where it does not, as the format allows. The checksum written for
// each table is computed from its bytes rather than copied from the source,
// so a face whose directory disagreed with its own data is not carried into
// the copy readers get. The result is then read back by the same check every
// WOFF in templates/fonts/ is held to, so what this writes is a file this
// package will serve.
func Convert(src []byte) ([]byte, error) {
	if len(src) > MaxSourceBytes {
		return nil, fmt.Errorf("%d bytes, and the most this converts is %d. "+
			"Subset it to the scripts the site uses first", len(src), MaxSourceBytes)
	}
	tables, flavour, err := sfntTables(src)
	if err != nil {
		return nil, err
	}

	n := len(tables)
	type packed struct {
		data       []byte
		orig, comp uint32
		sum        uint32
	}
	out := make([]packed, n)
	var totalSfnt uint64 = 12 + 16*uint64(n)
	for i, t := range tables {
		var z bytes.Buffer
		zw, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
		_, _ = zw.Write(t.data)
		_ = zw.Close()
		p := packed{data: t.data, orig: uint32(len(t.data)), sum: checksum(t.tag, t.data)}
		if z.Len() < len(t.data) {
			p.data = z.Bytes()
		}
		p.comp = uint32(len(p.data))
		out[i] = p
		totalSfnt += pad4(uint64(len(t.data)))
	}
	if totalSfnt > maxSfntBytes {
		return nil, fmt.Errorf("the face is %d bytes uncompressed, and the most this serves is %d", totalSfnt, maxSfntBytes)
	}

	be := binary.BigEndian
	var w bytes.Buffer
	header := make([]byte, 44)
	copy(header[0:4], signatureWOFF)
	be.PutUint32(header[4:8], flavour)
	be.PutUint16(header[12:14], uint16(n))
	be.PutUint32(header[16:20], uint32(totalSfnt))
	// The face's own revision, from head.fontRevision, so a WOFF says which
	// version of the face it is the way the file it came from did.
	for _, t := range tables {
		if t.tag == "head" {
			be.PutUint16(header[20:22], be.Uint16(t.data[4:6]))
			be.PutUint16(header[22:24], be.Uint16(t.data[6:8]))
		}
	}
	w.Write(header)
	offset := uint32(44 + 20*n)
	dir := make([]byte, 20*n)
	for i, t := range tables {
		e := dir[20*i:]
		copy(e[0:4], t.tag)
		be.PutUint32(e[4:8], offset)
		be.PutUint32(e[8:12], out[i].comp)
		be.PutUint32(e[12:16], out[i].orig)
		be.PutUint32(e[16:20], out[i].sum)
		offset += uint32(pad4(uint64(out[i].comp)))
	}
	w.Write(dir)
	for _, p := range out {
		w.Write(p.data)
		w.Write(make([]byte, pad4(uint64(len(p.data)))-uint64(len(p.data))))
	}
	b := w.Bytes()
	be.PutUint32(b[8:12], uint32(len(b)))

	if _, err := checkWOFF(b); err != nil {
		// A file this wrote and cannot read back is a bug here, not in the
		// face, and it is not handed to anybody's browser.
		return nil, fmt.Errorf("the WOFF written from this face does not read back: %v", err)
	}
	return b, nil
}

// checksum is the sfnt table checksum: the table as big-endian 32-bit words,
// zero-padded, summed. The head table is summed with its checkSumAdjustment
// taken as zero, because that field is itself derived from every checksum.
func checksum(tag string, data []byte) uint32 {
	var sum uint32
	for i := 0; i < len(data); i += 4 {
		var word [4]byte
		copy(word[:], data[i:])
		if tag == "head" && i == 8 {
			continue
		}
		sum += binary.BigEndian.Uint32(word[:])
	}
	return sum
}

func pad4(n uint64) uint64 { return (n + 3) &^ 3 }

// Sniff names what a file is from its first bytes: "woff2", "woff",
// "truetype", "opentype", "collection", or "" for none of them.
//
// From the bytes rather than the name, because the name is what somebody
// typed, and a .ttf renamed .woff2 is the commonest way a font arrives
// broken.
func Sniff(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	switch {
	case bytes.Equal(b[:4], signature):
		return "woff2"
	case bytes.Equal(b[:4], signatureWOFF):
		return "woff"
	}
	switch binary.BigEndian.Uint32(b[:4]) {
	case flavourTrueType, flavourApple:
		return "truetype"
	case flavourCFF:
		return "opentype"
	case flavourTTC:
		return "collection"
	}
	return ""
}
