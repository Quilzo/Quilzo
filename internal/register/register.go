// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/store"
)

const (
	// Ref is the store ref the record of the register lives on. It is never
	// promoted anywhere: nothing publishes the register to a site.
	Ref = "register"
	// ProposalsRef is where what a model or a crew proposes waits for a
	// person. Posture, figures, the index and bundles read Ref and never
	// this one.
	ProposalsRef = "register-proposals"
	// Area is the register's place in the access policy. It sits inside
	// the compliance area, which a role over the site reaches only as
	// administrator, so somebody who may read the site's pages does not
	// thereby read its risks; the compliance officer and the auditor, whose
	// jobs are granted on that area, reach it without a grant of their own.
	Area = auth.AreaCompliance + "/register"
)

// ErrNotFound is a record, or a proposal, that is not there.
var ErrNotFound = errors.New("no such record in the register")

// Register is the security record of one organisation, on one store.
//
// The zero value is not usable; Open makes one. The hooks are the host's:
// this package does not know where the audit log is or who is signed in, and
// a write is refused until it has been told how to record itself.
type Register struct {
	Store *store.Store

	// Audit records a write, or a refusal to write. Put refuses to write
	// at all while it is nil: a record of evidence that nobody can show
	// was written by whom is not one.
	Audit func(audit.Record) error
	// Ready reports, before anything is committed, whether the audit entry
	// could be written. Nil means it is not asked.
	Ready func() error
	// Approvals checks an approval's authentication evidence against the
	// record it approves. The shape of an approval, and the rule that the
	// person who asked is not the one who agreed, are checked here whether
	// or not this is set; what a passkey asserted is the approvals
	// module's to verify.
	Approvals func(rec Record, id ID, a *Approval) error
	// Now is the clock, for tests. Nil is the system's.
	Now func() time.Time

	mu sync.Mutex
	ix *Index
}

// Open is the register on a store.
func Open(s *store.Store) *Register { return &Register{Store: s} }

func (r *Register) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Actor is who is writing, and how the surface they came through asks the
// access policy about them.
type Actor struct {
	// Name is the principal, as the audit log names it. It goes in the
	// audit entry and nowhere in the store.
	Name string
	// Subject is the pseudonym that stands for them in the record, when
	// they have one. It is the author of the commit, in place of a name.
	Subject ID
	// Kind is whether a person, a service or a model is writing. A model
	// may propose and may not write the record.
	Kind audit.Kind
	// Verified says the surface proved who they are.
	Verified bool
	// Model is what an agent's acts are recorded as having been decided
	// by, as the audit log's own field has it.
	Model string
	// May asks the policy gate, as this session with its own limits. Nil
	// refuses everything: a surface that forgot the gate has none.
	May func(act auth.Action, resource string) error
}

// stored is a record as the store holds it. It is the generic record's
// shape, an identifier, the fields and two stamps, so that anything that
// reads the generic shape can read a register record too.
type stored struct {
	ID      string          `json:"id"`
	Fields  json.RawMessage `json:"fields"`
	Created int64           `json:"created"`
	Updated int64           `json:"updated"`
	// Proposed is set on the proposals ref only: who proposed the record,
	// and why. See proposals.go.
	Proposed *proposed `json:"proposed,omitempty"`
}

// Entry is a record read back from the register.
type Entry struct {
	ID   ID   `json:"id"`
	Kind Kind `json:"kind"`
	// Record is the typed record: a Control, an Evidence.
	Record Record `json:"record"`
	// Created is when the record was first written, and Updated when its
	// fields last changed.
	Created Time `json:"created"`
	Updated Time `json:"updated"`
	// Object is the identifier of the stored object, which is the hash of
	// the record as it stands. Shown beside a figure, it is what a reader
	// checks the figure's source against.
	Object string `json:"object"`
}

// canonicalFields is a record's fields as bytes that are the same whoever
// wrote them: keys in order, numbers as they were written.
func canonicalFields(rec Record) (json.RawMessage, error) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// decode turns stored fields back into the kind's own type. A field the
// kind does not have is refused, not dropped: a record that reads back as
// less than was written is not the record.
func (s *Spec) decode(fields json.RawMessage) (Record, error) {
	ptr := reflect.New(s.typ)
	dec := json.NewDecoder(bytes.NewReader(fields))
	dec.DisallowUnknownFields()
	if err := dec.Decode(ptr.Interface()); err != nil {
		return nil, fmt.Errorf("a stored %s does not read as one: %w", s.Kind, err)
	}
	rec, ok := ptr.Elem().Interface().(Record)
	if !ok {
		return nil, fmt.Errorf("%s is not a record", s.Kind)
	}
	return rec, nil
}

// reader reads trees of one store, each once.
type reader struct {
	s     *store.Store
	trees map[string]map[string]string
}

func newReader(s *store.Store) *reader {
	return &reader{s: s, trees: map[string]map[string]string{}}
}

func (rd *reader) tree(oid string) (map[string]string, error) {
	if t, ok := rd.trees[oid]; ok {
		return t, nil
	}
	t, err := rd.s.GetTree(oid)
	if err != nil {
		return nil, err
	}
	rd.trees[oid] = t
	return t, nil
}

// lookup follows a path down from a root tree, one small tree a level, and
// reports the object at its end. It reads five trees to find a record among
// any number, where flattening the tree would read them all.
func (rd *reader) lookup(root, path string) (string, bool, error) {
	oid := root
	for len(path) > 0 {
		if oid == "" {
			return "", false, nil
		}
		t, err := rd.tree(oid)
		if err != nil {
			return "", false, err
		}
		seg := path
		if i := strings.IndexByte(path, '/'); i >= 0 {
			seg, path = path[:i], path[i+1:]
		} else {
			path = ""
		}
		next, ok := t[seg]
		if !ok {
			return "", false, nil
		}
		oid = next
	}
	return oid, oid != "", nil
}

// treeAt is the tree a ref's head commit holds, and the commit. Both are
// empty for a ref nothing was ever written to.
func (r *Register) treeAt(ref string) (tree, commit string, err error) {
	commit = r.Store.GetRef(ref)
	if commit == "" {
		return "", "", nil
	}
	c, err := r.Store.GetCommit(commit)
	if err != nil {
		return "", "", fmt.Errorf("the %s ref points at a commit that cannot be read: %w", ref, err)
	}
	return c.Tree, commit, nil
}

// entryAt reads the record of a kind stored at an object.
func (r *Register) entryAt(spec *Spec, oid string) (Entry, *stored, error) {
	var st stored
	if err := r.Store.GetBlob(oid, &st); err != nil {
		return Entry{}, nil, err
	}
	rec, err := spec.decode(st.Fields)
	if err != nil {
		return Entry{}, nil, err
	}
	return Entry{ID: ID(st.ID), Kind: spec.Kind, Record: rec, Created: Time(st.Created),
		Updated: Time(st.Updated), Object: oid}, &st, nil
}

// Get reads one record by its identifier, whatever kind it is. An
// identifier names one record across the register, so the kind need not be
// said.
func (r *Register) Get(id ID) (Entry, error) { return r.getOn(Ref, id) }

func (r *Register) getOn(ref string, id ID) (Entry, error) {
	if !id.Valid() {
		return Entry{}, fmt.Errorf("%w: %q is not a record's identifier", ErrNotFound, clipped(string(id)))
	}
	tree, _, err := r.treeAt(ref)
	if err != nil {
		return Entry{}, err
	}
	rd := newReader(r.Store)
	for _, spec := range Kinds() {
		oid, ok, err := rd.lookup(tree, collection.Path(spec.Collection, string(id)))
		if err != nil {
			return Entry{}, err
		}
		if ok {
			e, _, err := r.entryAt(kinds[spec.Kind], oid)
			return e, err
		}
	}
	return Entry{}, fmt.Errorf("%w: %s", ErrNotFound, id)
}

// List reads a page of one kind's records, in the order of their
// identifiers, and how many the kind holds. The order is stable from one
// call to the next, so a page is a page.
func (r *Register) List(kind Kind, offset, limit int) ([]Entry, int, error) {
	spec, err := specFor(kind)
	if err != nil {
		return nil, 0, err
	}
	ix, err := r.Index()
	if err != nil {
		return nil, 0, err
	}
	rows := ix.Rows(kind)
	total := len(rows)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	end := total
	if limit > 0 && offset+limit < total {
		end = offset + limit
	}
	tree, _, err := r.treeAt(Ref)
	if err != nil {
		return nil, 0, err
	}
	rd := newReader(r.Store)
	out := make([]Entry, 0, end-offset)
	for _, row := range rows[offset:end] {
		id := idOf(row.ID)
		oid, ok, err := rd.lookup(tree, collection.Path(spec.Collection, string(id)))
		if err != nil {
			return nil, 0, err
		}
		if !ok {
			// The record was written after the index was taken and before
			// this read; the next call sees it.
			continue
		}
		e, _, err := r.entryAt(spec, oid)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, nil
}

// Counts is how many records each kind holds, for the kinds that hold any.
func (r *Register) Counts() (map[Kind]int, error) {
	ix, err := r.Index()
	if err != nil {
		return nil, err
	}
	out := map[Kind]int{}
	for _, s := range Kinds() {
		if n := len(ix.Rows(s.Kind)); n > 0 {
			out[s.Kind] = n
		}
	}
	return out, nil
}

// Head is the commit the register stands at: the hash that names the whole
// record as it is now. Empty for a register nothing was written to.
func (r *Register) Head() string { return r.Store.GetRef(Ref) }

// sortedKeys is a map's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
