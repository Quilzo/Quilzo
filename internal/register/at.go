// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/collection"
)

// The register as it stood at one of its commits.
//
// The store keeps every commit, so what the register said at any moment it
// was written can be read again exactly. A control test reads the register
// at its head and names the commit it read; a replay of that run reads the
// same commit, and so the same facts, the same test and the same
// population, whatever has been written since.

// View is the register at one commit, for reading.
type View struct {
	r      *Register
	commit string
	tree   string
	rd     *reader
}

// At is the register at a commit it made on its own ref, or at its head when
// commit is empty. A commit of the proposals ref, or of anything that is not
// the register, is refused: what was proposed is not what the register said.
func (r *Register) At(commit string) (*View, error) {
	if commit == "" {
		tree, head, err := r.treeAt(Ref)
		if err != nil {
			return nil, err
		}
		return &View{r: r, commit: head, tree: tree, rd: newReader(r.Store)}, nil
	}
	c, err := r.Store.GetCommit(commit)
	if err != nil {
		return nil, fmt.Errorf("%w: the register made no commit %s that can be read", ErrNotFound, clipped(commit))
	}
	if c.Meta["register"] != Ref {
		return nil, fmt.Errorf("%w: %s is not a commit of the register", ErrNotFound, clipped(commit))
	}
	return &View{r: r, commit: commit, tree: c.Tree, rd: newReader(r.Store)}, nil
}

// Commit is the commit the view reads, empty for a register nothing was
// written to.
func (v *View) Commit() string { return v.commit }

// Get reads one record as it stood at the view's commit.
func (v *View) Get(id ID) (Entry, error) {
	if !id.Valid() {
		return Entry{}, fmt.Errorf("%w: %q is not a record's identifier", ErrNotFound, clipped(string(id)))
	}
	for _, spec := range Kinds() {
		oid, ok, err := v.rd.lookup(v.tree, collection.Path(spec.Collection, string(id)))
		if err != nil {
			return Entry{}, err
		}
		if ok {
			e, _, err := v.r.entryAt(kinds[spec.Kind], oid)
			return e, err
		}
	}
	return Entry{}, fmt.Errorf("%w: %s", ErrNotFound, id)
}

// Each calls fn with every record of a kind as it stood at the view's
// commit, in the order of their identifiers, with the record's fields as
// they are stored: the JSON a query compares, each value as it was written.
// An error from fn stops the walk and is returned.
func (v *View) Each(kind Kind, fn func(e Entry, fields map[string]any) error) error {
	spec, err := specFor(kind)
	if err != nil {
		return err
	}
	if v.tree == "" {
		return nil
	}
	sub, ok, err := v.rd.lookup(v.tree, strings.TrimSuffix(collection.Prefix(spec.Collection), "/"))
	if err != nil || !ok {
		return err
	}
	paths, err := v.r.Store.GetNested(sub)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(paths))
	for p := range paths {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	for _, p := range keys {
		e, st, err := v.r.entryAt(spec, paths[p])
		if err != nil {
			return err
		}
		var fields map[string]any
		if err := json.NewDecoder(bytes.NewReader(st.Fields)).Decode(&fields); err != nil {
			return fmt.Errorf("a stored %s does not read as one: %w", spec.Kind, err)
		}
		if err := fn(e, fields); err != nil {
			return err
		}
	}
	return nil
}
