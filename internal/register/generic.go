// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
)

// What every surface reads of any kind: a record's history, a kind's
// records filtered by a field's value, the same as a spreadsheet, and the
// risks in the order of their rating.
//
// One implementation over every kind, read from the kind's schema, so a
// kind added later is listed, filtered, exported and followed through its
// history on the command line, the admin, the agent interface and the API
// without an edit to any of them. Nothing here writes, and nothing here
// reads the site's records: the register is read from its own ref.

// Change is one commit that changed a record: when, why, under whose
// pseudonym, and the object the record was stored as after it.
type Change struct {
	// Commit is the commit that changed it, and Parent the one before.
	Commit string `json:"commit"`
	Parent string `json:"parent,omitempty"`
	At     Time   `json:"at"`
	// By is the pseudonym of whoever wrote it, as the commit's author has
	// it; empty for a service, which has none.
	By ID `json:"by,omitempty"`
	// Why is the line the write said it was, written by code.
	Why string `json:"why"`
	// Object is the record as that commit left it, by its hash.
	Object string `json:"object"`
	// New says the commit wrote the record for the first time.
	New bool `json:"new,omitempty"`
}

// History is the commits that changed a record, newest first, at most
// limit of them (none is every one). A commit that did not touch the
// record is not in it.
//
// It walks the register's first parents from its head and reads, in each
// commit's tree, the five small trees down to the record, so a register of
// many commits is read a commit at a time and never flattened.
func (r *Register) History(id ID, limit int) ([]Change, error) {
	e, err := r.Get(id)
	if err != nil {
		return nil, err
	}
	path := collection.Path(kinds[e.Kind].Collection, string(id))
	rd := newReader(r.Store)
	var out []Change
	// pending is the newer commit whose object differs from what this one
	// holds: it changed the record, and is written out once the commit
	// before it has been read.
	var pending *Change
	commit := r.Store.GetRef(Ref)
	for commit != "" {
		c, err := r.Store.GetCommit(commit)
		if err != nil {
			return nil, fmt.Errorf("the register's commit %s cannot be read: %w", commit, err)
		}
		oid, _, err := rd.lookup(c.Tree, path)
		if err != nil {
			return nil, err
		}
		if pending != nil {
			if oid != pending.Object {
				pending.New = oid == ""
				out = append(out, *pending)
				if limit > 0 && len(out) >= limit {
					return out, nil
				}
			}
			pending = nil
		}
		if oid == "" {
			break
		}
		parent := ""
		if len(c.Parents) > 0 {
			parent = c.Parents[0]
		}
		pending = &Change{Commit: commit, Parent: parent, At: Time(c.At), By: ID(c.Author), Why: c.Message, Object: oid}
		commit = parent
	}
	if pending != nil {
		pending.New = true
		out = append(out, *pending)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Filter is a field of a kind and the value it must hold: field=value. A
// list matches when any of its members does; a time is matched as the
// seconds it holds, as it is stored.
type Filter struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

func (f Filter) String() string { return f.Field + "=" + f.Value }

// ParseFilter reads field=value. The value may be empty, which matches a
// field that is not set.
func ParseFilter(s string) (Filter, error) {
	field, value, ok := strings.Cut(s, "=")
	field = strings.TrimSpace(field)
	if !ok || field == "" {
		return Filter{}, fmt.Errorf("%w: a filter is field=value, such as status=open, and %q is not one", ErrInvalid, clipped(s))
	}
	return Filter{Field: field, Value: value}, nil
}

// filterable is the field of a kind a filter names, or why it cannot be
// filtered on. An object is not one value, so it is not.
func filterable(spec *Spec, name string) (Field, error) {
	for _, f := range spec.Fields {
		if f.Name != name {
			continue
		}
		if strings.HasSuffix(f.Type, "object") {
			return Field{}, fmt.Errorf("%w: the %s field %q holds an object, which is not one value to filter on", ErrInvalid,
				strings.ToLower(string(spec.Kind)), name)
		}
		return f, nil
	}
	var names []string
	for _, f := range spec.Fields {
		if !strings.HasSuffix(f.Type, "object") {
			names = append(names, f.Name)
		}
	}
	return Field{}, fmt.Errorf("%w: a %s has no field %q; it is filtered on %s", ErrInvalid,
		strings.ToLower(string(spec.Kind)), clipped(name), strings.Join(names, ", "))
}

// Find is a page of one kind's records whose fields hold the values the
// filters say, every filter at once, in the order of their identifiers,
// and how many match. With no filter it is List.
func (r *Register) Find(kind Kind, filters []Filter, offset, limit int) ([]Entry, int, error) {
	spec, err := specFor(kind)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(filters) == 0 {
		return r.List(kind, offset, limit)
	}
	for _, f := range filters {
		if _, err := filterable(spec, f.Field); err != nil {
			return nil, 0, err
		}
	}
	all, _, err := r.List(kind, 0, 0)
	if err != nil {
		return nil, 0, err
	}
	var hits []Entry
	for _, e := range all {
		values := valuesOf(e.Record)
		ok := true
		for _, f := range filters {
			if !matches(values[f.Field], f.Value) {
				ok = false
				break
			}
		}
		if ok {
			hits = append(hits, e)
		}
	}
	total := len(hits)
	offset = min(max(offset, 0), total)
	end := total
	if limit > 0 && offset+limit < total {
		end = offset + limit
	}
	return hits[offset:end], total, nil
}

// valuesOf is a record's fields as JSON, by name.
func valuesOf(rec Record) map[string]json.RawMessage {
	raw, _ := json.Marshal(rec)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	return m
}

// matches reports whether a field's stored value is the value a filter
// asks for: a string as itself, a number or a yes or no as JSON writes
// it, and a list when any member is.
func matches(v json.RawMessage, want string) bool {
	if len(v) == 0 || string(v) == "null" {
		return want == ""
	}
	var list []json.RawMessage
	if json.Unmarshal(v, &list) == nil {
		for _, m := range list {
			if matches(m, want) {
				return true
			}
		}
		return len(list) == 0 && want == ""
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s == want
	}
	return string(v) == want
}

// rated is a kind whose records have a rating code works out from their
// typed fields, for the top of a register: a risk's likelihood times its
// impact. A kind gains the column in its export, and a top, by having the
// method.
type rated interface{ rating() int64 }

// Rating is a record's rating, and whether its kind has one.
func Rating(rec Record) (int64, bool) {
	if r, ok := rec.(rated); ok {
		return r.rating(), true
	}
	return 0, false
}

// Top is the n records rated highest, highest first, those rated alike in
// the order of their natural keys; none is every one. A kind with no
// rating has no top, and is refused.
func Top(entries []Entry, n int) ([]Entry, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	if _, ok := Rating(entries[0].Record); !ok {
		return nil, fmt.Errorf("%w: a %s has no rating to put the highest first by", ErrInvalid,
			strings.ToLower(string(entries[0].Kind)))
	}
	out := append([]Entry(nil), entries...)
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := Rating(out[i].Record)
		b, _ := Rating(out[j].Record)
		if a != b {
			return a > b
		}
		_, ka := out[i].Record.Key()
		_, kb := out[j].Record.Key()
		return ka < kb
	})
	if n > 0 && n < len(out) {
		out = out[:n]
	}
	return out, nil
}

// ExportColumns is the columns a kind's export has, in order: the
// record's identifier, when it was written and changed, the hash it is
// stored under, each field of the schema, and its rating when its kind
// has one.
func ExportColumns(spec Spec) []string {
	cols := []string{"id", "created", "updated", "object"}
	for _, f := range spec.Fields {
		cols = append(cols, f.Name)
	}
	if spec.typ != nil {
		if _, ok := reflect.Zero(spec.typ).Interface().(rated); ok {
			cols = append(cols, "rating")
		}
	}
	return cols
}

// WriteCSV writes records of one kind as CSV, a column per field of its
// schema (ExportColumns), every cell safe to open in a spreadsheet.
//
// A record's fields are what somebody's source said, and a title that
// begins with an equals sign is a formula to a spreadsheet that opens the
// file: it can fetch an address with the cells beside it in the query, or
// start a program. Every cell that begins with =, +, -, @, a tab or a
// carriage return is written after an apostrophe, which a spreadsheet
// shows as text and does not run, as OWASP's advice on CSV injection has
// it. Free text is its digest here, as in the record: the words are in the
// side store, where they can be erased, and an export copied to a laptop
// cannot be.
func WriteCSV(w io.Writer, spec Spec, entries []Entry) error {
	s, err := specFor(spec.Kind)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	cols := ExportColumns(*s)
	cw := csv.NewWriter(w)
	if err := cw.Write(cols); err != nil {
		return err
	}
	for _, e := range entries {
		if e.Kind != s.Kind {
			return fmt.Errorf("%w: a %s in an export of %s records", ErrInvalid, e.Kind, s.Kind)
		}
		values := valuesOf(e.Record)
		row := []string{string(e.ID), stamp(e.Created), stamp(e.Updated), e.Object}
		for _, f := range s.Fields {
			row = append(row, cellOf(f, values[f.Name]))
		}
		if n, ok := Rating(e.Record); ok {
			row = append(row, strconv.FormatInt(n, 10))
		}
		for i := range row {
			row[i] = FormulaSafe(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// FormulaSafe is a cell a spreadsheet shows as text and does not run.
func FormulaSafe(cell string) string {
	if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
		return "'" + cell
	}
	return cell
}

func stamp(t Time) string {
	if t == 0 {
		return ""
	}
	return t.At().Format(time.RFC3339)
}

// cellOf is one field's value as a cell: a string as itself, a time as a
// date and time a spreadsheet reads, a list of plain values separated by
// semicolons, and an object as the JSON it is stored as.
func cellOf(f Field, v json.RawMessage) string {
	if len(v) == 0 || string(v) == "null" {
		return ""
	}
	switch {
	case f.Type == "time":
		var n int64
		if json.Unmarshal(v, &n) == nil {
			return stamp(Time(n))
		}
	case strings.HasPrefix(f.Type, "list of ") && !strings.HasSuffix(f.Type, "object"):
		var list []json.RawMessage
		if json.Unmarshal(v, &list) == nil {
			parts := make([]string, 0, len(list))
			for _, m := range list {
				parts = append(parts, plainOf(m))
			}
			return strings.Join(parts, "; ")
		}
	case strings.HasSuffix(f.Type, "object"):
		var b bytes.Buffer
		if json.Compact(&b, v) == nil {
			return b.String()
		}
	}
	return plainOf(v)
}

func plainOf(v json.RawMessage) string {
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	return string(v)
}

// rating is a risk's likelihood times its impact, each from 1 to 5, which
// is the rating the risk register is read in the order of. Code works it
// out from the two typed numbers; nobody types it, and nothing a model
// wrote is in it.
func (r Risk) rating() int64 { return r.Likelihood * r.Impact }
