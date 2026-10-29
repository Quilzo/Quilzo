// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
)

// Records in the admin.
//
// The reason this screen has to exist rather than being "use the API": most
// people who build things with this will never open a terminal, and a feature
// that is only reachable from one is a feature they do not have. That has been
// the pattern with everything added here — the capability lands in the CLI, the
// GUI is done later, and later does not arrive.

// Data is what the host supplies so the admin can read and write records.
type Data struct {
	Tree   func() (string, error)
	Commit func(tree, message, author string) error
}

// typeLoader adapts the admin's Types wiring to what the record gate wants.
//
// Nil when this server was started without access to the types, which the gate
// treats as a refusal rather than as "no types" — a server that cannot read the
// constraint must not store content it has not checked against it.
func (s *Server) typeLoader() func() (*schema.Store, error) {
	if s.Types == nil || s.Types.Load == nil {
		return nil
	}
	return s.Types.Load
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// Somebody who may read one collection opens this screen and sees that
	// one; somebody who may read none is refused, as before.
	if s.Policy != nil && !s.Policy.AnywhereUnder(p.Name, auth.ActView, auth.AreaData) {
		s.can(w, r, p, auth.ActView, auth.AreaData)
		return
	}
	if s.Data == nil {
		s.render(w, r, "records.html", map[string]any{
			"Title": "Data", "Principal": p, "Nav": "records",
			"Unavailable": "this server was started without access to the data",
		})
		return
	}
	tree, err := s.Data.Tree()
	if err != nil {
		s.render(w, r, "records.html", map[string]any{
			"Title": "Data", "Principal": p, "Nav": "records",
			"Unavailable": err.Error(),
		})
		return
	}

	names, _ := collection.Names(s.Store, tree)
	// And the collections a type is bound to that hold nothing yet: one set
	// up a moment ago, such as events, is where the first record is written,
	// and a screen listing only collections with records offered nowhere to
	// write it.
	if s.Types != nil && s.Types.Load != nil {
		if st, err := s.Types.Load(); err == nil && st != nil {
			have := map[string]bool{}
			for _, n := range names {
				have[n] = true
			}
			for n := range st.Collections {
				if !have[n] && collection.ValidName(n) == nil {
					names = append(names, n)
				}
			}
			sort.Strings(names)
		}
	}
	type collRow struct {
		Name  string
		Count int
	}
	var colls []collRow
	mayRead := map[string]bool{}
	for _, n := range names {
		if !s.allows(p, auth.ActView, auth.DataResource(n)) {
			continue
		}
		c, _ := collection.Count(s.Store, tree, n)
		colls = append(colls, collRow{n, c})
		mayRead[n] = true
	}

	selected := strings.TrimSpace(r.URL.Query().Get("c"))
	if selected != "" && !mayRead[selected] {
		// One out of reach is answered as one that does not exist.
		selected = ""
	}
	if selected == "" && len(colls) > 0 {
		selected = colls[0].Name
	}

	data := map[string]any{
		"Title": "Data", "Principal": p, "Nav": "records",
		"Collections": colls, "Selected": selected,
		"Message":  r.URL.Query().Get("m"),
		"CanWrite": selected != "" && s.allows(p, auth.ActEditDraft, auth.DataResource(selected)),
	}

	// What a new record of this collection's type starts as.
	//
	// The form was a textarea and a placeholder, so writing a record meant
	// remembering the field names, remembering which were required, and
	// finding out which you had got wrong by being refused. The type has
	// declared all of it since it existed.
	if selected != "" && s.Types != nil && s.Types.Load != nil {
		if st, err := s.Types.Load(); err == nil && st != nil {
			if name, bound := st.Collections[selected]; bound {
				if t, ok := st.Registry.Get(name); ok {
					if body, jerr := json.MarshalIndent(t.Blank(), "", "  "); jerr == nil {
						data["Blank"] = string(body)
						data["BlankType"] = name
					}
				}
			}
		}
	}

	// A record opened for editing: its fields fill the form, and its id the
	// id box, so changing one record is not retyping it.
	var editing map[string]any
	if id := strings.TrimSpace(r.URL.Query().Get("edit")); id != "" && selected != "" {
		if rec, err := collection.Get(s.Store, tree, selected, id); err == nil && rec != nil {
			if body, jerr := json.MarshalIndent(rec.Fields, "", "  "); jerr == nil {
				data["Blank"] = string(body)
				data["EditID"] = rec.ID
				editing = rec.Fields
			}
		}
	}
	// A collection whose type is known is written with a form of that type's
	// fields — a date as a date, a time as a time, a choice as its choices —
	// rather than as JSON, which only somebody who writes JSON can use. JSON
	// stays one link away for a field the form cannot say.
	if t, ok := s.recordType(selected); ok && r.URL.Query().Get("raw") == "" {
		body := map[string]any{}
		for k, v := range t.Blank() {
			body[k] = v
		}
		if editing != nil {
			body = editing
		}
		data["Fields"] = s.withPictures(t, typedFields(t, body, nil))
		data["BlankType"] = t.Name
	}

	if selected != "" {
		q := collection.Query{Limit: 100, Sort: r.URL.Query().Get("sort")}
		if f := strings.TrimSpace(r.URL.Query().Get("find")); f != "" {
			// One box, matched against every field, because an editor looking
			// for a record knows what it says and not which column it is in.
			q.Contains = map[string]string{}
			data["Find"] = f
		}
		recs, total, err := collection.List(s.Store, tree, selected, q)
		if err == nil {
			if f := strings.TrimSpace(r.URL.Query().Get("find")); f != "" {
				recs = filterAnyField(recs, f)
				total = len(recs)
			}
			data["Records"] = recs
			data["Total"] = total
			data["Columns"] = columnsOf(recs)
		}
	}
	s.render(w, r, "records.html", data)
}

// filterAnyField keeps records where any field contains the text.
//
// Done here rather than in the query because Query filters named fields, and
// widening it to "any field" there would make the query language's cost
// unpredictable — this is a display convenience over an already-loaded page.
func filterAnyField(in []collection.Record, find string) []collection.Record {
	want := strings.ToLower(find)
	var out []collection.Record
	for _, r := range in {
		for _, v := range r.Fields {
			if strings.Contains(strings.ToLower(fmt.Sprint(v)), want) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// columnsOf is the union of every field name in the page, in a stable order.
//
// Records in a collection need not share a shape — nothing forces them to —
// so a table built from the first record's keys would silently hide fields
// that only some records carry.
func columnsOf(recs []collection.Record) []string {
	seen := map[string]bool{}
	for _, r := range recs {
		for k := range r.Fields {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	// The field that names a record leads, so a row reads as "which one"
	// before "what about it".
	for _, lead := range []string{"name", "title", "label", "heading"} {
		if seen[lead] {
			rest := []string{lead}
			for _, k := range out {
				if k != lead {
					rest = append(rest, k)
				}
			}
			out = rest
			break
		}
	}
	if len(out) > 5 {
		// A table wider than the screen is a table nobody reads. The rest are
		// on the record itself, which Edit opens.
		out = out[:5]
	}
	return out
}

// recordType is the type bound to a collection, when there is one.
func (s *Server) recordType(coll string) (schema.Type, bool) {
	if coll == "" || s.Types == nil || s.Types.Load == nil {
		return schema.Type{}, false
	}
	st, err := s.Types.Load()
	if err != nil || st == nil {
		return schema.Type{}, false
	}
	name, bound := st.Collections[coll]
	if !bound {
		return schema.Type{}, false
	}
	return st.Registry.Get(name)
}

// handleRecordSave writes one record from the form.
func (s *Server) handleRecordSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFromData(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	if s.Data == nil {
		http.Error(w, "no data store", http.StatusNotFound)
		return
	}
	coll := strings.TrimSpace(r.FormValue("collection"))
	if err := collection.ValidName(coll); err != nil {
		s.recordsBack(w, r, coll, err.Error())
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))

	var fields map[string]any
	if r.FormValue("__typed") == "1" {
		// The type's form: the record as it is, changed by what was typed,
		// each value read as its field's kind.
		t, ok := s.recordType(coll)
		if !ok {
			s.recordsBack(w, r, coll, "this collection has no type to read the form by")
			return
		}
		fields = map[string]any{}
		if id != "" {
			if tree, err := s.Data.Tree(); err == nil {
				if rec, err := collection.Get(s.Store, tree, coll, id); err == nil && rec != nil {
					for k, v := range rec.Fields {
						fields[k] = v
					}
				}
			}
		}
		form := url.Values{}
		for k, v := range r.Form {
			if k != "collection" && k != "id" {
				form[k] = v
			}
		}
		coerceForm(t, form, fields)
	} else {
		raw := strings.TrimSpace(r.FormValue("fields"))
		if raw == "" {
			s.recordsBack(w, r, coll, "a record with no fields is not a record")
			return
		}
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			// The message names the position, because "invalid JSON" in a
			// textarea somebody has been typing into for five minutes is not
			// a fix.
			s.recordsBack(w, r, coll, "that is not a JSON object: "+err.Error())
			return
		}
	}

	err := s.Store.WithRefLock(func() error {
		tree, err := s.Data.Tree()
		if err != nil {
			return err
		}
		next, _, err := collection.Put(s.Store, tree, coll,
			collection.Record{ID: id, Fields: fields}, time.Now(),
			schema.RecordGate(s.typeLoader()))
		if err != nil {
			return err
		}
		return s.Data.Commit(next, "admin: write "+coll, p.Name)
	})
	if err != nil {
		s.recordsBack(w, r, coll, err.Error())
		return
	}
	s.audit("records.write", "/"+coll, map[string]string{
		"collection": coll, "by": p.Name})
	s.recordsBack(w, r, coll, "saved")
}

func (s *Server) handleRecordDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFromData(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	if s.Data == nil {
		http.Error(w, "no data store", http.StatusNotFound)
		return
	}
	coll := strings.TrimSpace(r.FormValue("collection"))
	id := strings.TrimSpace(r.FormValue("id"))

	err := s.Store.WithRefLock(func() error {
		tree, err := s.Data.Tree()
		if err != nil {
			return err
		}
		next, err := collection.Delete(s.Store, tree, coll, id)
		if err != nil {
			return err
		}
		return s.Data.Commit(next, "admin: delete from "+coll, p.Name)
	})
	if err != nil {
		s.recordsBack(w, r, coll, err.Error())
		return
	}
	s.audit("records.delete", "/"+coll, map[string]string{
		"collection": coll, "record": id, "by": p.Name})
	s.recordsBack(w, r, coll, "deleted")
}

func (s *Server) recordsBack(w http.ResponseWriter, r *http.Request, coll, msg string) {
	http.Redirect(w, r, "/records?c="+urlQueryEscape(coll)+"&m="+
		urlQueryEscape(msg), http.StatusSeeOther)
}

// postFromData is postFrom for a form that names a collection: asked about
// that collection rather than the site.
func (s *Server) postFromData(w http.ResponseWriter, r *http.Request, act auth.Action) (principal, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	coll := strings.TrimSpace(r.FormValue("collection"))
	if collection.ValidName(coll) != nil {
		coll = ""
	}
	resource := auth.AreaData
	if coll != "" {
		resource = auth.DataResource(coll)
	}
	if !s.can(w, r, p, act, resource) {
		return principal{}, false
	}
	return p, true
}
