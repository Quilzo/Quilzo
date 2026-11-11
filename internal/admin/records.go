// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"fmt"
	"io"
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
	// Bring brings a spreadsheet, a JSON list or a calendar into a
	// collection, as `quilzo records import` does. Nil means the screen
	// offers no upload.
	Bring func(coll, filename string, body []byte, opts BringOptions, by Actor) (*BringResult, error)
	// Sheet is a collection as a spreadsheet, for the download. Nil means
	// the screen offers none.
	Sheet func(coll string, by Actor) ([]byte, int, error)
}

// BringOptions says how a file is brought into a collection.
type BringOptions struct {
	// Key is the field matching rows to records already here, "none", or
	// "" for the type's page link.
	Key string
	// Dates is "dmy" or "mdy" for dates like 03/04/2026, or "" to work
	// it out.
	Dates    string
	SkipBad  bool
	DryRun   bool
	Pictures bool
}

// BringResult is what bringing a file in did, or would do.
type BringResult struct {
	New, Updated int
	// Columns says which column became which field, and which were left
	// out and why.
	Columns  []string
	Problems []string
	Notes    []string
}

// MaxRecordUpload bounds a file brought into a collection from the Data
// screen.
const MaxRecordUpload = 32 << 20

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
		"Problem":  r.URL.Query().Get("e"),
		"CanWrite": selected != "" && s.allows(p, auth.ActEditDraft, auth.DataResource(selected)),
		"CanBring": selected != "" && s.Data.Bring != nil &&
			s.allows(p, auth.ActEditDraft, auth.DataResource(selected)),
		"CanSheet":  selected != "" && s.Data.Sheet != nil,
		"MaxUpload": MaxRecordUpload >> 20,
	}
	// The fields rows can be matched by, the page link first and chosen
	// unless asked otherwise.
	if t, ok := s.recordType(selected); ok {
		var keys []map[string]string
		chosen := false
		for _, f := range t.Fields {
			switch f.Kind {
			case schema.Slug, schema.Text, schema.Email, schema.Number:
			default:
				continue
			}
			if f.AltFor != "" {
				continue
			}
			label := f.Label
			if label == "" {
				label = f.Name
			}
			k := map[string]string{"Name": f.Name, "Label": label}
			if f.Kind == schema.Slug && !chosen {
				k["Default"], chosen = "1", true
			}
			keys = append(keys, k)
		}
		data["Keys"], data["KeyChosen"] = keys, chosen
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

	// Every record, a page at a time, and Find over all of them.
	//
	// It listed the first hundred in id order under the count of all of
	// them, with no way to the rest, and Find filtered those hundred and put
	// what it kept where the total was: a record past the hundredth was "0
	// records", whatever it said.
	if selected != "" {
		find := strings.TrimSpace(r.URL.Query().Get("find"))
		if find != "" {
			data["Find"] = find
		}
		if idx, err := s.Records.For(s.Store, tree, selected); err == nil {
			all := idx.Records
			if find != "" {
				all = filterAnyField(all, find)
			}
			pg := paginate(r, len(all), recordsPageSize)
			recs, total := collection.Query{Sort: r.URL.Query().Get("sort"),
				Offset: pg.Offset, Limit: pg.Size}.Apply(all)
			data["Records"] = recs
			data["Total"] = total
			data["Columns"] = columnsOf(recs)
			data["Paging"], data["PagePath"] = pg, "/records"
		}
	}
	s.render(w, r, "records.html", data)
}

// recordsPageSize is how many records the Data screen lists at once: the
// hundred it always showed, now with a way to the next hundred.
const recordsPageSize = 100

// filterAnyField keeps records where any field contains the text.
//
// One box, matched against every field, because an editor looking for a
// record knows what it says and not which column it is in. Done here rather
// than in the query because Query filters named fields, and widening it to
// "any field" there would make the query language's cost unpredictable. It
// runs over the whole collection, as decoded by the index, and never over
// the page on the screen: filtering the hundred already shown is what made
// Find miss everything after them.
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
	s.happened("record.changed", coll)
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
	s.happened("record.changed", coll)
	s.recordsBack(w, r, coll, "deleted")
}

// happened tells Happened, when there is one.
func (s *Server) happened(eventType, subject string) {
	if s.Happened != nil {
		s.Happened(eventType, subject)
	}
}

// handleRecordImport brings a spreadsheet, a JSON list or a calendar into
// a collection, as `quilzo records import` does: all of it or, when it
// cannot all be, none of it unless asked otherwise, and back to the
// screen with what was done.
func (s *Server) handleRecordImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// A file, not a form: its own limit, as an upload to the media library
	// has (the middleware leaves this path to it).
	r.Body = http.MaxBytesReader(w, r.Body, MaxRecordUpload+1<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		s.recordsProblem(w, r, "", fmt.Sprintf("that file could not be read: the limit is %d MB", MaxRecordUpload>>20))
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()
	coll := strings.TrimSpace(r.FormValue("collection"))
	if collection.ValidName(coll) != nil {
		http.Error(w, "no such collection", http.StatusBadRequest)
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, auth.DataResource(coll)) {
		return
	}
	if s.Data == nil || s.Data.Bring == nil {
		http.NotFound(w, r)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		s.recordsProblem(w, r, coll, "choose a file to bring in")
		return
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, MaxRecordUpload+1))
	if err != nil || len(body) > MaxRecordUpload {
		s.recordsProblem(w, r, coll, fmt.Sprintf("the file is larger than %d MB", MaxRecordUpload>>20))
		return
	}
	opts := BringOptions{Key: r.FormValue("key"), Dates: r.FormValue("dates"),
		SkipBad: r.FormValue("skip_bad") == "1", DryRun: r.FormValue("dry_run") == "1",
		Pictures: r.FormValue("pictures") == "1"}
	if opts.Dates != "dmy" && opts.Dates != "mdy" {
		opts.Dates = ""
	}
	res, err := s.Data.Bring(coll, header.Filename, body, opts, p.actor())
	if err != nil {
		s.recordsProblem(w, r, coll, err.Error())
		return
	}
	s.recordsBack(w, r, coll, broughtSentence(res, opts.DryRun))
}

// broughtSentence is what bringing a file in did, as the screen says it.
func broughtSentence(res *BringResult, dry bool) string {
	verb := "Brought in"
	if dry {
		verb = "Checked: it would bring in"
	}
	n := res.New + res.Updated
	noun := "records"
	if n == 1 {
		noun = "record"
	}
	parts := []string{fmt.Sprintf("%s %d %s: %d new, %d changed.", verb, n, noun, res.New, res.Updated)}
	var left []string
	for _, c := range res.Columns {
		if strings.Contains(c, "left out") {
			left = append(left, c)
		}
	}
	if len(left) > 0 {
		parts = append(parts, "Columns "+strings.Join(left, "; ")+".")
	}
	if len(res.Problems) > 0 {
		shown := res.Problems
		if len(shown) > 5 {
			shown = append(shown[:5:5], fmt.Sprintf("and %d more", len(res.Problems)-5))
		}
		parts = append(parts, "Not brought in: "+strings.Join(shown, "; ")+".")
	}
	parts = append(parts, res.Notes...)
	if dry {
		parts = append(parts, "Nothing was written.")
	} else if res.New+res.Updated > 0 {
		parts = append(parts, "They are in the draft until you publish.")
	}
	return strings.Join(parts, " ")
}

// handleRecordExport is a collection as a spreadsheet, to download.
func (s *Server) handleRecordExport(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	coll := strings.TrimSpace(r.URL.Query().Get("c"))
	if collection.ValidName(coll) != nil {
		http.NotFound(w, r)
		return
	}
	if !s.can(w, r, p, auth.ActView, auth.DataResource(coll)) {
		return
	}
	if s.Data == nil || s.Data.Sheet == nil {
		http.NotFound(w, r)
		return
	}
	body, n, err := s.Data.Sheet(coll, p.actor())
	if err != nil {
		s.recordsProblem(w, r, coll, err.Error())
		return
	}
	s.audit("records.export", "/"+coll, map[string]string{"collection": coll, "records": fmt.Sprint(n),
		"by": p.Name})
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+coll+`.csv"`)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

func (s *Server) recordsProblem(w http.ResponseWriter, r *http.Request, coll, msg string) {
	http.Redirect(w, r, "/records?c="+urlQueryEscape(coll)+"&e="+
		urlQueryEscape(msg), http.StatusSeeOther)
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
