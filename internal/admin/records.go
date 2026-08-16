package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lithoform/lithoform/internal/auth"
	"github.com/lithoform/lithoform/internal/collection"
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

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
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
	type collRow struct {
		Name  string
		Count int
	}
	var colls []collRow
	for _, n := range names {
		c, _ := collection.Count(s.Store, tree, n)
		colls = append(colls, collRow{n, c})
	}

	selected := strings.TrimSpace(r.URL.Query().Get("c"))
	if selected == "" && len(colls) > 0 {
		selected = colls[0].Name
	}

	data := map[string]any{
		"Title": "Data", "Principal": p, "Nav": "records",
		"Collections": colls, "Selected": selected,
		"Message":  r.URL.Query().Get("m"),
		"CanWrite": s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
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
	if len(out) > 8 {
		// A table wider than the screen is a table nobody reads. The rest are
		// on the record's own page.
		out = out[:8]
	}
	return out
}

// handleRecordSave writes one record from the form.
func (s *Server) handleRecordSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.postFrom(w, r, auth.ActEditDraft)
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
	raw := strings.TrimSpace(r.FormValue("fields"))
	if raw == "" {
		s.recordsBack(w, r, coll, "a record with no fields is not a record")
		return
	}
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		// The message names the position, because "invalid JSON" in a textarea
		// somebody has been typing into for five minutes is not a fix.
		s.recordsBack(w, r, coll, "that is not a JSON object: "+err.Error())
		return
	}

	err := s.Store.WithRefLock(func() error {
		tree, err := s.Data.Tree()
		if err != nil {
			return err
		}
		next, _, err := collection.Put(s.Store, tree, coll,
			collection.Record{ID: id, Fields: fields}, time.Now())
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
	p, ok := s.postFrom(w, r, auth.ActEditDraft)
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
