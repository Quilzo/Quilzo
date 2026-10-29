// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
)

// A collection whose type is known is written with that type's form: a date
// as a date, a time as a time, a choice as its choices, and what is typed is
// stored as its field's kind, with a blank optional field left out.
func TestARecordIsWrittenWithItsTypesForm(t *testing.T) {
	srv, token := setup(t)
	reg := schema.NewRegistry()
	if err := reg.Add(schema.Type{Name: "event", Fields: []schema.Field{
		{Name: "title", Kind: schema.Text, Label: "Title", Required: true},
		{Name: "date", Kind: schema.Date, Label: "Date", Required: true},
		{Name: "time", Kind: schema.Time, Label: "Starts at"},
		{Name: "seats", Kind: schema.Number, Label: "Seats"},
		{Name: "status", Kind: schema.Choice, Label: "Status", Choices: []string{"cancelled", "postponed"}},
		{Name: "venue", Kind: schema.Text, Label: "Venue"},
		{Name: "image", Kind: schema.Text, Label: "Picture"},
		{Name: "alt", Kind: schema.Text, Label: "What the picture shows", AltFor: "image"},
	}}); err != nil {
		t.Fatal(err)
	}
	st := &schema.Store{Registry: reg, Collections: map[string]string{"events": "event"}}
	srv.Types = &Types{Load: func() (*schema.Store, error) { return st, nil }}
	tree := ""
	srv.Data = &Data{Tree: func() (string, error) { return tree, nil },
		Commit: func(next, msg, by string) error { tree = next; return nil }}

	id := withLibrary(t, srv)
	page := get(t, srv, "/records?c=events", token).Body.String()
	for _, want := range []string{`name="date" type="date"`, `name="time" type="time"`, `<select id="f-status" name="status"`,
		`name="__typed" value="1"`, "Write it as JSON instead", "Describes <strong>Picture</strong>",
		`list="pictures-image"`, `<option value="` + id + `" label="a test photograph">`} {
		if !strings.Contains(page, want) {
			t.Errorf("the form lacks %s", want)
		}
	}
	whole(t, page)

	form := url.Values{"collection": {"events"}, "id": {""}, "__typed": {"1"}, "title": {"Rye night"},
		"date": {"2026-11-14"}, "time": {"19:30"}, "seats": {"40"}, "status": {""}, "venue": {""}}
	if w := postForm(t, srv, "/records/save", token, form.Encode()); w.Code != http.StatusSeeOther ||
		strings.Contains(w.Header().Get("Location"), "not") {
		t.Fatalf("saving: %d %s", w.Code, w.Header().Get("Location"))
	}
	recs, _, err := collection.List(srv.Store, tree, "events", collection.Query{})
	if err != nil || len(recs) != 1 {
		t.Fatalf("records: %v %v", recs, err)
	}
	f := recs[0].Fields
	if f["title"] != "Rye night" || f["date"] != "2026-11-14" || f["time"] != "19:30" || f["seats"] != 40.0 {
		t.Fatalf("stored: %v", f)
	}
	if _, ok := f["venue"]; ok {
		t.Error("a blank optional field was stored as an empty value")
	}
	if _, ok := f["collection"]; ok {
		t.Error("the form's own fields were stored in the record")
	}
	// Opened again, the form holds what was saved; a bad time is refused by
	// the type, as it is from anywhere else.
	edit := get(t, srv, "/records?c=events&edit="+recs[0].ID, token).Body.String()
	if !strings.Contains(edit, `value="19:30"`) || !strings.Contains(edit, `value="`+recs[0].ID+`"`) {
		t.Fatal("editing does not show the record")
	}
	form.Set("id", recs[0].ID)
	form.Set("time", "25:00")
	w := postForm(t, srv, "/records/save", token, form.Encode())
	if !strings.Contains(w.Header().Get("Location"), "time") {
		t.Fatalf("a bad time was saved: %s", w.Header().Get("Location"))
	}
}
