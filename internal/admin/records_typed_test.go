// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
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
	// The redirect's own parameters, not its text: a flash token is random,
	// and one with "not" in it once read here as a refusal.
	if w := postForm(t, srv, "/records/save", token, form.Encode()); w.Code != http.StatusSeeOther ||
		redirectQuery(w).Get("e") != "" || redirectQuery(w).Get("m") != "saved" {
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

// The Data screen takes a spreadsheet or a calendar into a collection, as
// `quilzo records import` does, and gives the collection back as a
// spreadsheet; each asks of the collection what writing and reading it ask.
func TestTheDataScreenBringsASpreadsheetInAndGivesOneBack(t *testing.T) {
	srv, token := setup(t)
	reg := schema.NewRegistry()
	if err := reg.Add(schema.Type{Name: "event", Fields: []schema.Field{
		{Name: "title", Kind: schema.Text, Label: "Title", Required: true},
		{Name: "slug", Kind: schema.Slug, Label: "Page link", Required: true},
		{Name: "date", Kind: schema.Date, Label: "Date", Required: true},
	}}); err != nil {
		t.Fatal(err)
	}
	st := &schema.Store{Registry: reg, Collections: map[string]string{"events": "event"}}
	srv.Types = &Types{Load: func() (*schema.Store, error) { return st, nil }}
	var got struct {
		coll, name string
		size       int
		opts       BringOptions
		by         string
	}
	srv.Data = &Data{Tree: func() (string, error) { return "", nil },
		Commit: func(next, msg, by string) error { return nil },
		Bring: func(coll, name string, body []byte, o BringOptions, by Actor) (*BringResult, error) {
			got.coll, got.name, got.size, got.opts, got.by = coll, name, len(body), o, by.Name
			return &BringResult{New: 2, Updated: 1, Columns: []string{`"Notes" left out: no field of event is called this`},
				Problems: []string{"line 4: date: \"someday\" is not a date"}}, nil
		},
		Sheet: func(coll string, by Actor) ([]byte, int, error) {
			return []byte("id,title\r\nabc,'=SUM(A1)\r\n"), 1, nil
		}}

	page := get(t, srv, "/records?c=events", token).Body.String()
	for _, want := range []string{`action="/records/import" enctype="multipart/form-data"`,
		`<option value="slug" selected>Page link</option>`, `href="/records/export?c=events"`,
		`<option value="dmy">Day first: 3 April</option>`} {
		if !strings.Contains(page, want) {
			t.Errorf("the Data screen lacks %s", want)
		}
	}
	whole(t, page)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("collection", "events")
	fw, _ := mw.CreateFormFile("file", "events.csv")
	_, _ = fw.Write(bytes.Repeat([]byte("x"), 3<<20))
	_ = mw.WriteField("key", "slug")
	_ = mw.WriteField("dates", "dmy")
	_ = mw.WriteField("skip_bad", "1")
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/records/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	srv.Handler().ServeHTTP(res, req)
	loc := res.Header().Get("Location")
	if res.Code != http.StatusSeeOther || got.coll != "events" || got.name != "events.csv" || got.size != 3<<20 ||
		got.opts != (BringOptions{Key: "slug", Dates: "dmy", SkipBad: true}) {
		t.Fatalf("%d %s: %+v", res.Code, loc, got)
	}
	back, _ := url.Parse(loc)
	msg := back.Query().Get("m")
	for _, want := range []string{"Brought in 3 records: 2 new, 1 changed.", `"Notes" left out`, "line 4: date",
		"in the draft until you publish"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the screen does not say %q: %s", want, msg)
		}
	}

	dl := get(t, srv, "/records/export?c=events", token)
	if dl.Code != http.StatusOK || dl.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
		!strings.Contains(dl.Header().Get("Content-Disposition"), `filename="events.csv"`) ||
		!strings.Contains(dl.Body.String(), "'=SUM(A1)") {
		t.Fatalf("download: %d %v %q", dl.Code, dl.Header(), dl.Body.String())
	}
	if get(t, srv, "/records/export?c=../x", token).Code != http.StatusNotFound {
		t.Error("a collection that cannot be was answered")
	}
}

// redirectQuery is a redirect's parameters.
func redirectQuery(w *httptest.ResponseRecorder) url.Values {
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		return url.Values{}
	}
	return u.Query()
}
