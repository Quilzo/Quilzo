// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
)

// stockists is a Data screen over a collection whose type refuses a slug
// that is not one.
func stockists(t *testing.T) (*Server, string, *string) {
	t.Helper()
	srv, token := setup(t)
	reg := schema.NewRegistry()
	if err := reg.Add(schema.Type{Name: "stockist", Fields: []schema.Field{
		{Name: "name", Kind: schema.Text, Label: "Name", Required: true},
		{Name: "slug", Kind: schema.Slug, Label: "Page link", Required: true},
	}}); err != nil {
		t.Fatal(err)
	}
	st := &schema.Store{Registry: reg, Collections: map[string]string{"stockists": "stockist"}}
	srv.Types = &Types{Load: func() (*schema.Store, error) { return st, nil }}
	tree := ""
	srv.Data = &Data{Tree: func() (string, error) { return tree, nil },
		Commit: func(next, msg, by string) error { tree = next; return nil }}
	return srv, token, &tree
}

// A refused record is said as a refusal, and what was typed stays typed.
//
// The type's refusal came back as m=, which the Data screen shows as the
// green "saved" notice with role=status, and the form was closed: the
// redirect carried no edit=, so every other change was gone with it.
func TestARefusedRecordIsARefusalAndKeepsWhatWasTyped(t *testing.T) {
	srv, token, tree := stockists(t)

	form := url.Values{"collection": {"stockists"}, "id": {""}, "__typed": {"1"},
		"name": {"Rye & Co, the high street"}, "slug": {"Not A Slug!!"}}
	w := postForm(t, srv, "/records/save", token, form.Encode())
	body := w.Body.String()
	if q := redirectQuery(w); q.Get("m") != "" {
		t.Fatalf("the refusal came back as a message: %s", w.Header().Get("Location"))
	}
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a refused record answered %d %s", w.Code, w.Header().Get("Location"))
	}
	if !strings.Contains(body, `<p class="notice bad" role="alert">`) || strings.Contains(body, `class="notice ok"`) {
		t.Error("the refusal is not shown as one")
	}
	if !strings.Contains(body, "lowercase words joined by hyphens") {
		t.Error("the refusal does not say what is wrong")
	}
	for _, want := range []string{`value="Rye &amp; Co, the high street"`, `value="Not A Slug!!"`} {
		if !strings.Contains(body, want) {
			t.Errorf("what was typed is gone: no %s", want)
		}
	}
	if !regexp.MustCompile(`id="f-slug" name="slug"[^>]*aria-invalid="true"`).MatchString(body) {
		t.Error("the field that was refused is not marked")
	}
	whole(t, body)

	// Changing a record that is there, the form stays on that record.
	w = postForm(t, srv, "/records/save", token, url.Values{"collection": {"stockists"}, "id": {""}, "__typed": {"1"},
		"name": {"Rye"}, "slug": {"rye"}}.Encode())
	if redirectQuery(w).Get("m") != "saved" {
		t.Fatalf("a good record was not saved: %d %s", w.Code, w.Header().Get("Location"))
	}
	recs, _, _ := collection.List(srv.Store, *tree, "stockists", collection.Query{})
	if len(recs) != 1 {
		t.Fatalf("records: %v", recs)
	}
	w = postForm(t, srv, "/records/save", token, url.Values{"collection": {"stockists"}, "id": {recs[0].ID},
		"__typed": {"1"}, "name": {"Rye bakers"}, "slug": {"Rye Bakers"}}.Encode())
	body = w.Body.String()
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, `name="id" value="`+recs[0].ID+`"`) ||
		!strings.Contains(body, `value="Rye bakers"`) {
		t.Errorf("refusing a change closed the record or lost the change: %d", w.Code)
	}

	// Written as JSON, the JSON stays.
	w = postForm(t, srv, "/records/save", token, url.Values{"collection": {"stockists"}, "id": {""},
		"fields": {`{"name": "Rye", "slug": "rye"`}}.Encode())
	body = w.Body.String()
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, `{&#34;name&#34;: &#34;Rye&#34;, &#34;slug&#34;: &#34;rye&#34;</textarea>`) ||
		!strings.Contains(body, `role="alert">that is not a JSON object`) {
		t.Errorf("refusing JSON lost it: %d", w.Code)
	}
}

// A record refused for a collection that has nothing in it yet stays with
// that collection.
//
// The JSON form takes a collection's name, and a collection is made by its
// first record, so a record written for one that is not there yet is not on
// the screen the refusal answered with. The screen fell back to the first
// collection there was and put what had been typed into that one's form:
// the next Save wrote it into the wrong collection. With no collection at all
// to fall back to, the refusal was not said anywhere.
func TestARefusedRecordForANewCollectionStaysWithIt(t *testing.T) {
	srv, token, _ := bulkRecords(t, 3)
	bad := `{"hostname": "laptop-14"`
	w := postForm(t, srv, "/records/save", token, url.Values{"collection": {"laptops"}, "id": {""},
		"fields": {bad}}.Encode())
	body := w.Body.String()
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, `role="alert">that is not a JSON object`) {
		t.Fatalf("the refusal is not said: %d %s", w.Code, w.Header().Get("Location"))
	}
	if !strings.Contains(body, `name="collection" value="laptops"`) ||
		strings.Contains(body, `name="collection" value="bulk"`) {
		t.Error("what was typed for laptops is in another collection's form")
	}
	if !strings.Contains(body, `{&#34;hostname&#34;: &#34;laptop-14&#34;</textarea>`) {
		t.Error("what was typed is gone")
	}

	// The same with no collection to fall back to.
	srv, token = setup(t)
	tree := ""
	srv.Data = &Data{Tree: func() (string, error) { return tree, nil },
		Commit: func(next, msg, by string) error { tree = next; return nil }}
	w = postForm(t, srv, "/records/save", token, url.Values{"collection": {"laptops"}, "id": {""},
		"fields": {bad}}.Encode())
	body = w.Body.String()
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(body, `role="alert">that is not a JSON object`) ||
		!strings.Contains(body, `name="collection" value="laptops"`) {
		t.Errorf("with no collections yet, the refusal is lost: %d", w.Code)
	}
}
