// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/site"
)

// A page is given a form from the forms there are, in its editor, and the
// same choice takes it off again; Pages starts a page by its address.
func TestAPageIsGivenAFormInItsEditor(t *testing.T) {
	srv, token := setup(t)
	srv.Forms = &Forms{Load: func() (*form.Set, error) {
		return &form.Set{Forms: []form.Form{{Name: "enquiry", Label: "Ask us anything"}, {Name: "restock"}}}, nil
	}}

	page := get(t, srv, "/page/contact", token).Body.String()
	for _, want := range []string{`<select id="f-form" name="__form"`, `<option value="enquiry">Ask us anything</option>`,
		`<option value="restock">restock</option>`} {
		if !strings.Contains(page, want) {
			t.Errorf("the editor lacks %s", want)
		}
	}
	whole(t, page)

	save := func(choice string) map[string]any {
		t.Helper()
		v := url.Values{"__name": {"contact"}, "__base": {srv.Store.GetRef(site.RefDraft)}, "title": {"Contact"},
			"__form": {choice}}
		if w := postForm(t, srv, "/save", token, v.Encode()); w.Code != http.StatusSeeOther {
			t.Fatalf("saving: %d %s", w.Code, w.Body.String())
		}
		pages, err := site.PagesAt(srv.Store, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := pages["contact"].(map[string]any)
		return body
	}
	if b := save("enquiry"); b["form"] != "enquiry" || b["title"] != "Contact" {
		t.Fatalf("the page was saved as %v", b)
	}
	if !strings.Contains(get(t, srv, "/page/contact", token).Body.String(), `<option value="enquiry" selected>`) {
		t.Error("the editor does not show the form the page carries")
	}
	if b := save(""); b["form"] != nil {
		t.Fatalf("None left the form on the page: %v", b)
	}

	w := get(t, srv, "/pages/new?name=Summer+Fair+2027", token)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/page/summer-fair-2027" {
		t.Fatalf("a new page: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := get(t, srv, "/pages/new?name=%20", token); !strings.HasPrefix(w.Header().Get("Location"), "/?e=") {
		t.Errorf("an empty address: %q", w.Header().Get("Location"))
	}
}
