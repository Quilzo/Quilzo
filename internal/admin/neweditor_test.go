// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
)

// A page started from Pages opens an editor somebody can write it in.
//
// It opened on a form with a form picker, a search-engine box and "What
// changed", and nothing else: the editor shows the fields a page already
// has, and a page that does not exist yet has none. "Save to draft" stored
// an empty page, the editor was as empty afterwards, and nothing on it led
// to Sections, the one screen that could put anything in it.
func TestANewPageOpensAnEditorToWriteItIn(t *testing.T) {
	srv, token := setup(t)

	w := get(t, srv, "/pages/new?name=Opening+Hours", token)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || loc != "/page/opening-hours" {
		t.Fatalf("New page went to %d %q", w.Code, loc)
	}
	body := get(t, srv, loc, token).Body.String()
	for _, want := range []string{
		`<input id="f-title" name="title"`,
		`<textarea id="f-body" name="body"`,
		`name="__then" value="sections"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the new page's editor has no %s", want)
		}
	}
	whole(t, body)

	// What was typed is the page, and the second button goes on to Sections.
	w = save(t, srv, token, url.Values{"__name": {"opening-hours"}, "title": {"Opening hours"},
		"body": {"Nine to five."}, "__then": {"sections"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/sections?page=opening-hours" {
		t.Fatalf("saving and going on to Sections: %d %q", w.Code, w.Header().Get("Location"))
	}
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := pages["opening-hours"].(map[string]any)
	if got["title"] != "Opening hours" || got["body"] != "Nine to five." {
		t.Fatalf("the page saved as %v", pages["opening-hours"])
	}
	if _, has := got["__then"]; has {
		t.Error("the button's own value was saved into the page")
	}
	if w := get(t, srv, "/sections?page=opening-hours", token); w.Code != http.StatusOK {
		t.Fatalf("Sections did not open on the saved page: %d", w.Code)
	}

	// Opened again, it holds what was saved, and Sections is a link away.
	body = get(t, srv, "/page/opening-hours", token).Body.String()
	for _, want := range []string{`value="Opening hours"`, `>Nine to five.</textarea>`,
		`href="/sections?page=opening-hours"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the saved page's editor has no %s", want)
		}
	}
}

// A page saved empty, as the editor used to leave a new one, is written in
// the same way: an empty page is a page nobody has written yet.
func TestAnEmptyPageOffersATitleAndABody(t *testing.T) {
	srv, token := setup(t)
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["blank"] = map[string]any{}
	if _, err := site.SaveDraft(srv.Store, pages, "an empty page", "test"); err != nil {
		t.Fatal(err)
	}
	body := get(t, srv, "/page/blank", token).Body.String()
	for _, want := range []string{`name="title"`, `name="body"`, `href="/sections?page=blank"`} {
		if !strings.Contains(body, want) {
			t.Errorf("an empty page's editor has no %s", want)
		}
	}
	// A page with its own fields is shown those, and is not given more.
	about := get(t, srv, "/page/about", token).Body.String()
	if n := strings.Count(about, `name="body"`); n != 1 {
		t.Errorf("about's editor has %d body fields", n)
	}
}
