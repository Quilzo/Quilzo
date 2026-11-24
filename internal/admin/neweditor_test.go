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
	// The box begins with the line break a browser drops from one.
	body = get(t, srv, "/page/opening-hours", token).Body.String()
	for _, want := range []string{`value="Opening hours"`, ">\nNine to five.</textarea>",
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

// An address the store cannot hold is refused when it is typed, and a save
// to one is refused as the person's to fix, on a page of this screen.
//
// New page made 200 x's into a page name and opened an editor on it, and
// Save to draft ended on a plain-text 500 with the store's sentence and no
// way back: the name was met only at the commit, by the store's rule.
func TestANewPageAtAnAddressTheStoreCannotHoldIsRefusedFirst(t *testing.T) {
	srv, token := setup(t)

	long := strings.Repeat("x", 200)
	w := get(t, srv, "/pages/new?name="+long, token)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/?e=") {
		t.Fatalf("New page at a 200-character address went to %d %q", w.Code, loc)
	}

	before, _ := site.PagesAt(srv.Store, site.RefDraft)
	for _, name := range []string{long, "a b", "-dash", "Ürün"} {
		w = save(t, srv, token, url.Values{"__name": {name}, "title": {"T"}})
		if w.Code != http.StatusBadRequest {
			t.Errorf("saving %.20q answered %d, not 400", name, w.Code)
			continue
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("saving %.20q answered %s, not a page of this screen", name, ct)
		}
		whole(t, w.Body.String())
	}
	after, _ := site.PagesAt(srv.Store, site.RefDraft)
	if len(after) != len(before) {
		t.Errorf("a refused save wrote a page: %d pages, then %d", len(before), len(after))
	}
}

// New page at an address in another language opens the page at that
// address, spelled in the letters a page address holds, and one in a script
// with no such spelling is told so.
//
// Ürünler opened /page/r-nler and Café Menu /page/caf-menu, and a Greek or
// Arabic address was refused with "Give the new page an address", which
// blamed the person for an address they had given.
func TestANewPageAtAnAddressInAnotherLanguage(t *testing.T) {
	srv, token := setup(t)
	for typed, want := range map[string]string{
		"Ürünler":         "/page/urunler",
		"Café Menu":       "/page/cafe-menu",
		"Σχετικά με εμάς": "/page/schetika-me-emas",
		"tr/Hakkımızda":   "/page/tr/hakkimizda",
	} {
		w := get(t, srv, "/pages/new?name="+url.QueryEscape(typed), token)
		if loc := w.Header().Get("Location"); loc != want {
			t.Errorf("New page at %q went to %q, want %q", typed, loc, want)
		}
	}
	w := get(t, srv, "/pages/new?name="+url.QueryEscape("مرحبا"), token)
	loc, _ := url.QueryUnescape(w.Header().Get("Location"))
	if !strings.HasPrefix(loc, "/?e=") || strings.Contains(loc, "Give the new page an address") ||
		!strings.Contains(loc, "Latin") {
		t.Errorf("an Arabic address went to %q", loc)
	}
}
