// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
)

// A page with no type may still carry numbers and booleans, written by
// `quilzo add`, the content API or an import. The editor offers them as text
// boxes, and the save stored back the strings the boxes submitted: an edit
// of the title turned rows 10 into "10" and featured false into "false",
// which a layout reads as true, so a page explicitly not featured was shown
// as featured. A value keeps the type it had while it reads as one.
func TestSavingAnUntypedPageKeepsItsNumbersAndBooleans(t *testing.T) {
	srv, token := setup(t)
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["about"] = map[string]any{
		"title": "Typed values", "body": "Some words.",
		"rows": 10.0, "price": 12.5, "featured": false, "shown": true,
		"tags": []any{"a", "b"},
	}
	if _, err := site.SaveDraft(srv.Store, pages, "typed values", "test"); err != nil {
		t.Fatal(err)
	}

	w := save(t, srv, token, url.Values{
		"__name": {"about"}, "title": {"Typed values (edited)"},
		"body": {"Some words."}, "rows": {"10"}, "price": {" 12.5 "},
		"featured": {"false"}, "shown": {"true"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("the save answered %d: %s", w.Code, w.Body.String())
	}
	pages, err = site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	body := pages["about"].(map[string]any)
	for key, want := range map[string]any{
		"rows": 10.0, "price": 12.5, "featured": false, "shown": true,
		"title": "Typed values (edited)",
	} {
		if body[key] != want {
			t.Errorf("%s is %#v after a title-only save, want %#v", key, body[key], want)
		}
	}
	if tags, ok := body["tags"].([]any); !ok || len(tags) != 2 {
		t.Errorf("tags is %#v", body["tags"])
	}

	// What somebody deliberately typed over a number is still saved as
	// they typed it: the editor keeps types, it does not refuse words.
	w = save(t, srv, token, url.Values{
		"__name": {"about"}, "title": {"Typed values"}, "rows": {"ten"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("the second save answered %d", w.Code)
	}
	pages, _ = site.PagesAt(srv.Store, site.RefDraft)
	if got := pages["about"].(map[string]any)["rows"]; got != "ten" {
		t.Errorf("rows typed as words is %#v", got)
	}
}

// A browser submits a textarea with CRLF line endings, as the HTML spec
// says it must. Stored as sent, every multi-line field of a page saved from
// the editor changed bytes though nobody touched it, so a title-only edit
// counted as a body change and a colleague's --merge of a real body edit was
// refused as "you both changed this field". Line endings are stored as \n,
// in a page with a type, one without, and a section's fields.
func TestSavingInTheBrowserKeepsLineEndings(t *testing.T) {
	const sent = "First paragraph.\r\n\r\nSecond paragraph.\rThird."
	const kept = "First paragraph.\n\nSecond paragraph.\nThird."

	t.Run("untyped", func(t *testing.T) {
		srv, token := setup(t)
		w := save(t, srv, token, url.Values{
			"__name": {"about"}, "title": {"About"}, "body": {sent},
		})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("the save answered %d", w.Code)
		}
		pages, _ := site.PagesAt(srv.Store, site.RefDraft)
		if got := pages["about"].(map[string]any)["body"]; got != kept {
			t.Errorf("body stored as %q", got)
		}
	})

	t.Run("typed", func(t *testing.T) {
		srv, token := setup(t)
		withTypes(t, srv)
		w := save(t, srv, token, url.Values{
			"__name": {"index"}, "title": {"Home"}, "body": {sent},
			"tags": {"one\r\ntwo\rthree"}, "stray": {"a\r\nb"},
		})
		if w.Code != http.StatusSeeOther && w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("the save answered %d", w.Code)
		}
		// The undeclared field is refused by the type, so read what the
		// form would build rather than what was stored.
		pages, _ := site.PagesAt(srv.Store, site.RefDraft)
		body := srv.pageFromForm(pages, "index", url.Values{
			"title": {"Home"}, "body": {sent},
			"tags": {"one\r\ntwo\rthree"}, "stray": {"a\r\nb"},
		})
		if body["body"] != kept {
			t.Errorf("body built as %q", body["body"])
		}
		if tags, _ := body["tags"].([]any); len(tags) != 3 {
			t.Errorf("tags built as %#v", body["tags"])
		}
		if body["stray"] != "a\nb" {
			t.Errorf("an undeclared field built as %q", body["stray"])
		}
	})

	t.Run("section", func(t *testing.T) {
		srv, token := setup(t)
		pages, err := site.PagesAt(srv.Store, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		withProse, err := section.Insert(pages["index"], "prose", 0)
		if err != nil {
			t.Fatal(err)
		}
		pages["index"] = withProse
		if _, err := site.SaveDraft(srv.Store, pages, "prose", "test"); err != nil {
			t.Fatal(err)
		}
		base := srv.Store.GetRef(site.RefDraft)
		if w := postForm(t, srv, "/sections/fields", token, url.Values{
			"page": {"index"}, "at": {"0"}, "base": {base}, "v.title": {"A\r\nheading"},
		}.Encode()); w.Code >= 400 {
			t.Fatalf("the section save answered %d: %s", w.Code, w.Body.String())
		}
		pages, _ = site.PagesAt(srv.Store, site.RefDraft)
		fields, err := section.Fields(pages["index"], 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fields {
			if f.Path == "title" && f.Value != "A\nheading" {
				t.Errorf("the section's title stored as %q", f.Value)
			}
		}
	})
}

// A list's max_len is not a character limit on the box it is edited in. The
// editor copied it to the textarea's maxlength, so a dish with five
// allergens could not be saved once touched (the browser counted the
// characters of all five) and typing stopped at the fifth character; a list
// with no items yet was a one-line input, where nothing typed became more
// than one item. A list is always a multi-line box, one item per line, and
// what it may hold is checked where every surface's writes are checked.
func TestTheEditorDrawsEveryListAsOnePerLine(t *testing.T) {
	typ := schema.Type{Name: "dish", Fields: []schema.Field{
		{Name: "title", Kind: schema.Text, MaxLen: 40},
		{Name: "allergens", Kind: schema.List, MaxLen: 5},
	}}
	for _, body := range []map[string]any{
		{"title": "Cilbir", "allergens": []any{"egg", "milk", "nuts", "soy", "gluten"}},
		{"title": "Baklava"},
	} {
		fields := typedFields(typ, body, nil)
		var list, title field
		for _, f := range fields {
			switch f.Key {
			case "allergens":
				list = f
			case "title":
				title = f
			}
		}
		if !list.Long {
			t.Errorf("%s: the list is drawn on one line", body["title"])
		}
		if list.MaxLen != 0 {
			t.Errorf("%s: the list's box is limited to %d characters", body["title"], list.MaxLen)
		}
		if !strings.Contains(list.Help, "One per line") {
			t.Errorf("%s: the list says nothing of one per line: %q", body["title"], list.Help)
		}
		if title.MaxLen != 40 {
			t.Errorf("a text field lost its limit: %d", title.MaxLen)
		}
	}
}
