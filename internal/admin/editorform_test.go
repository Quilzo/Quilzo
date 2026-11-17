// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/i18n"
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

// Review told whoever approves a change to read it first, and showed the
// page's name and the word "modified": nothing of what the page now says.
// Each modified page shows the fields that changed, before and after.
func TestReviewShowsWhatChangedInsideAPage(t *testing.T) {
	srv, token := setup(t)
	if _, err := site.Publish(srv.Store, ""); err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["about"] = map[string]any{"title": "About", "body": "Who we are, and since when."}
	if _, err := site.SaveDraft(srv.Store, pages, "an edit", "test"); err != nil {
		t.Fatal(err)
	}
	html := get(t, srv, "/review", token).Body.String()
	for _, want := range []string{"Who we are.", "Who we are, and since when."} {
		if !strings.Contains(html, want) {
			t.Errorf("review does not show %q", want)
		}
	}
	if strings.Contains(html, "Welcome.") {
		t.Error("review shows a page nobody changed")
	}
}

// browserForm is what a browser submits for the editor's fields: each box
// with what it was drawn holding, and a checkbox only when it is ticked.
func browserForm(name string, fields []field) url.Values {
	form := url.Values{"__name": {name}}
	for _, f := range fields {
		if f.Checkbox {
			if f.Checked {
				form.Set(f.Key, "true")
			}
			continue
		}
		form.Set(f.Key, f.Value)
	}
	return form
}

// A page with a type may carry what its type does not declare: the fields
// every page may have (its sections, its hero, its terms, whether it is for
// members only), and values a type would refuse. The editor drew each as an
// empty text box unless it was text, and an empty box is how a field is
// removed, so saving a typed page from the browser took its sections, its
// terms and its members-only mark off it: a page for members became public
// on the next publish, by an edit of its title. A value that is not text is
// kept unless somebody changes it.
func TestSavingATypedPageKeepsWhatItsTypeDoesNotDeclare(t *testing.T) {
	srv, token := setup(t)
	withTypes(t, srv)
	sections := []any{map[string]any{"prose": map[string]any{"title": "Our story"}}}
	terms := map[string]any{"topic": []any{"history"}}
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["index"] = map[string]any{
		"title": "Home", "body": "Welcome.",
		"sections": sections, "terms": terms, "hero": map[string]any{"title": "Hello"},
		"members_only": true, "noindex": true, "starts": "2026-01-01",
	}
	if _, err := site.SaveDraft(srv.Store, pages, "a typed page", "test"); err != nil {
		t.Fatal(err)
	}

	typ, _ := srv.TypeFor("index")
	form := browserForm("index", typedFields(typ, pages["index"], nil))
	form.Set("title", "Home, edited")
	// The editor's own Search engines fieldset, as it is drawn for this page.
	form.Set("__seo", "1")
	form.Set("__noindex", "1")
	if w := save(t, srv, token, form); w.Code != http.StatusSeeOther {
		t.Fatalf("the save answered %d: %s", w.Code, w.Body.String())
	}
	pages, err = site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	body := pages["index"].(map[string]any)
	if body["title"] != "Home, edited" {
		t.Errorf("the title is %#v", body["title"])
	}
	for key, want := range map[string]any{
		"sections": sections, "terms": terms, "hero": map[string]any{"title": "Hello"},
		"members_only": true, "noindex": true, "starts": "2026-01-01",
	} {
		if !reflect.DeepEqual(body[key], want) {
			t.Errorf("%s is %#v after a title-only save, want %#v", key, body[key], want)
		}
	}

	// A value the type refuses is still shown, so the refusal names
	// something visible, and is still removed by clearing its box; left
	// alone it is what it was.
	held := map[string]any{
		"title": "Home", "body": "Welcome.",
		"rows": 10.0, "gallery": []any{"a", "b"}, "note": "first\nsecond",
	}
	fields := typedFields(typ, held, nil)
	shown := map[string]field{}
	for _, f := range fields {
		shown[f.Key] = f
	}
	for _, key := range []string{"rows", "gallery", "note"} {
		if shown[key].Value == "" {
			t.Errorf("%s, which the type refuses, is drawn as an empty box", key)
		}
	}
	if !shown["note"].Long {
		t.Error("text of two lines is drawn in a one-line box, which joins them")
	}
	kept := srv.pageFromForm(map[string]any{"index": held}, "index", browserForm("index", fields))
	for _, key := range []string{"rows", "gallery", "note"} {
		if !reflect.DeepEqual(kept[key], held[key]) {
			t.Errorf("%s is %#v when nobody touched it, want %#v", key, kept[key], held[key])
		}
	}
	cleared := browserForm("index", fields)
	cleared.Set("rows", "")
	cleared.Set("gallery", "")
	gone := srv.pageFromForm(map[string]any{"index": held}, "index", cleared)
	for _, key := range []string{"rows", "gallery"} {
		if _, still := gone[key]; still {
			t.Errorf("%s is still there after its box was cleared: %#v", key, gone[key])
		}
	}
}

// A browser takes the line breaks out of what a one-line box holds, and the
// first line break out of a multi-line box that starts with one. So text of
// two short lines, an address or opening hours, drawn in a one-line box was
// joined into one line by a save that never touched it, and a body that
// began with a blank line lost it. Text with a line break is drawn in a
// multi-line box, and every such box begins with a line break of its own
// for the browser to take.
func TestTheEditorDrawsTextSoABrowserSendsItBackUnchanged(t *testing.T) {
	const hours = "Mon to Fri\nSat"
	for _, f := range flatten(map[string]any{"title": "Visit", "hours": hours}) {
		if f.Key == "hours" && !f.Long {
			t.Error("a page with no type: two short lines are drawn in a one-line box")
		}
	}
	typ := schema.Type{Name: "place", Fields: []schema.Field{
		{Name: "title", Kind: schema.Text}, {Name: "hours", Kind: schema.Text},
	}}
	for _, f := range typedFields(typ, map[string]any{"title": "Visit", "hours": hours}, nil) {
		switch {
		case f.Key == "hours" && !f.Long:
			t.Error("a page with a type: two short lines are drawn in a one-line box")
		case f.Key == "title" && f.Long:
			t.Error("a title of one line is drawn in a multi-line box")
		}
	}
	fields, err := section.Fields(map[string]any{section.Field: []any{
		map[string]any{"prose": map[string]any{"title": hours, "items": []any{hours}}},
	}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 2 {
		t.Fatalf("the section has %d fields to edit, want its title and its one item", len(fields))
	}
	for _, f := range fields {
		if f.Value == hours && !f.Long {
			t.Errorf("a section's %s: two short lines are drawn in a one-line box", f.Path)
		}
	}

	srv, token := setup(t)
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["about"] = map[string]any{"title": "About", "body": "\nBegins with a blank line."}
	if _, err := site.SaveDraft(srv.Store, pages, "a blank first line", "test"); err != nil {
		t.Fatal(err)
	}
	html := get(t, srv, "/page/about", token).Body.String()
	if !strings.Contains(html, ">\n\nBegins with a blank line.</textarea>") {
		t.Error("the body's box does not begin with a line break for the browser to take, so the body loses its own")
	}
}

// The preview is the page as a reader gets it, and a reader gets a
// translated page in its own language and direction. The preview showed the
// Arabic page as its layout wrote it, English and left to right, so what an
// editor checked was not what was published.
func TestThePreviewShowsATranslatedPageInItsLanguage(t *testing.T) {
	srv, token := setup(t)
	locales := i18n.NewConfig("en")
	if err := locales.Add("ar"); err != nil {
		t.Fatal(err)
	}
	srv.Languages = &Languages{Load: func() (*i18n.Config, error) { return locales, nil }}
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["ar/about"] = map[string]any{"title": "من نحن", "body": "مرحبا"}
	if _, err := site.SaveDraft(srv.Store, pages, "in Arabic", "test"); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"/preview/ar/about?plain=1": `<html lang="ar" dir="rtl">`,
		"/preview/about?plain=1":    `<html lang="en" dir="ltr">`,
	} {
		if html := get(t, srv, path, token).Body.String(); !strings.Contains(html, want) {
			t.Errorf("%s does not open %s: %.80s", path, want, html)
		}
	}
	// A site in one language is previewed as its layout wrote it.
	srv.Languages = nil
	if html := get(t, srv, "/preview/about?plain=1", token).Body.String(); !strings.Contains(html, `<html lang="en">`) {
		t.Errorf("a site in one language had its preview changed: %.80s", html)
	}
}

// The boxes that filter what a screen lists find a word as Find does:
// whatever case it was typed in and with or without its marks. Records and
// the picture picker lowered both sides with strings.ToLower, under which
// the capital I of Turkish is never its own small letter ı, so an editor
// typing ÇILBIR, or cilbir on a keyboard without the letters, was shown no
// record and no picture of the dish.
func TestTheFiltersFindAWordInCapitalsAndWithoutItsMarks(t *testing.T) {
	records := []collection.Record{
		{ID: "a", Fields: map[string]any{"name": "Çılbır", "price": 120.0}},
		{ID: "b", Fields: map[string]any{"name": "Baklava", "price": 90.0}},
	}
	for _, q := range []string{"ÇILBIR", "cilbir", "çılbır", "120"} {
		if got := filterAnyField(records, q); len(got) != 1 || got[0].ID != "a" {
			t.Errorf("records: %q finds %v", q, got)
		}
	}
	if got := filterAnyField(records, "kahve"); len(got) != 0 {
		t.Errorf("records: a word no record has finds %v", got)
	}

	srv, token := setup(t)
	id := withLibrary(t, srv)
	lib, err := srv.Media.Library()
	if err != nil {
		t.Fatal(err)
	}
	f, body, err := lib.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "Bir tabak çılbır"
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	pick := func(q string) bool {
		html := get(t, srv, "/media/pick?page=index&at=0&path=poster&q="+url.QueryEscape(q), token).Body.String()
		return strings.Contains(html, `value="/media/`+id+`"`)
	}
	for _, q := range []string{"ÇILBIR", "cilbir", "çılbır", "TABAK"} {
		if !pick(q) {
			t.Errorf("the picker: %q does not find the picture of it", q)
		}
	}
	if pick("kahve") {
		t.Error("the picker: a word the picture does not have finds it")
	}
}
