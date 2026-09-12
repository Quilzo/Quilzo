// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/schema"
)

// The panel is built from content, so content cannot build the panel.
//
// This is the property that matters and the reason to write the markup by
// hand rather than through a template: a page name, a field value and a
// section label all end up inside the injected HTML, and all three are written
// by whoever can write content. The page being previewed is the draft, so a
// value here has not been through any gate yet.
//
// Nothing in the panel may come out as markup. Checked by looking for tags the
// panel does not write, which is the same shape as the prose transform's
// check and for the same reason: searching for "<script" as a substring cannot
// tell a tag from the same characters escaped as text, and escaping them is
// the transform working.
func TestNothingInAPageCanWriteMarkupIntoThePanel(t *testing.T) {
	nasty := `</details><script>alert(1)</script><a href="javascript:alert(1)">`

	for _, c := range []struct {
		name string
		page string
		body any
	}{
		{"in the page name", nasty, map[string]any{"title": "ok"}},
		{"in a field value", "hello", map[string]any{"title": nasty}},
		{"in a field name", "hello", map[string]any{nasty: "ok"}},
		{"in a section label", "hello", map[string]any{
			"sections": []any{map[string]any{"quote": map[string]any{
				"text": nasty, "who": nasty}}},
		}},
		{"in a section kind", "hello", map[string]any{
			"sections": []any{map[string]any{nasty: map[string]any{}}},
		}},
	} {
		bar := previewBar(c.page, c.body, schema.Type{}, false)
		if tag, ok := onlyPanelTags(bar); !ok {
			t.Errorf("%s: the panel emitted <%s>, which it does not write:\n  %s",
				c.name, tag, bar)
		}
		// On the hrefs, not on the whole string. Every one of these values
		// appears in the panel as escaped text, so searching for
		// "javascript:" as a substring finds &#34;javascript:… — which is the
		// escaping working, not failing. The same mistake the prose transform's
		// test records making, which is a good reason to record it twice.
		for _, href := range hrefsIn(bar) {
			low := strings.ToLower(href)
			if !strings.HasPrefix(href, "/") ||
				strings.HasPrefix(low, "//") ||
				strings.Contains(low, ":") {
				t.Errorf("%s: the panel linked to %q, which is not a rooted "+
					"path on this server", c.name, href)
			}
		}
	}
}

// onlyPanelTags reports the first tag in s that previewBar does not write.
func onlyPanelTags(s string) (string, bool) {
	allowed := map[string]bool{
		"div": true, "details": true, "summary": true, "span": true,
		"p": true, "ul": true, "ol": true, "li": true, "a": true,
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		j := i + 1
		if j < len(s) && s[j] == '/' {
			j++
		}
		k := j
		for k < len(s) && ((s[k] >= 'a' && s[k] <= 'z') || (s[k] >= '0' && s[k] <= '9')) {
			k++
		}
		if name := s[j:k]; !allowed[name] {
			return name, false
		}
	}
	return "", true
}

// The stylesheet goes in the head and the panel goes in the body.
//
// Two insertions rather than one, because a <link rel="stylesheet"> in the
// body is something browsers accept and the specification does not — and this
// is a document somebody may run through a validator.
func TestThePanelIsInsertedWhereEachHalfBelongs(t *testing.T) {
	page := `<!doctype html><html><head><title>x</title></head><body><h1>Hi</h1></body></html>`
	out := injectBar(page, `<div class="qz-bar">panel</div>`)

	head := strings.Index(out, "<head>")
	link := strings.Index(out, `href="/preview.css"`)
	headEnd := strings.Index(out, "</head>")
	bodyAt := strings.Index(out, "<body>")
	panel := strings.Index(out, `class="qz-bar"`)

	if link < head || link > headEnd {
		t.Errorf("the stylesheet is not in the head:\n  %s", out)
	}
	if panel < bodyAt {
		t.Errorf("the panel is not inside the body:\n  %s", out)
	}
	// And the page it was given is still all there, in order.
	if !strings.Contains(out, "<h1>Hi</h1>") ||
		!strings.Contains(out, "<title>x</title>") {
		t.Errorf("injecting the panel changed the page:\n  %s", out)
	}
}

// A layout is somebody else's file, so the tags may be in any case and may not
// be there at all.
func TestInjectionSurvivesAnUnusualDocument(t *testing.T) {
	for _, page := range []string{
		`<!DOCTYPE html><HTML><HEAD></HEAD><BODY>x</BODY></HTML>`,
		`<html><body>x</body></html>`,
		`<body>x</body>`,
		`<p>a fragment with no body at all</p>`,
		``,
	} {
		out := injectBar(page, `<div class="qz-bar">panel</div>`)
		if !strings.Contains(out, `class="qz-bar"`) {
			t.Errorf("the panel was dropped from %q", page)
		}
		if !strings.Contains(out, `href="/preview.css"`) {
			t.Errorf("the stylesheet was dropped from %q", page)
		}
		// Whatever was there is still there.
		if page != "" && !strings.Contains(out, "x") &&
			!strings.Contains(out, "fragment") {
			t.Errorf("content was lost from %q:\n  %s", page, out)
		}
	}
}

// A typed page is listed in the type's order and with the type's labels; an
// untyped one alphabetically.
//
// The order is the editor's argument: "the declaration is the author's
// sequence of thought". A panel that sorted a typed page alphabetically would
// disagree with the form it links into, entry by entry.
func TestFieldsAreListedTheWayTheTypeDeclaresThem(t *testing.T) {
	typ := schema.Type{Name: "post", Fields: []schema.Field{
		{Name: "zebra", Kind: schema.Text, Label: "Last"},
		{Name: "alpha", Kind: schema.Text, Label: "First"},
	}}
	body := map[string]any{"alpha": "a", "zebra": "z"}

	got := previewFields(body, typ, true)
	if len(got) != 2 || got[0].label != "Last" || got[1].label != "First" {
		t.Errorf("a typed page was not listed in the type's order: %+v", got)
	}

	// Untyped: alphabetical, because there is no declared order to keep and a
	// map has none of its own.
	got = previewFields(body, schema.Type{}, false)
	if len(got) != 2 || got[0].key != "alpha" || got[1].key != "zebra" {
		t.Errorf("an untyped page was not listed alphabetically: %+v", got)
	}
}

// The arrangement is listed as sections, not twice.
func TestTheArrangementIsNotAlsoAField(t *testing.T) {
	body := map[string]any{
		"title":    "Hello",
		"layout":   "page",
		"sections": []any{map[string]any{"quote": map[string]any{"text": "x"}}},
	}
	for _, f := range previewFields(body, schema.Type{}, false) {
		if f.key == "sections" || f.key == "layout" {
			t.Errorf("%q is listed as a field; sections are listed as sections "+
				"and a layout is not content", f.key)
		}
	}
}

// A long value is cut on a character, not on a byte.
//
// Cutting a multi-byte character in half puts a replacement glyph in a panel
// somebody is reading to recognise which field they want.
func TestALongValueIsCutOnACharacter(t *testing.T) {
	long := strings.Repeat("é", 200)
	got := peek(long)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a long value was not shortened: %q", got)
	}
	if strings.ContainsRune(got, '\uFFFD') {
		t.Errorf("the value was cut mid-character: %q", got)
	}
	// And a short one is left alone.
	if peek("short") != "short" {
		t.Errorf("a short value was changed: %q", peek("short"))
	}
	// A value that is not text has no preview rather than a rendering of its
	// Go type.
	if p := peek([]any{1, 2}); p != "" {
		t.Errorf("a non-text value produced %q", p)
	}
}

// hrefsIn collects the addresses the panel actually linked to.
func hrefsIn(s string) []string {
	var out []string
	for _, seg := range strings.Split(s, `<a href="`)[1:] {
		if end := strings.IndexByte(seg, '"'); end >= 0 {
			out = append(out, seg[:end])
		}
	}
	return out
}
