// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"strings"
	"testing"
)

// Every page has a Markdown copy of its words, never indexed and naming
// the page as canonical; a page says where it lives, and one that asks to
// be left out of results is, from its head, its headers and the sitemap.
func TestAPageHasAMarkdownCopyAndSaysWhereItLives(t *testing.T) {
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Marginalia", "sections": []any{
			map[string]any{"id": "s1", "hero": map[string]any{"title": "Paper, made in small runs", "lead": "From a mill in Kent.",
				"image": strings.Repeat("ab", 32)}},
			map[string]any{"id": "s2", "features": map[string]any{"title": "Why us", "items": []any{
				map[string]any{"title": "Cotton rag", "text": "No wood pulp."},
				map[string]any{"title": "Returns", "href": "/returns", "text": "Thirty days."},
				map[string]any{"title": "Bad", "href": "javascript:alert(1)"},
			}}},
		}},
		"thanks":  map[string]any{"title": "Thank you", "noindex": true},
		"essay":   map[string]any{"title": "An essay", "canonical": "https://journal.example/essay"},
		"returns": map[string]any{"title": "Returns", "body": "Unopened items within thirty days."},
	})
	w := get(st, "/index.md", nil)
	md := w.Body.String()
	if w.Code != 200 || w.Header().Get("X-Robots-Tag") != "noindex" ||
		w.Header().Get("Link") != `<https://example.org/>; rel="canonical"` {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	for _, want := range []string{"# Marginalia", "## Paper, made in small runs", "From a mill in Kent.", "## Why us",
		"- Cotton rag: No wood pulp.", "- [Returns](/returns): Thirty days.", "- Bad"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in\n%s", want, md)
		}
	}
	if strings.Contains(md, "javascript:") || strings.Contains(md, strings.Repeat("ab", 32)) {
		t.Fatalf("a script link or a media id in the copy:\n%s", md)
	}
	if got := get(st, "/returns.md", nil).Body.String(); !strings.Contains(got, "Unopened items within thirty days.") {
		t.Fatal(got)
	}
	if w := get(st, "/nowhere.md", nil); w.Code != 404 {
		t.Errorf("a copy of no page: %d", w.Code)
	}

	page := get(st, "/returns", nil).Body.String()
	if !strings.Contains(page, `<link rel="canonical" href="https://example.org/returns">`) ||
		!strings.Contains(page, `type="text/markdown" href="/returns.md"`) {
		t.Fatalf("%s", page)
	}
	thanks := get(st, "/thanks", nil)
	if thanks.Header().Get("X-Robots-Tag") != "noindex" || !strings.Contains(thanks.Body.String(), `<meta name="robots" content="noindex">`) {
		t.Fatal("a page that asks to be left out of results is not")
	}
	if !strings.Contains(get(st, "/essay", nil).Body.String(), `href="https://journal.example/essay"`) {
		t.Fatal("a copy does not name the page it copies")
	}
	sm := get(st, "/sitemap.xml", nil).Body.String()
	if strings.Contains(sm, "/thanks") || strings.Contains(sm, "/essay") || !strings.Contains(sm, "/returns") {
		t.Fatalf("%s", sm)
	}
}
