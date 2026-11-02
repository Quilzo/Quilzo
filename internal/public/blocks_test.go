// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

const blockTpl = `<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head><body>
<h1>{{ page.title }}</h1>{% for s in page.sections %}<p>{{ s.cta.title }}</p>{% end %}</body></html>`

// A block is no page of its own on the public site, and a page reusing it
// shows its sections; when only the block changes, the page's ETag does
// too, so nothing cached shows the old block.
func TestAReusedBlockIsServedOnlyWhereItIsReused(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index": map[string]any{"title": "Home", "sections": []any{
			map[string]any{"id": "x1", "block": map[string]any{"page": "cta"}}}},
		"cta": map[string]any{"title": "Call", "block": true, "sections": []any{
			map[string]any{"cta": map[string]any{"title": "Order a sample"}}}},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	st := New(s, render.OneLayout(blockTpl))
	w := get(st, "/", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Order a sample") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	tag := w.Header().Get("ETag")
	if tag == "" {
		t.Fatal("a page with no ETag")
	}
	if w := get(st, "/cta", nil); w.Code != http.StatusNotFound {
		t.Fatalf("a block served on its own: %d", w.Code)
	}
	if w := get(st, "/sitemap.xml", nil); strings.Contains(w.Body.String(), "/cta") {
		t.Fatal("a block in the sitemap")
	}

	pages["cta"] = map[string]any{"title": "Call", "block": true, "sections": []any{
		map[string]any{"cta": map[string]any{"title": "Book a visit"}}}}
	if _, err := site.SaveDraft(s, pages, "the block changed", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	w = get(st, "/", nil)
	if !strings.Contains(w.Body.String(), "Book a visit") || strings.Contains(w.Body.String(), "Order a sample") {
		t.Fatalf("%s", w.Body.String())
	}
	if w.Header().Get("ETag") == tag {
		t.Fatal("the page kept its ETag when its block changed")
	}
	if w := get(st, "/", map[string]string{"If-None-Match": tag}); w.Code == http.StatusNotModified {
		t.Fatal("a cache was told the old block is still current")
	}
}
