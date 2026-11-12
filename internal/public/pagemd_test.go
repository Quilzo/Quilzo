// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/listing"
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

// shopSite is a stationer's shop: a page whose content is a listing of the
// catalogue, a page that lists it by the page field, a page for each product
// and a thank-you page left out of search results.
func shopSite(t *testing.T) *Site {
	t.Helper()
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Marginalia"},
		"shop": map[string]any{"title": "Everything", "intro": "The whole catalogue, newest first.",
			"sections": []any{map[string]any{"listing": map[string]any{"name": "catalogue"}}}},
		"instock": map[string]any{"title": "In stock", "listings": "catalogue"},
		"product": map[string]any{"detail": "catalogue", "detail_key": "slug"},
		"thanks":  map[string]any{"title": "Thank you for ordering", "noindex": true},
	})
	recs := []collection.Record{
		{ID: "11111111111111111111111111111111", Fields: map[string]any{"name": "Indigo ink", "slug": "indigo-ink",
			"price_display": "£12.00", "description": "Iron gall, blue-black.", "sku": "SKU-SECRET-1"}},
		{ID: "22222222222222222222222222222222", Fields: map[string]any{"name": "Cotton notebook", "slug": "notebook",
			"price_display": "£18.00", "description": "Rag paper, sewn.", "sku": "SKU-SECRET-2"}},
	}
	tree, _, err := collection.PutMany(st.Store, "", "products", recs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	set := &listing.Set{}
	if err := set.Add(listing.Listing{Name: "catalogue", Label: "The catalogue", Collection: "products", Sort: "name",
		Rows: 20, Fields: []string{"name", "slug", "price_display", "description"}}); err != nil {
		t.Fatal(err)
	}
	st.Listings = &listing.Resolver{Store: st.Store, Set: set, Live: func() string { return tree }}
	return st
}

// TestAListingPagesCopyHasItsRows — found by following llms.txt as an
// agent would: /shop.md was the shop's heading and intro and not one
// product, /blog.md not one post and /events.md not one event, because the
// copy was made from the page's own fields and a listing's rows are not in
// them. The copy now has what a visitor is shown: each row as a list item,
// with its link, its price or its date.
func TestAListingPagesCopyHasItsRows(t *testing.T) {
	st := shopSite(t)
	for path, want := range map[string][]string{
		"/shop.md": {"# Everything", "The whole catalogue, newest first.",
			"- [Indigo ink](/product/indigo-ink) (£12.00): Iron gall, blue-black.",
			"- [Cotton notebook](/product/notebook) (£18.00): Rag paper, sewn."},
		"/instock.md": {"# In stock", "## The catalogue", "- [Indigo ink](/product/indigo-ink) (£12.00)"},
	} {
		w := get(st, path, nil)
		md := w.Body.String()
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		for _, s := range want {
			if !strings.Contains(md, s) {
				t.Errorf("%s lacks %q:\n%s", path, s, md)
			}
		}
		if strings.Contains(md, "SKU-SECRET") {
			t.Errorf("%s carries a field the listing keeps private:\n%s", path, md)
		}
	}

	blog := get(blogSite(t), "/blog.md", nil).Body.String()
	for _, s := range []string{"## From the oven", "- [Rye, at last](/post/rye) (25 January 2026): What came out of the oven on day 25.",
		"- [Day 16](/post/day-16)"} {
		if !strings.Contains(blog, s) {
			t.Errorf("/blog.md lacks %q:\n%s", s, blog)
		}
	}
	if strings.Contains(blog, "do not publish") {
		t.Errorf("/blog.md carries a field the listing keeps private:\n%s", blog)
	}

	ev, _ := eventsSite(t)
	events := get(ev, "/events.md", nil).Body.String()
	for _, s := range []string{"## What's on", "- [Rye night](/event/rye-night) (", "The bakery", "£5", "Four ryes, tasted."} {
		if !strings.Contains(events, s) {
			t.Errorf("/events.md lacks %q:\n%s", s, events)
		}
	}
	if strings.Contains(events, "Last week's tasting") {
		t.Errorf("/events.md lists an event that is over:\n%s", events)
	}
}

// TestARecordsPageHasAMarkdownCopy — found the same way: each product,
// post and event has a page of its own, and /post/rye.md answered 404, so
// an agent following a listing's link to the copy found nothing. The page
// itself offered /post.md, the empty copy of the page posts are drawn with,
// and named /post as its canonical address, so every post told search
// engines it was a copy of that one.
func TestARecordsPageHasAMarkdownCopy(t *testing.T) {
	w := get(blogSite(t), "/post/rye.md", nil)
	md := w.Body.String()
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/markdown") ||
		w.Header().Get("X-Robots-Tag") != "noindex" ||
		w.Header().Get("Link") != `<https://crumb.example/post/rye>; rel="canonical"` {
		t.Fatalf("%d %v\n%s", w.Code, w.Header(), md)
	}
	for _, s := range []string{"# Rye, at last", "25 January 2026", "Sam Baker", "The rye took three tries.", "## What changed"} {
		if !strings.Contains(md, s) {
			t.Errorf("/post/rye.md lacks %q:\n%s", s, md)
		}
	}
	if strings.Contains(md, "do not publish") {
		t.Errorf("the copy carries a field the listing keeps private:\n%s", md)
	}
	page := getPage(blogSite(t), "/post/rye").Body.String()
	for _, want := range []string{`<link rel="canonical" href="https://crumb.example/post/rye">`,
		`<link rel="alternate" type="text/markdown" href="/post/rye.md">`} {
		if !strings.Contains(page, want) {
			t.Errorf("the post's page lacks %s", want)
		}
	}

	shop := shopSite(t)
	shop.BaseURL = "https://marginalia.example"
	p := get(shop, "/product/indigo-ink.md", nil)
	if p.Code != 200 || !strings.Contains(p.Body.String(), "# Indigo ink") || !strings.Contains(p.Body.String(), "£12.00") ||
		!strings.Contains(p.Body.String(), "Iron gall, blue-black.") || strings.Contains(p.Body.String(), "SKU-SECRET") {
		t.Fatalf("%d\n%s", p.Code, p.Body.String())
	}
	if w := get(shop, "/product/nothing.md", nil); w.Code != 404 {
		t.Errorf("a copy of no record: %d", w.Code)
	}

	ev, _ := eventsSite(t)
	e := get(ev, "/event/rye-night.md", nil).Body.String()
	for _, s := range []string{"# Rye night", "The bakery", "1 High Street, Leeds", "£5", "Four ryes, tasted."} {
		if !strings.Contains(e, s) {
			t.Errorf("/event/rye-night.md lacks %q:\n%s", s, e)
		}
	}
}

// TestLLMsTxtListsWhatTheSitemapLists — found by reading llms.txt: it
// listed the bare templates a product, a post and an event are drawn with
// (/product.md, two bytes of nothing) and a page that asks to be left out
// of search results, which the sitemap leaves out.
func TestLLMsTxtListsWhatTheSitemapLists(t *testing.T) {
	body := get(shopSite(t), "/llms.txt", nil).Body.String()
	for _, want := range []string{"(/index.md)", "(/shop.md)", "(/instock.md)"} {
		if !strings.Contains(body, want) {
			t.Errorf("llms.txt lacks %s:\n%s", want, body)
		}
	}
	for _, not := range []string{"(/product.md)", "(/thanks.md)"} {
		if strings.Contains(body, not) {
			t.Errorf("llms.txt lists %s:\n%s", not, body)
		}
	}
}
