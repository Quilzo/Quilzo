// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// From the command line: a page made a block, reused on another, listed
// with where it is used, and kept while it is.
func TestABlockIsReusedFromTheCommandLine(t *testing.T) {
	root := demoStore(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["hours"] = map[string]any{"title": "Opening hours", "sections": []any{
		map[string]any{"text": map[string]any{"title": "Open nine to five"}}}}
	if _, err := site.SaveDraft(s, pages, "hours", "test"); err != nil {
		t.Fatal(err)
	}
	if err := cmdSection(root, []string{"reuse", "index", "hours"}); err == nil {
		t.Fatal("reused a page that is not a block")
	}
	if err := cmdSection(root, []string{"block", "hours"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSection(root, []string{"reuse", "index", "hours", "--at", "0"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSection(root, []string{"blocks"}); err != nil {
		t.Fatal(err)
	}
	pages, _ = site.PagesAt(s, site.RefDraft)
	if got := site.BlockUses(pages)["hours"]; len(got) != 1 || got[0] != "index" {
		t.Fatalf("%v", got)
	}
	if name, ok := site.BlockRef(pages["index"].(map[string]any)["sections"].([]any)[0]); !ok || name != "hours" {
		t.Fatal("not reused first")
	}
	if err := cmdSection(root, []string{"block", "hours", "--off"}); err == nil || !strings.Contains(err.Error(), "index") {
		t.Fatalf("made a page again while reused: %v", err)
	}
	// As a reader gets it: the chatbot reads the block's words on the page.
	read := site.WithBlocks(pages)
	if _, alone := read["hours"]; alone {
		t.Fatal("the block is read on its own")
	}
	b, _ := json.Marshal(read["index"])
	if !strings.Contains(strings.ToLower(string(b)), "open nine to five") {
		t.Fatal("the page does not read as the block")
	}
}

// A page that reuses a block can be published. The arrangement gate used to
// read the reuse section as a section of the kind "block", which there is not,
// and refused every page that reused one with "renders as nothing at all":
// the documented way to reuse a block was the one way never to publish it.
// What is still refused is a reuse that does show nothing: one naming a page
// that is not a block, or that is not there.
func TestAPageReusingABlockPassesTheArrangementGate(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	ref := func(page string) any {
		return map[string]any{"id": "r-" + page, "block": map[string]any{"page": page}}
	}
	pages := map[string]any{
		"index": map[string]any{"title": "Home", "sections": []any{ref("promo")}},
		"promo": map[string]any{"title": "Promo", "block": true, "sections": []any{
			map[string]any{"prose": map[string]any{"title": "Ten per cent off",
				"paragraphs": []any{"On everything, this week."}}}}},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	arrangement := func() []string {
		t.Helper()
		for _, c := range contentGates(root, s, "") {
			if c.Name != "arrangement" {
				continue
			}
			bad, _, err := c.Run()
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, f := range bad {
				out = append(out, f.Page+": "+f.Detail)
			}
			return out
		}
		t.Fatal("no arrangement gate")
		return nil
	}
	if bad := arrangement(); len(bad) != 0 {
		t.Fatalf("a page reusing a block was refused: %v", bad)
	}

	pages["about"] = map[string]any{"title": "About", "sections": []any{ref("index"), ref("gone")}}
	if _, err := site.SaveDraft(s, pages, "second", "test"); err != nil {
		t.Fatal(err)
	}
	bad := arrangement()
	if len(bad) != 2 || !strings.Contains(bad[0], "index") || !strings.Contains(bad[1], "gone") {
		t.Fatalf("a reuse of what is not a block was not refused: %v", bad)
	}
}

// A link written in a page to a page of the site that is not there is said
// at publish. Every starter's sample linked to pages it never made — /about,
// /contact, /guide, /start, /shop, /work/reading — and they published as 404s
// with nothing said: a menu entry pointing at nothing is refused, and a link
// in the words was never looked at. Said, not refused, because a page may go
// out before the one it links to; and only of what is certainly nowhere, so
// the site's own routes, files and redirects are left alone.
func TestALinkToNoPageIsSaidAtPublish(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdRedirect(root, []string{"add", "/old-prices", "/about"}); err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index": map[string]any{"title": "Home",
			"hero": map[string]any{"lead": "Hello.", "cta_label": "Read the guide", "cta_href": "/guide",
				"secondary_label": "See", "secondary_href": "#features"},
			"header_cta_href": "/about?from=top",
			"sections": []any{map[string]any{"features": map[string]any{"title": "Things", "items": []any{
				map[string]any{"title": "Work", "href": "/work/reading"},
				map[string]any{"title": "Blog", "href": "/blog/first-post"},
				map[string]any{"title": "Old", "href": "/old-prices"},
				map[string]any{"title": "Feed", "href": "/feed.xml"},
				map[string]any{"title": "Search", "href": "/search?q=bread"},
				map[string]any{"title": "Picture", "href": "/media/" + strings.Repeat("a", 64)},
				map[string]any{"title": "Elsewhere", "href": "https://example.org/about"},
				map[string]any{"title": "Home", "href": "/"},
			}}}}},
		"about": map[string]any{"title": "About"},
		"blog":  map[string]any{"title": "Blog"},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	for _, c := range contentGates(root, s, "") {
		if c.Name != "navigation" {
			continue
		}
		bad, advice, err := c.Run()
		if err != nil {
			t.Fatal(err)
		}
		if len(bad) > 0 {
			t.Errorf("a link to no page refused the publish: %v", bad)
		}
		var said []string
		for _, f := range advice {
			said = append(said, f.Page+": "+f.Detail)
		}
		all := strings.Join(said, "\n")
		for _, want := range []string{"/guide", "/work/reading"} {
			if !strings.Contains(all, want) {
				t.Errorf("a link to %s, which is no page, is not said: %q", want, all)
			}
		}
		for _, fine := range []string{"/about", "/blog/", "/old-prices", "/feed.xml", "/search", "/media/", "example.org", "#features", `"/"`} {
			if strings.Contains(all, fine) {
				t.Errorf("a link that goes somewhere is said to go nowhere (%s): %q", fine, all)
			}
		}
		if len(advice) != 2 {
			t.Errorf("%d links said, want 2: %q", len(advice), all)
		}
		return
	}
	t.Fatal("there is no navigation gate")
}

// A link in a page's words is a link written in the page too. A page's body
// and a prose section's are drawn with [words](address) as links, so
// "[our story](/story)" sent a reader to a page that was not there as
// surely as a button did, and the publish said nothing of it while it named
// every button that did the same.
func TestALinkInAPagesWordsToNoPageIsSaidAtPublish(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index": map[string]any{"title": "Home",
			"body": "Read [our story](/story) or [about us](/about), and [elsewhere](https://example.org/x).",
			"sections": []any{map[string]any{"prose": map[string]any{"title": "More",
				"body": "See [the prices](/prices#now) and [the feed](/feed.xml)."}}}},
		"about": map[string]any{"title": "About"},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	for _, c := range contentGates(root, s, "") {
		if c.Name != "navigation" {
			continue
		}
		_, advice, err := c.Run()
		if err != nil {
			t.Fatal(err)
		}
		var said []string
		for _, f := range advice {
			said = append(said, f.Page+": "+f.Detail)
		}
		all := strings.Join(said, "\n")
		for _, want := range []string{"/story", "/prices#now"} {
			if !strings.Contains(all, want) {
				t.Errorf("a link in the words to %s, which is no page, is not said: %q", want, all)
			}
		}
		for _, fine := range []string{"/about", "example.org", "/feed.xml"} {
			if strings.Contains(all, fine) {
				t.Errorf("a link that goes somewhere is said to go nowhere (%s): %q", fine, all)
			}
		}
		return
	}
	t.Fatal("there is no navigation gate")
}
