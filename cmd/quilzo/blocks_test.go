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
