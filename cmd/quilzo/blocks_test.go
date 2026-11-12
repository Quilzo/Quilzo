// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
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

// A section is listed by a line of its own content, cut where a character
// starts and to 44 bytes with its mark, so the list stays one row a section.
func TestASectionIsListedByItsWordsCutBetweenCharacters(t *testing.T) {
	root := demoStore(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	kept := strings.Repeat("a", 41)
	pages["hours"] = map[string]any{"title": "Opening hours", "sections": []any{
		map[string]any{"prose": map[string]any{"title": kept + "a中文"}}}}
	if _, err := site.SaveDraft(s, pages, "hours", "test"); err != nil {
		t.Fatal(err)
	}
	saved := w
	t.Cleanup(func() { w = saved })
	stdout, read := captureStdout(t)
	w = &out.Writer{Out: stdout, Err: io.Discard}
	err = cmdSection(root, []string{"list", "hours"})
	if listed := read(); err != nil || !strings.Contains(listed, " "+kept+"…\n") {
		t.Fatalf("%v\n%q", err, listed)
	}
}
