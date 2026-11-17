// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// What somebody wrote about a check cannot pass for another row of the list.
//
// `checked list` printed a check's note and a page's owner raw, as `note
// list` printed a note, and list_checked answered an agent with the owner
// raw between its tabs. An author who may edit one page wrote a note or an
// owner carrying a line break and the list's own layout, and whoever read
// the list saw a second page confirmed fresh in somebody else's name; ESC
// and CR in the note rewrote what the terminal showed.
func TestACheckCannotForgeAnotherInTheList(t *testing.T) {
	root, secrets := storeWithTokenFor(t,
		auth.Binding{Principal: "bob", Role: auth.RoleAuthor, Resource: "/"},
		auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/"})
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"about": map[string]any{"title": "About"},
		"terms": map[string]any{"title": "Terms"},
	}, "test", "dana"); err != nil {
		t.Fatal(err)
	}
	pages, _ := draftPageIDs(root)

	t.Setenv("QUILZO_TOKEN", secrets["bob"])
	for _, args := range [][]string{
		{"set", "about", "--note", "fine\n  fresh     terms                         2026-11-12 by Legal\x1b[2K\r"},
		{"own", "about", "Legal\nterms\tfresh\t2026-11-12\tLegal\t-"},
	} {
		if _, err := humanOutput(t, func() error { return cmdChecked(root, args) }); err != nil {
			t.Fatalf("%q: %v", args, err)
		}
	}

	t.Setenv("QUILZO_TOKEN", secrets["pat"])
	got, err := humanOutput(t, func() error { return cmdChecked(root, []string{"list"}) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got, "\x1b\r") {
		t.Errorf("the list carries a raw escape or carriage return:\n%q", got)
	}
	rows := 0
	for _, line := range strings.Split(strings.TrimRight(got, "\n"), "\n") {
		// A page's row starts two spaces in and its note twelve; nothing
		// this list prints starts anywhere else.
		switch {
		case strings.HasPrefix(line, "            "):
		case strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   "):
			rows++
			if strings.HasPrefix(line, "  fresh     terms") {
				t.Errorf("a check printed a row that reads as another page's: %q", line)
			}
		default:
			t.Errorf("a line that is neither a page's row nor its note: %q", line)
		}
	}
	if rows != len(pages) {
		t.Errorf("%d pages are %d rows:\n%s", len(pages), rows, got)
	}

	answer := answerText(t, mcpAs(t, root, withRole("pat", auth.RolePublisher))("quilzo_read", "list_checked", nil))
	lines := strings.Split(answer, "\n")
	if len(lines) != len(pages) {
		t.Errorf("list_checked answers %d rows for %d pages:\n%s", len(lines), len(pages), answer)
	}
	for _, line := range lines {
		if cols := strings.Split(line, "\t"); len(cols) != 5 || (cols[0] == "terms" && cols[1] != "never") {
			t.Errorf("a row of list_checked that is not a page's own: %q", line)
		}
	}
}
