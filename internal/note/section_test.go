// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package note

import (
	"testing"
	"time"
)

// A note can be about a block.
//
// It could not. This package anchors a remark to a page and a field name, and
// says why a position would not do: "a position moves when a paragraph is
// added above it, and a note that drifts to the wrong paragraph is the failure
// this is trying to avoid".
//
// That reasoning was right and it left a note unable to attach to a section at
// all, because a section had no name — it was a position in a list and nothing
// else. internal/section/id.go gave it one. This is the join.
func TestANoteCanBeAboutASection(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	written, err := st.Add(Note{
		Page: "about", Section: "8f3c1a90", Author: "ada",
		Text: "this quote needs a source", Content: "hash1",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if written.Section != "8f3c1a90" {
		t.Fatalf("the section was not kept: %+v", written)
	}

	// And it comes back with the page's notes, where a screen filters for the
	// section it is showing. The store is keyed by page and stays that way: a
	// section note is a page note that knows which block it is about.
	all, err := st.List("about")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Section != "8f3c1a90" {
		t.Errorf("the note did not come back with its section: %+v", all)
	}
}

// A note about the page as a whole still has no section, which is how a screen
// tells the two apart.
func TestAPageNoteHasNoSection(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	written, err := st.Add(Note{
		Page: "about", Author: "ada", Text: "the whole thing reads oddly",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if written.Section != "" {
		t.Errorf("a note about the page claims a section: %q", written.Section)
	}
}
