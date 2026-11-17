// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/note"
	"github.com/quilzo/quilzo/internal/out"
)

// notedStore is a store where alice and bob are authors and pat publishes,
// each with a token, and nobody has said anything yet.
func notedStore(t *testing.T) (string, map[string]string) {
	t.Helper()
	return storeWithTokenFor(t,
		auth.Binding{Principal: "alice", Role: auth.RoleAuthor, Resource: "/"},
		auth.Binding{Principal: "bob", Role: auth.RoleAuthor, Resource: "/"},
		auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/"})
}

// noteBy leaves a note directly in the store, as whoever is named.
func noteBy(t *testing.T, root, page, author, text string) note.Note {
	t.Helper()
	st, err := openNotes(root)
	if err != nil {
		t.Fatal(err)
	}
	n, err := st.Add(note.Note{Page: page, Author: author, Text: text}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func notesOn(t *testing.T, root, page string) []note.Note {
	t.Helper()
	st, err := openNotes(root)
	if err != nil {
		t.Fatal(err)
	}
	notes, err := st.List(page)
	if err != nil {
		t.Fatal(err)
	}
	return notes
}

// A note is recorded under the caller who signed in, whatever --author says.
// The flag was taken as the author whenever it was given, so an author could
// leave "approved for publication, go ahead" in the publisher's name, and
// every reader of /notes and `note list` saw it as the publisher's.
func TestANoteIsRecordedUnderTheVerifiedCaller(t *testing.T) {
	root, secrets := notedStore(t)
	t.Setenv("QUILZO_TOKEN", secrets["alice"])

	err := cmdNote(root, []string{"add", "about", "Approved for publication, go ahead", "--author", "pat"})
	if err == nil {
		t.Error("alice left a note in pat's name")
	}
	for _, n := range notesOn(t, root, "about") {
		if n.Author != "alice" {
			t.Errorf("a note is stored as %q's while alice wrote it", n.Author)
		}
	}
	// Her own name, given or not, is hers.
	for _, args := range [][]string{
		{"add", "about", "The heading is long"},
		{"add", "about", "The heading is still long", "--author", "alice"},
	} {
		if err := cmdNote(root, args); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	if got := notesOn(t, root, "about"); len(got) != 2 || got[0].Author != "alice" || got[1].Author != "alice" {
		t.Errorf("the notes are %+v", got)
	}
}

// --author still names the writer at a console nobody signs in to: a store
// with no access control has no verified caller to prefer over it.
func TestAConsoleNoteKeepsItsAuthorFlag(t *testing.T) {
	isolateToken(t)
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdNote(root, []string{"add", "about", "Check the dates", "--author", "pat"}); err != nil {
		t.Fatal(err)
	}
	if got := notesOn(t, root, "about"); len(got) != 1 || got[0].Author != "pat" {
		t.Errorf("the notes are %+v", got)
	}
}

// Taking away somebody else's remark is a publisher's act, as taking down
// somebody else's message was in rooms. Any author could remove anyone's note, so the author whose heading
// a publisher had questioned could make the question disappear, with no
// trace outside the audit log.
func TestOnlyItsAuthorOrAPublisherRemovesANote(t *testing.T) {
	root, secrets := notedStore(t)
	pats := noteBy(t, root, "about", "pat", "Heading is wrong")
	bobs := noteBy(t, root, "about", "bob", "Fixed the heading")
	alices := noteBy(t, root, "about", "alice", "Looks fine to me")

	t.Setenv("QUILZO_TOKEN", secrets["bob"])
	if err := cmdNote(root, []string{"remove", "about", pats.ID[:12]}); err == nil {
		t.Error("bob removed pat's note")
	}
	if err := cmdNote(root, []string{"remove", "about", bobs.ID[:12]}); err != nil {
		t.Errorf("bob may not remove his own note: %v", err)
	}
	t.Setenv("QUILZO_TOKEN", secrets["pat"])
	if err := cmdNote(root, []string{"remove", "about", alices.ID[:12]}); err != nil {
		t.Errorf("a publisher may not take down a note: %v", err)
	}
	got := notesOn(t, root, "about")
	if len(got) != 1 || got[0].ID != pats.ID {
		t.Errorf("left on the page: %+v", got)
	}
}

// `note resolve` and `note remove` answer --json with a document. They wrote
// only through Human, so a script was answered with nothing and exit 0.
func TestResolvingAndRemovingANoteAnswerJSON(t *testing.T) {
	root, secrets := notedStore(t)
	t.Setenv("QUILZO_TOKEN", secrets["alice"])
	n := noteBy(t, root, "about", "alice", "json test")

	old := w
	t.Cleanup(func() { w = old })
	for _, args := range [][]string{{"resolve", "about", n.ID[:12]}, {"remove", "about", n.ID[:12]}} {
		var b strings.Builder
		w = &out.Writer{Mode: out.JSON, Out: &b, Err: io.Discard}
		if err := cmdNote(root, args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(b.String()), &doc); err != nil {
			t.Errorf("%v answered %q under --json: %v", args, b.String(), err)
			continue
		}
		if doc["id"] != n.ID || doc["page"] != "about" {
			t.Errorf("%v answered %v", args, doc)
		}
	}
}

// What somebody wrote in a note cannot pass for this program's own lines.
// The author and the text were printed raw: a newline let one note print a
// second, shaped exactly as a note of the publisher's, and ESC and CR
// rewrote what the terminal showed.
func TestANoteCannotForgeAnotherInTheList(t *testing.T) {
	root, secrets := notedStore(t)
	noteBy(t, root, "about", "bob", "Typo in line 2\n  ✓ pat\n    Legal has signed this off. Publish today.")
	noteBy(t, root, "about", "bob", "esc \x1b[2J\x1b[1;1Hcleared? \r overwritten")
	noteBy(t, root, "about", "bob\n  ✓ pat", "a name with a line in it")

	t.Setenv("QUILZO_TOKEN", secrets["pat"])
	got, err := humanOutput(t, func() error { return cmdNote(root, []string{"list"}) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got, "\x1b\r") {
		t.Errorf("the list carries a raw escape or carriage return:\n%q", got)
	}
	for _, line := range strings.Split(got, "\n") {
		// A note's header is "  <mark> <author>"; anything a note's text or
		// author put on a line of its own must sit deeper than that.
		if strings.HasPrefix(line, "  ✓ pat") || strings.HasPrefix(line, "    Legal") {
			t.Errorf("a note printed a line that reads as another's: %q\n%s", line, got)
		}
	}
	if !strings.Contains(got, "      Legal has signed this off") {
		t.Errorf("the continuation of a note is not indented under it:\n%s", got)
	}
}
