// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package note

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func store(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func a(page, text string) Note {
	return Note{Page: page, Author: "ada", Text: text, Content: "hash-one"}
}

// A note is about a page, and a conversation is read in the order it happened.
func TestNotesAreAConversationInOrder(t *testing.T) {
	st := store(t)
	now := time.Unix(1_700_000_000, 0)

	for i, text := range []string{"first", "second", "third"} {
		if _, err := st.Add(a("hello", text), now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.List("hello")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d notes, want 3", len(got))
	}
	for i, want := range []string{"first", "second", "third"} {
		if got[i].Text != want {
			t.Errorf("note %d is %q, want %q; a conversation read out of order "+
				"is one nobody can follow", i, got[i].Text, want)
		}
	}
	// A page with none is empty rather than an error: nobody has said anything
	// about it yet, which is the ordinary case.
	if other, oerr := st.List("nothing-said"); oerr != nil || len(other) != 0 {
		t.Errorf("a page with no notes returned %v, %v", other, oerr)
	}
}

// Notes come back in the order they were written, every time.
//
// At is Unix seconds, like every other timestamp here, so two notes written in
// one sitting land in the same second. Sorting on At and breaking ties on a
// random id put the second remark before the first about two-thirds of the
// time — which is what driving this by hand showed, and which reads as the
// tool losing track of a conversation.
//
// The id is the nanosecond clock followed by randomness, so it sorts by
// creation and is the same order on every read.
func TestNotesComeBackInTheOrderTheyWereWritten(t *testing.T) {
	st := store(t)
	base := time.Unix(1_700_000_000, 0)

	var want []string
	for i, text := range []string{"one", "two", "three", "four", "five"} {
		// All within the same second, which is the case that was wrong.
		at := base.Add(time.Duration(i) * 20 * time.Millisecond)
		n, err := st.Add(a("hello", text), at)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, n.ID)
	}

	for run := 0; run < 10; run++ {
		got, err := st.List("hello")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("run %d returned %d notes, want %d", run, len(got), len(want))
		}
		for i := range want {
			if got[i].ID != want[i] {
				t.Fatalf("run %d: note %d is %q (%q), want the one written %s",
					run, i, got[i].Text, got[i].ID[:8], []string{
						"first", "second", "third", "fourth", "fifth"}[i])
			}
		}
	}

	// And they all landed in the same second, so this was not passing by
	// accident on a coarse timestamp.
	got, _ := st.List("hello")
	if got[0].At != got[len(got)-1].At {
		t.Fatalf("the test did not exercise the same-second case: %d vs %d",
			got[0].At, got[len(got)-1].At)
	}
}

// A note says what it was written against, so it can say when that changed.
//
// collab.Approval carries a hash for the same reason and says why: it "is what
// makes the approval unfalsifiable by later editing". A note that silently
// starts describing different words is worse than no note.
func TestANoteKnowsWhenThePageMovedUnderIt(t *testing.T) {
	n := a("hello", "this heading is wrong")

	if n.Stale("hash-one") {
		t.Error("a note is stale against the content it was written for")
	}
	if !n.Stale("hash-two") {
		t.Error("a note is not stale against content it was not written for")
	}
	// Neither hash known is not a claim that it drifted. A store that predates
	// this would otherwise show a warning on every note in it.
	if n.Stale("") {
		t.Error("an unknown current hash was reported as drift")
	}
	if (Note{Content: ""}).Stale("hash-two") {
		t.Error("a note with no anchor was reported as drift")
	}
}

// Resolved, not deleted — and the record says who.
func TestResolvingANoteKeepsItAndNamesWhoDidIt(t *testing.T) {
	st := store(t)
	now := time.Unix(1_700_000_000, 0)
	n, err := st.Add(a("hello", "fix this"), now)
	if err != nil {
		t.Fatal(err)
	}

	if err := st.Resolve("hello", n.ID, "grace", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("hello", n.ID)
	if err != nil {
		t.Fatalf("the note is gone after being resolved: %v", err)
	}
	if !got.Resolved || got.ResolvedBy != "grace" {
		t.Errorf("resolving did not record who: %+v", got)
	}
	if got.Text != "fix this" {
		t.Error("resolving changed what the note said")
	}
	// And it is still in the list, because the conversation has to stay
	// readable.
	if all, _ := st.List("hello"); len(all) != 1 {
		t.Errorf("a resolved note left the list; an editor asking why a heading " +
			"changed should find the answer, not an empty list")
	}
	if n := Unresolved([]Note{got}); n != 0 {
		t.Errorf("Unresolved counted a resolved note")
	}

	// Resolving without a name is refused: somebody has to be askable.
	if err := st.Resolve("hello", n.ID, "  ", now); err == nil {
		t.Error("a note was resolved by nobody")
	}
}

// A note with nothing in it, or nobody behind it, is refused.
func TestANoteNeedsSomethingToSayAndSomebodyToSayIt(t *testing.T) {
	st := store(t)
	now := time.Now()
	for _, c := range []struct {
		why  string
		note Note
	}{
		{"no page", Note{Author: "ada", Text: "x"}},
		{"no text", Note{Page: "hello", Author: "ada"}},
		{"blank text", Note{Page: "hello", Author: "ada", Text: "   "}},
		{"no author", Note{Page: "hello", Text: "x"}},
		{"text too long", Note{Page: "hello", Author: "ada",
			Text: strings.Repeat("x", MaxText+1)}},
		{"author too long", Note{Page: "hello", Text: "x",
			Author: strings.Repeat("a", MaxAuthor+1)}},
		{"field too long", Note{Page: "hello", Author: "ada", Text: "x",
			Field: strings.Repeat("f", MaxField+1)}},
	} {
		if _, err := st.Add(c.note, now); err == nil {
			t.Errorf("%s was accepted", c.why)
		}
	}
}

// A page name and a note id become path segments, so neither may leave the
// directory.
//
// Both arrive from outside: a page name from content, an id from a URL. The
// check is here because the place a path is built is the only place that can
// be sure it was checked.
func TestNothingCanWriteOutsideTheNotesDirectory(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "notes"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	for _, page := range []string{
		"../escaped", "../../escaped", "a/../../escaped", "/etc/passwd",
		`..\escaped`, "a/./../../x", "..", ".",
	} {
		if _, err := st.Add(Note{Page: page, Author: "ada", Text: "x"}, now); err == nil {
			t.Errorf("a note was written for page %q", page)
		}
		if _, err := st.List(page); err == nil {
			t.Errorf("notes were listed for page %q", page)
		}
	}
	for _, id := range []string{"../escaped", "..", "a/../../x"} {
		if err := st.Remove("hello", id); err == nil {
			t.Errorf("a file was removed for id %q", id)
		}
	}

	// Nothing was created beside the notes directory.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "notes" {
			t.Errorf("%q appeared next to the notes directory", e.Name())
		}
	}
}

// A page name with a slash in it is ordinary and still works.
func TestANestedPageNameWorks(t *testing.T) {
	st := store(t)
	now := time.Now()
	if _, err := st.Add(a("people/ada", "check the dates"), now); err != nil {
		t.Fatalf("a nested page name was refused: %v", err)
	}
	got, err := st.List("people/ada")
	if err != nil || len(got) != 1 {
		t.Fatalf("a nested page's notes did not come back: %v %v", got, err)
	}
	if pages, perr := st.Pages(); perr != nil || len(pages) != 1 ||
		pages[0] != "people/ada" {
		t.Errorf("Pages reported %v, %v", pages, perr)
	}
}

// Removing something that is not there says so, rather than succeeding.
func TestRemovingANoteThatIsNotThereSaysSo(t *testing.T) {
	st := store(t)
	err := st.Remove("hello", "0123456789abcdef0123456789abcdef")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("removing a missing note returned %v, want ErrNotFound", err)
	}
	if _, err := st.Get("hello", "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("getting a missing note returned %v, want ErrNotFound", err)
	}
}

// Every page that has notes is listed once.
func TestPagesListsEachPageOnce(t *testing.T) {
	st := store(t)
	now := time.Now()
	for _, page := range []string{"a", "a", "b", "people/ada", "people/ada"} {
		if _, err := st.Add(a(page, "x"), now); err != nil {
			t.Fatal(err)
		}
	}
	pages, err := st.Pages()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "b", "people/ada"}
	if len(pages) != len(want) {
		t.Fatalf("Pages returned %v, want %v", pages, want)
	}
	for i := range want {
		if pages[i] != want[i] {
			t.Errorf("Pages returned %v, want %v", pages, want)
			break
		}
	}
}
