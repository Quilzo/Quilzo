package site

import (
	"errors"
	"strings"
	"testing"

	"github.com/rsh1k/scrivet/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func page(title string) map[string]any { return map[string]any{"title": title} }

// The scenario the whole thing exists for: two people load the same draft, both
// save, and the second must not silently erase the first.
func TestTheSecondWriterDoesNotSilentlyOverwriteTheFirst(t *testing.T) {
	s := newStore(t)
	base, err := SaveDraft(s, map[string]any{
		"index": page("Home"), "about": page("About")}, "first", "dana")
	if err != nil {
		t.Fatal(err)
	}

	// Dana and Sam both read `base`. Dana saves.
	if _, err := SaveDraftFrom(s, map[string]any{
		"index": page("Home, edited by Dana"), "about": page("About")},
		"dana's edit", "dana", base); err != nil {
		t.Fatal(err)
	}

	// Sam saves against the same base. This must be refused.
	_, err = SaveDraftFrom(s, map[string]any{
		"index": page("Home, edited by Sam"), "about": page("About")},
		"sam's edit", "sam", base)
	if err == nil {
		t.Fatal("the second write overwrote the first without a word")
	}

	var c *Conflict
	if !errors.As(err, &c) {
		t.Fatalf("refused, but not as a conflict: %T %v", err, err)
	}
	if c.By != "dana" {
		t.Errorf("the conflict does not name who moved it: %q", c.By)
	}
	if c.Touches([]string{"index"}) == nil {
		t.Error("the conflict does not report that index actually collided")
	}
	// And Dana's work is still there.
	pages, err := PagesAt(s, RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if pages["index"].(map[string]any)["title"] != "Home, edited by Dana" {
		t.Error("the refused write landed anyway")
	}
}

// Two people editing different pages is the common case, and reporting it as a
// dangerous collision is what teaches people to retry blindly — which is how
// the real ones get retried blindly too.
func TestAConflictOnUnrelatedPagesSaysSo(t *testing.T) {
	s := newStore(t)
	base, _ := SaveDraft(s, map[string]any{
		"index": page("Home"), "about": page("About")}, "first", "dana")

	if _, err := SaveDraftFrom(s, map[string]any{
		"index": page("Home"), "about": page("About, edited")},
		"dana edits about", "dana", base); err != nil {
		t.Fatal(err)
	}

	_, err := SaveDraftFrom(s, map[string]any{
		"index": page("Home, edited"), "about": page("About")},
		"sam edits index", "sam", base)

	var c *Conflict
	if !errors.As(err, &c) {
		t.Fatalf("expected a conflict, got %v", err)
	}
	if both := c.Touches([]string{"index"}); len(both) != 0 {
		t.Errorf("editing index was reported as colliding with an edit to "+
			"about: %v", both)
	}
	if both := c.Touches([]string{"about"}); len(both) != 1 {
		t.Errorf("a real collision on about was not identified: %v", both)
	}
}

// A stale base has to be refused even when the content is identical, because
// the writer's belief about what they were changing was wrong either way.
func TestAStaleBaseIsRefusedEvenWhenNothingWouldChange(t *testing.T) {
	s := newStore(t)
	base, _ := SaveDraft(s, map[string]any{"index": page("Home")}, "first", "dana")
	if _, err := SaveDraftFrom(s, map[string]any{"index": page("Changed")},
		"second", "dana", base); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDraftFrom(s, map[string]any{"index": page("Changed")},
		"third", "sam", base); err == nil {
		t.Error("a write from a stale base was accepted because the result " +
			"happened to match")
	}
}

// The single-writer case must not be made worse to serve the concurrent one.
func TestAnEmptyBaseMeansWhateverIsCurrent(t *testing.T) {
	s := newStore(t)
	if _, err := SaveDraft(s, map[string]any{"index": page("Home")},
		"first", "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDraft(s, map[string]any{"index": page("Second")},
		"second", "dana"); err != nil {
		t.Fatalf("an unchecked write was refused: %v", err)
	}
	if _, err := SaveDraftFrom(s, map[string]any{"index": page("Third")},
		"third", "dana", ""); err != nil {
		t.Fatalf("an explicit empty base was refused: %v", err)
	}
}

// The message is what somebody reads at the moment they lose work, so it has to
// say who to talk to rather than only that something happened.
func TestTheConflictMessageIsActionable(t *testing.T) {
	s := newStore(t)
	base, _ := SaveDraft(s, map[string]any{"index": page("Home")}, "first", "dana")
	_, _ = SaveDraftFrom(s, map[string]any{"index": page("Edited")},
		"dana's edit", "dana", base)
	_, err := SaveDraftFrom(s, map[string]any{"index": page("Mine")},
		"sam's edit", "sam", base)

	msg := err.Error()
	for _, want := range []string{"dana", "index", "moved"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message omits %q: %s", want, msg)
		}
	}
}
