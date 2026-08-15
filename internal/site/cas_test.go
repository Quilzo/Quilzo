package site

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

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

// Every id this tool prints is shortened to twelve characters, so a base given
// as a short id has to work. The first version compared strings exactly, which
// made --based-on fail as a permanent conflict against the only value a user
// has ever seen — and a control that always refuses looks broken rather than
// strict.
func TestAShortenedCommitIDIsAcceptedAsABase(t *testing.T) {
	s := newStore(t)
	full, err := SaveDraft(s, map[string]any{"index": page("Home")}, "first", "dana")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDraftFrom(s, map[string]any{"index": page("Edited")},
		"second", "dana", full[:12]); err != nil {
		t.Fatalf("a twelve-character base was refused: %v", err)
	}
}

// A prefix short enough to collide must not match. A base that matches the
// wrong commit is worse than one that matches none.
func TestATooShortPrefixIsNotAMatch(t *testing.T) {
	if sameCommit("abc", "abcdef0123456789") {
		t.Error("a three-character prefix matched")
	}
	if !sameCommit("abcdef01", "abcdef0123456789") {
		t.Error("an eight-character prefix did not match")
	}
	if sameCommit("abcdef01", "abcdef99999999") {
		t.Error("a non-matching prefix matched")
	}
	if !sameCommit("abc", "abc") {
		t.Error("identical short values did not match")
	}
}

// The overlap report has to be right, because it is the one that tells somebody
// whether they can retry safely. The first version diffed against the short
// prefix the user typed, which cannot be loaded as an object — so the diff
// failed silently and every collision was reported as "nothing you changed was
// touched". That is the opposite of the truth and the most dangerous thing this
// message could say.
func TestOverlapIsReportedCorrectlyWhenTheBaseIsShortened(t *testing.T) {
	s := newStore(t)
	base, _ := SaveDraft(s, map[string]any{
		"index": page("Home"), "about": page("About")}, "first", "dana")

	if _, err := SaveDraftFrom(s, map[string]any{
		"index": page("Home, by Dana"), "about": page("About")},
		"dana edits index", "dana", base[:12]); err != nil {
		t.Fatal(err)
	}

	// Sam edits the same page from the same shortened base.
	_, err := SaveDraftFrom(s, map[string]any{
		"index": page("Home, by Sam"), "about": page("About")},
		"sam edits index", "sam", base[:12])

	var c *Conflict
	if !errors.As(err, &c) {
		t.Fatalf("expected a conflict, got %v", err)
	}
	if both := c.Touches([]string{"index"}); len(both) != 1 {
		t.Errorf("editing the same page was reported as not colliding: "+
			"conflict pages %v", c.Pages)
	}
	if len(c.Pages) == 0 {
		t.Error("the conflict reports no changed pages at all, which means the " +
			"diff failed and the message will claim a retry is safe")
	}
}

// -- writes are serialised, across processes ---------------------------------

// The bug this exists to prevent, stated as a property.
//
// SaveDraftFrom read the current ref, compared it against the caller's base,
// built a commit and wrote the ref — four steps with nothing held between
// them. Sixteen concurrent writes carrying the same base all passed the
// comparison and all committed, and fifteen edits were silently lost. Every
// mechanism layered on top of this one — --based-on, the API's If-Match, the
// four-eyes review — inherited the hole, because all three are the same check
// wearing different clothes.
//
// The tests above this one pass without the lock. They write in sequence,
// which is the case that was never broken.
func TestExactlyOneConcurrentWriteAgainstOneBaseSucceeds(t *testing.T) {
	s := newStore(t)
	base, err := SaveDraft(s, map[string]any{"a": page("A")}, "first", "test")
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var won, lost int
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := SaveDraftFrom(s, map[string]any{
				"a": page(fmt.Sprintf("edit %d", i)),
			}, "concurrent", "test", base)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				won++
			} else {
				lost++
			}
		}(i)
	}
	wg.Wait()

	if won != 1 {
		t.Errorf("%d of 16 writes against the same base succeeded; exactly one "+
			"should, or --based-on is advice rather than a check", won)
	}
	if lost != 15 {
		t.Errorf("%d writes were refused, want 15", lost)
	}
}

// And the lock has to hold across processes rather than merely across
// goroutines, because the CLI, the admin interface and the content API are
// three processes against one store and that is a normal way to run this.
//
// A mutex passes the test above and fails in deployment, which is the worse of
// the two outcomes: it looks tested.
func TestTheRefLockHoldsAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDraft(s, map[string]any{"a": page("A")}, "first", "t"); err != nil {
		t.Fatal(err)
	}
	// A second Store over the same directory is what a second process holds.
	other, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	entered, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() {
		held <- s.WithRefLock(func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	blocked := make(chan struct{})
	go func() {
		other.WithRefLock(func() error { return nil })
		close(blocked)
	}()

	select {
	case <-blocked:
		t.Fatal("a second store took the ref lock while the first held it, so " +
			"the lock does not cross a process boundary")
	case <-time.After(150 * time.Millisecond):
	}

	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("the second store never acquired the lock after release")
	}
}

// A compare-and-swap that loses says what it found, because "failed" leaves
// the caller unable to tell somebody else's write from a broken store, and
// those need different responses.
func TestACompareAndSwapThatLosesSaysWhatItFound(t *testing.T) {
	s := newStore(t)
	first, err := SaveDraft(s, map[string]any{"a": page("A")}, "first", "t")
	if err != nil {
		t.Fatal(err)
	}
	second, err := SaveDraft(s, map[string]any{"a": page("B")}, "second", "t")
	if err != nil {
		t.Fatal(err)
	}
	err = s.CompareAndSwapRef(RefLive, first, second)
	if err == nil {
		t.Fatal("a swap against the wrong expected value succeeded")
	}
	var moved *store.RefMoved
	if !errors.As(err, &moved) {
		t.Fatalf("lost with %T, want a *store.RefMoved: %v", err, err)
	}
	if !strings.Contains(err.Error(), "nothing") {
		t.Errorf("the message does not say what was found: %v", err)
	}
	// And the correct swap must still work.
	if err := s.CompareAndSwapRef(RefLive, "", second); err != nil {
		t.Errorf("a correct swap was refused: %v", err)
	}
	if got := s.GetRef(RefLive); got != second {
		t.Errorf("live is %s, want %s", got, second)
	}
}
