package site

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

func mfields(kv ...string) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// start writes a two-page draft and returns the store and the commit id.
func start(t *testing.T) (*store.Store, string) {
	t.Helper()
	s := newStore(t)
	cid, err := SaveDraft(s, map[string]any{
		"index": mfields("title", "Home", "body", "Welcome."),
		"about": mfields("title", "About", "body", "Founded 2019."),
	}, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	return s, cid
}

func draft(t *testing.T, s *store.Store) map[string]any {
	t.Helper()
	p, err := PagesAt(s, RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The case that makes most refusals unnecessary: two people on different
// pages. Compare-and-swap refuses this correctly and uselessly — they collided
// on the ref and on nothing else.
func TestAMergingWriteKeepsBothPeoplesWork(t *testing.T) {
	s, base := start(t)

	// They save first.
	theirs := draft(t, s)
	theirs["about"] = mfields("title", "About us", "body", "Founded 2019.")
	if _, err := SaveDraftFrom(s, theirs, "theirs", "B", base); err != nil {
		t.Fatal(err)
	}

	// I save second, from the same base, having changed a different page.
	mine := map[string]any{
		"index": mfields("title", "Home", "body", "A much longer welcome."),
		"about": mfields("title", "About", "body", "Founded 2019."),
	}
	_, merged, err := MergeDraftFrom(s, mine, "mine", "A", base)
	if err != nil {
		t.Fatalf("refused a merge with no overlap: %v", err)
	}
	if !merged.Clean() {
		t.Fatalf("reported conflicts where there were none: %s", merged.Summary())
	}

	got := draft(t, s)
	if v := got["index"].(map[string]any)["body"]; v != "A much longer welcome." {
		t.Errorf("my change was lost: %v", v)
	}
	if v := got["about"].(map[string]any)["title"]; v != "About us" {
		t.Errorf("their change was lost: %v", v)
	}
}

// A genuine disagreement writes nothing at all. A merge that wrote a partial
// result would leave the draft in a state neither person chose, and the one
// who is told to decide would be deciding about content that had already
// changed under them.
func TestARefusedMergeWritesNothing(t *testing.T) {
	s, base := start(t)

	theirs := draft(t, s)
	theirs["index"] = mfields("title", "Home", "body", "They rewrote this.")
	if _, err := SaveDraftFrom(s, theirs, "theirs", "B", base); err != nil {
		t.Fatal(err)
	}
	after := s.GetRef(RefDraft)

	mine := map[string]any{
		"index": mfields("title", "Home", "body", "I rewrote this."),
		"about": mfields("title", "About", "body", "Founded 2019."),
	}
	_, merged, err := MergeDraftFrom(s, mine, "mine", "A", base)
	if err == nil {
		t.Fatal("merged two different rewrites of the same field")
	}
	if merged.Clean() {
		t.Error("the returned merge says it is clean but the write failed")
	}
	if now := s.GetRef(RefDraft); now != after {
		t.Errorf("the draft moved to %s despite the refusal; it was %s",
			shortish(now), shortish(after))
	}
	if v := draft(t, s)["index"].(map[string]any)["body"]; v != "They rewrote this." {
		t.Errorf("their work was disturbed by my refused merge: %v", v)
	}

	// The error has to name what to decide, not that something happened.
	if !strings.Contains(err.Error(), "index.body") {
		t.Errorf("the error does not say what needs deciding: %v", err)
	}
	if !strings.Contains(err.Error(), "nothing was written") {
		t.Errorf("the error does not say the draft is untouched: %v", err)
	}
}

// The merge reads the base and the current draft and then writes. All three
// have to happen under one lock: reading the current draft outside it and
// merging against what it used to be is the exact bug compare-and-swap exists
// to prevent, wearing a merge as a disguise.
//
// Sixteen writers, each changing a different page from the same base. Every
// one of them must land.
func TestConcurrentMergesAllLand(t *testing.T) {
	s, base := start(t)

	const writers = 16
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pages := map[string]any{
				"index": mfields("title", "Home", "body", "Welcome."),
				"about": mfields("title", "About", "body", "Founded 2019."),
			}
			name := fmt.Sprintf("page%02d", i)
			pages[name] = mfields("title", name, "body", "written by "+name)
			_, _, err := MergeDraftFrom(s, pages,
				"add "+name, name, base)
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d was refused: %v", i, err)
		}
	}

	got := draft(t, s)
	missing := 0
	for i := 0; i < writers; i++ {
		name := fmt.Sprintf("page%02d", i)
		if _, there := got[name]; !there {
			missing++
		}
	}
	// Count what is there, not only what is absent. A draft that came back
	// empty would produce one complaint per page and read like many small
	// failures rather than one total one.
	if missing > 0 {
		t.Fatalf("%d of %d concurrent writes were lost; the draft holds %d "+
			"pages", missing, writers, len(got))
	}
	// And the two original pages survived all of it.
	if len(got) != writers+2 {
		t.Errorf("the draft holds %d pages, want %d", len(got), writers+2)
	}
}

// Merging without a base is the ordinary write. The base check is the safety
// property and merging must not be a way around it.
func TestMergingWithNoBaseIsAnOrdinaryWrite(t *testing.T) {
	s, _ := start(t)
	pages := draft(t, s)
	pages["index"] = mfields("title", "Home", "body", "Changed.")
	cid, merged, err := MergeDraftFrom(s, pages, "no base", "A", "")
	if err != nil {
		t.Fatal(err)
	}
	if cid == "" {
		t.Fatal("no commit was written")
	}
	if !merged.Clean() {
		t.Errorf("reported conflicts for a write with nothing to merge: %s",
			merged.Summary())
	}
}

// A base that is not in the history at all is an error, not a merge against
// nothing. Treating an unreadable base as empty would silently turn a
// checked write into an unchecked one.
func TestAnUnknownBaseIsRefused(t *testing.T) {
	s, _ := start(t)
	pages := draft(t, s)
	pages["index"] = mfields("title", "Home", "body", "Changed.")
	if _, _, err := MergeDraftFrom(s, pages, "bad base", "A",
		strings.Repeat("f", 64)); err == nil {
		t.Fatal("merged against a commit that does not exist")
	}
}

func shortish(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
