// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// published builds a site whose live ref holds these pages.
func livePages(t *testing.T, pages map[string]any) (*Site, *store.Store) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cid, err := site.SaveDraft(s, pages, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRef(site.RefLive, cid); err != nil {
		t.Fatal(err)
	}
	return &Site{Store: s}, s
}

// republish writes a new commit and moves live to it.
func republish(t *testing.T, s *store.Store, pages map[string]any) {
	t.Helper()
	cid, err := site.SaveDraft(s, pages, "again", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRef(site.RefLive, cid); err != nil {
		t.Fatal(err)
	}
}

// The memo answers what an uncached walk answered.
func TestTheMemoAnswersTheSameThing(t *testing.T) {
	st, _ := livePages(t, map[string]any{
		"index": map[string]any{"title": "Home"},
		"about": map[string]any{"title": "About"},
	})

	first, firstIDs, err := st.pages()
	if err != nil {
		t.Fatal(err)
	}
	second, secondIDs, err := st.pages()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("%d then %d pages", len(first), len(second))
	}
	for name := range first {
		if firstIDs[name] != secondIDs[name] {
			t.Errorf("%s has id %q then %q", name, firstIDs[name], secondIDs[name])
		}
	}
}

// A publish is picked up, because the memo is keyed on the commit.
//
// This is the whole reason a cache here can never be wrong: the key is the
// content. A new commit is a new key, so there is nothing to invalidate.
func TestAPublishIsPickedUp(t *testing.T) {
	st, s := livePages(t, map[string]any{
		"index": map[string]any{"title": "Home"},
	})
	if pages, _, _ := st.pages(); len(pages) != 1 {
		t.Fatalf("%d page(s) before", len(pages))
	}

	republish(t, s, map[string]any{
		"index": map[string]any{"title": "Home"},
		"news":  map[string]any{"title": "News"},
	})

	pages, _, err := st.pages()
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 2 {
		t.Errorf("%d page(s) after a publish, want 2; the memo did not notice "+
			"the ref move", len(pages))
	}
	if _, ok := pages["news"]; !ok {
		t.Error("the new page is missing")
	}
}

// The publish window is still asked on every request.
//
// This is the property the design exists to preserve, and the obvious way to
// write this cache breaks it. A page embargoed until noon is in the tree all
// morning; a set filtered once and reused would keep it hidden all afternoon,
// or — worse, with the clock the other way — reveal it early. So the decode is
// memoised and the date comparison is not.
func TestTheWindowIsAskedEveryTime(t *testing.T) {
	// An hour out, so nothing about how busy the machine is can decide this.
	// The clock is moved by asking the memo about a different time rather
	// than by waiting for one — an earlier version of this test slept 80ms
	// and failed in the full suite, where building the store took longer
	// than that and the embargo had already lifted before the first look.
	opens := time.Now().Add(time.Hour).UTC()
	st, _ := livePages(t, map[string]any{
		"index": map[string]any{"title": "Home"},
		"announce": map[string]any{"title": "Announcement",
			site.Starts: opens.Format(time.RFC3339Nano)},
	})

	set, err := st.decoded(st.Store.GetRef(st.ref()))
	if err != nil {
		t.Fatal(err)
	}
	// The page is in the memo either way: what is cached is the decode, not
	// the answer to a question about the time.
	if _, ok := set.bodies["announce"]; !ok {
		t.Fatal("the embargoed page is not in the decoded set, so the memo " +
			"has filtered it and the filter is what must not be cached")
	}

	before, beforeIDs := set.visibleAt(opens.Add(-time.Minute))
	if _, ok := before["announce"]; ok {
		t.Error("an embargoed page was published early")
	}
	if _, ok := beforeIDs["announce"]; ok {
		t.Error("an embargoed page is in the visible id set")
	}

	// The same memo, a later clock, nothing republished.
	after, afterIDs := set.visibleAt(opens.Add(time.Minute))
	if _, ok := after["announce"]; !ok {
		t.Error("the embargo lifted and the page stayed hidden: the memo " +
			"cached the answer to a question about the time")
	}
	if _, ok := afterIDs["announce"]; !ok {
		t.Error("the page is visible and has no id, so nothing can link to it")
	}
}

// And the same property through pages(), which is what the handlers call.
//
// A short wait here rather than an hour, and it is allowed to be short
// because the assertion is one-sided: the page must become visible. If the
// machine is slow the embargo has lifted by the first look too, and the test
// still asserts the thing it exists to assert.
func TestThePublishWindowOpensWithoutARepublish(t *testing.T) {
	soon := time.Now().Add(150 * time.Millisecond).UTC()
	st, _ := livePages(t, map[string]any{
		"index": map[string]any{"title": "Home"},
		"announce": map[string]any{"title": "Announcement",
			site.Starts: soon.Format(time.RFC3339Nano)},
	})

	// Builds the memo, whichever side of the window this lands on.
	if _, _, err := st.pages(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(soon.Add(150 * time.Millisecond)))

	pages, ids, err := st.pages()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pages["announce"]; !ok {
		t.Error("the embargo lifted and the page stayed hidden: the memo " +
			"cached the answer to a question about the time")
	}
	if _, ok := ids["announce"]; !ok {
		t.Error("the page is visible and has no id, so nothing can link to it")
	}
}

// A page whose window cannot be parsed stays hidden, from the memo too.
//
// Failing closed is the whole argument: the alternative is a typo silently
// lifting an embargo.
func TestAMalformedWindowStillHides(t *testing.T) {
	st, _ := livePages(t, map[string]any{
		"index": map[string]any{"title": "Home"},
		"oops":  map[string]any{"title": "Oops", site.Starts: "next tuesday"},
	})
	for i := 0; i < 2; i++ {
		pages, _, err := st.pages()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := pages["oops"]; ok {
			t.Fatalf("a page with an unreadable date was published (pass %d)", i)
		}
	}
}

// Each call gets its own maps, so a caller cannot disturb the next one.
//
// The bodies inside are shared and immutable — that is what content
// addressing means — but the maps are not, because a caller that wrote into a
// shared one would be editing every later request's idea of the site.
func TestEachCallGetsItsOwnMaps(t *testing.T) {
	st, _ := livePages(t, map[string]any{
		"index": map[string]any{"title": "Home"},
	})
	first, firstIDs, _ := st.pages()
	first["injected"] = map[string]any{"title": "Not real"}
	firstIDs["injected"] = "0000"

	second, secondIDs, _ := st.pages()
	if _, ok := second["injected"]; ok {
		t.Error("a page written into one caller's map appeared in the next's")
	}
	if _, ok := secondIDs["injected"]; ok {
		t.Error("an id written into one caller's map appeared in the next's")
	}
}

// Concurrent readers are safe, and the herd decodes once.
//
// Run under -race this is the test that matters; without it, it at least
// asserts that forty simultaneous first requests all get an answer.
func TestConcurrentReadersAreSafe(t *testing.T) {
	st, _ := livePages(t, map[string]any{
		"index": map[string]any{"title": "Home"},
		"about": map[string]any{"title": "About"},
		"news":  map[string]any{"title": "News"},
	})

	var wg sync.WaitGroup
	bad := make(chan string, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pages, ids, err := st.pages()
			if err != nil {
				bad <- err.Error()
				return
			}
			if len(pages) != 3 || len(ids) != 3 {
				bad <- "wrong page count"
			}
		}()
	}
	wg.Wait()
	close(bad)
	for msg := range bad {
		t.Error(msg)
	}
}

// Nothing published is an error, not an empty site.
func TestNothingPublishedIsStillAnError(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := &Site{Store: s}
	if _, _, err := st.pages(); err == nil {
		t.Error("an unpublished store answered with a page set")
	}
}
