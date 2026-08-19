package collection

import (
	"fmt"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/store"
)

// The index has to answer exactly what the scan answers.
//
// A faster wrong answer is worse than a slow right one, and this is the only
// test that would notice. Everything else in this file checks that reuse does
// not serve something stale, which is the specific way a cache goes wrong.
func TestTheIndexAgreesWithTheScan(t *testing.T) {
	s, tree := seed(t, 300)

	for _, q := range []Query{
		{},
		{Equals: map[string]any{"status": "unmet"}},
		{Equals: map[string]any{"owner": "person3"}},
		{Contains: map[string]string{"title": "number 1"}},
		{Sort: "owner", Descending: true, Limit: 25},
		{Limit: 5, Offset: 290},
		{Equals: map[string]any{"status": "nothing matches this"}},
	} {
		scanned, scannedTotal, err := List(s, tree, "controls", q)
		if err != nil {
			t.Fatal(err)
		}
		idx, err := Build(s, tree, "controls", nil)
		if err != nil {
			t.Fatal(err)
		}
		indexed, indexedTotal := idx.Query(q)

		if scannedTotal != indexedTotal {
			t.Errorf("%+v: scan says %d match, index says %d",
				q, scannedTotal, indexedTotal)
		}
		if len(scanned) != len(indexed) {
			t.Fatalf("%+v: scan returned %d rows, index %d",
				q, len(scanned), len(indexed))
		}
		for i := range scanned {
			if scanned[i].ID != indexed[i].ID {
				t.Errorf("%+v: row %d differs: %s vs %s",
					q, i, scanned[i].ID, indexed[i].ID)
			}
		}
	}
}

// Reuse must not survive a change.
//
// The whole optimisation rests on "an unchanged subtree identifier means
// unchanged contents". If that reasoning is wrong anywhere, this is where it
// shows: the edited record would come back with its old fields.
func TestAnEditIsVisibleThroughAReusedIndex(t *testing.T) {
	s, tree := seed(t, 500)

	warm, err := Build(s, tree, "controls", nil)
	if err != nil {
		t.Fatal(err)
	}
	target := warm.Records[10]

	next, updated, err := Put(s, tree, "controls", Record{
		ID: target.ID, Fields: map[string]any{"status": "changed", "owner": "nobody"},
	}, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Built with the previous index as the source of reuse — the case that
	// would go wrong.
	after, err := Build(s, next, "controls", warm)
	if err != nil {
		t.Fatal(err)
	}
	if after.Len() != warm.Len() {
		t.Errorf("editing a record changed the count from %d to %d",
			warm.Len(), after.Len())
	}

	found := false
	for _, r := range after.Records {
		if r.ID != updated.ID {
			continue
		}
		found = true
		if r.Fields["status"] != "changed" {
			t.Errorf("the index served the old value %q after an edit; reuse "+
				"is returning stale content", r.Fields["status"])
		}
	}
	if !found {
		t.Error("the edited record vanished from the index")
	}

	// And the old index still describes the old tree, because an index is
	// identified by the tree it was built from.
	for _, r := range warm.Records {
		if r.ID == target.ID && r.Fields["status"] == "changed" {
			t.Error("building a new index mutated the old one")
		}
	}
}

// A deleted record leaves.
func TestADeleteIsVisibleThroughAReusedIndex(t *testing.T) {
	s, tree := seed(t, 200)
	warm, err := Build(s, tree, "controls", nil)
	if err != nil {
		t.Fatal(err)
	}
	gone := warm.Records[7].ID

	next, err := Delete(s, tree, "controls", gone)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Build(s, next, "controls", warm)
	if err != nil {
		t.Fatal(err)
	}
	if after.Len() != warm.Len()-1 {
		t.Errorf("after a delete the index holds %d, expected %d",
			after.Len(), warm.Len()-1)
	}
	for _, r := range after.Records {
		if r.ID == gone {
			t.Fatal("a deleted record is still in the index")
		}
	}
}

// A new record appears.
func TestAnInsertIsVisibleThroughAReusedIndex(t *testing.T) {
	s, tree := seed(t, 50)
	warm, _ := Build(s, tree, "controls", nil)

	next, added, err := Put(s, tree, "controls",
		Record{Fields: map[string]any{"status": "brand-new"}}, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Build(s, next, "controls", warm)
	if err != nil {
		t.Fatal(err)
	}
	got, total := after.Query(Query{Equals: map[string]any{"status": "brand-new"}})
	if total != 1 || len(got) != 1 || got[0].ID != added.ID {
		t.Errorf("a record inserted after the index was built is not in it")
	}
}

// The cache is keyed by tree, so two states give two answers.
func TestTheCacheDoesNotConfuseTwoTrees(t *testing.T) {
	s, first := seed(t, 20)
	c := NewCache()

	a, err := c.For(s, first, "controls")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := Put(s, first, "controls",
		Record{Fields: map[string]any{"status": "extra"}}, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.For(s, second, "controls")
	if err != nil {
		t.Fatal(err)
	}

	if a.Len() != 20 {
		t.Errorf("the first tree holds %d, expected 20", a.Len())
	}
	if b.Len() != 21 {
		t.Errorf("the second tree holds %d, expected 21", b.Len())
	}
	// And asking for the first again still gets the first.
	again, err := c.For(s, first, "controls")
	if err != nil {
		t.Fatal(err)
	}
	if again.Len() != 20 {
		t.Errorf("re-asking for the first tree returned %d records; the cache "+
			"is keyed on something other than the tree", again.Len())
	}
}

// The cache is bounded, or a long-lived process holds every state it ever saw.
func TestTheCacheIsBounded(t *testing.T) {
	s, tree := seed(t, 5)
	c := NewCache()
	for i := 0; i < MaxCached+3; i++ {
		next, _, err := Put(s, tree, "controls",
			Record{Fields: map[string]any{"n": i}}, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		tree = next
		if _, err := c.For(s, tree, "controls"); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	held := len(c.byKey)
	c.mu.Unlock()
	if held > MaxCached {
		t.Errorf("the cache holds %d indexes; the bound is %d", held, MaxCached)
	}
}

// Ordering is stable, or a page's content appears to change on refresh.
func TestTheIndexOrderIsDeterministic(t *testing.T) {
	s, tree := seed(t, 100)
	first, err := Build(s, tree, "controls", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		again, err := Build(s, tree, "controls", nil)
		if err != nil {
			t.Fatal(err)
		}
		for j := range first.Records {
			if first.Records[j].ID != again.Records[j].ID {
				t.Fatalf("build %d ordered the records differently at row %d",
					i, j)
			}
		}
	}
}

// An empty or absent collection is empty, not an error.
func TestAnAbsentCollectionIsEmpty(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tree := range []string{"", mustEmptyTree(t, s)} {
		idx, err := Build(s, tree, "nothing_here", nil)
		if err != nil {
			t.Fatalf("tree %q: %v", tree, err)
		}
		if idx.Len() != 0 {
			t.Errorf("tree %q: an absent collection has %d records",
				tree, idx.Len())
		}
	}
}

func mustEmptyTree(t *testing.T, s *store.Store) string {
	t.Helper()
	oid, err := s.PutTree(map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

// Concurrent readers get correct answers.
//
// The cache is read by every request the admin and the public site serve, so
// this runs under -race in CI.
func TestTheCacheIsSafeUnderConcurrentUse(t *testing.T) {
	s, tree := seed(t, 100)
	c := NewCache()
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			for j := 0; j < 20; j++ {
				idx, err := c.For(s, tree, "controls")
				if err != nil {
					done <- err
					return
				}
				if idx.Len() != 100 {
					done <- fmt.Errorf("got %d records", idx.Len())
					return
				}
			}
			done <- nil
		}()
	}
	for i := 0; i < 16; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// A listing sorted by a field with repeated values must not shuffle.
//
// This is the bug the index found. Records arrived from a map walk, whose
// order Go randomises, and sort.SliceStable keeps the input order for ties —
// so a page listing three hundred records by an owner field with twenty
// distinct values showed a different arrangement on every refresh, with no
// change to the content.
//
// Checked through the scan rather than the index, because the scan is where
// the randomised input comes from and therefore where the bug lived.
func TestASortedListingDoesNotShuffleBetweenCalls(t *testing.T) {
	s, tree := seed(t, 300)
	q := Query{Sort: "owner", Limit: 50}

	first, _, err := List(s, tree, "controls", q)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 15; attempt++ {
		again, _, err := List(s, tree, "controls", q)
		if err != nil {
			t.Fatal(err)
		}
		for i := range first {
			if first[i].ID != again[i].ID {
				t.Fatalf("call %d returned a different row at position %d "+
					"(%s then %s) for the same query over unchanged content",
					attempt, i, first[i].ID, again[i].ID)
			}
		}
	}
}

// Descending must be the exact reverse, and must not overlap across pages.
//
// The old comparator returned "a before b" and "b before a" for equal values,
// which is not an ordering at all — sort is permitted to produce anything when
// given one. The visible symptom would have been page two of a descending
// listing repeating rows from page one.
func TestDescendingIsATotalOrderAndPagesDoNotOverlap(t *testing.T) {
	s, tree := seed(t, 200)

	page := func(offset int) []string {
		got, _, err := List(s, tree, "controls",
			Query{Sort: "owner", Descending: true, Limit: 40, Offset: offset})
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(got))
		for _, r := range got {
			ids = append(ids, r.ID)
		}
		return ids
	}

	seen := map[string]int{}
	for offset := 0; offset < 200; offset += 40 {
		for _, id := range page(offset) {
			seen[id]++
			if seen[id] > 1 {
				t.Fatalf("%s appeared on two pages of one listing", id)
			}
		}
	}
	if len(seen) != 200 {
		t.Errorf("paging through 200 records returned %d of them", len(seen))
	}

	// And the values really are descending.
	got, _, err := List(s, tree, "controls",
		Query{Sort: "owner", Descending: true, Limit: MaxLimit})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(got); i++ {
		a, _ := got[i-1].Fields["owner"].(string)
		b, _ := got[i].Fields["owner"].(string)
		if a < b {
			t.Fatalf("row %d (%q) sorts before row %d (%q) in a descending "+
				"listing", i-1, a, i, b)
		}
	}
}
