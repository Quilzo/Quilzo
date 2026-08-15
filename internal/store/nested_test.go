package store

import (
	"fmt"
	"testing"
	"time"
)

func seed(t *testing.T, s *Store, n int) string {
	t.Helper()
	var changes []Change
	for i := 0; i < n; i++ {
		changes = append(changes, Change{
			Path: fmt.Sprintf("data/things/%02x/%02x/rec%d",
				i%256, (i/256)%256, i),
			Value: map[string]any{"title": fmt.Sprintf("Record %d", i)},
		})
	}
	oid, err := s.PutNested("", changes)
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

// -- the property the whole change exists for --------------------------------

// One edit must cost what the edit costs, not what the store holds.
//
// The whole-tree builder was O(n): 221ms to change one record among twenty
// thousand, because it re-serialised and re-hashed every one of them and wrote
// a single flat tree listing all of them. Five writes a second is not an
// application, and that number is why this exists.
//
// Measured as a ratio rather than against a clock, because a threshold in
// milliseconds is a test that fails on a slow machine and passes on a fast one
// while measuring nothing about the code.
func TestOneEditDoesNotCostMoreAsTheStoreGrows(t *testing.T) {
	if testing.Short() {
		t.Skip("seeding twenty thousand records takes a minute")
	}
	small := newStore(t)
	smallBase := seed(t, small, 500)

	big := newStore(t)
	bigBase := seed(t, big, 20000)

	edit := func(s *Store, base string) time.Duration {
		start := time.Now()
		if _, err := s.PutNested(base, []Change{{
			Path:  "data/things/00/00/rec0",
			Value: map[string]any{"title": "edited"},
		}}); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}

	// Warmed, so the first-write cost of creating directories is not the
	// measurement.
	edit(small, smallBase)
	edit(big, bigBase)

	a, b := edit(small, smallBase), edit(big, bigBase)
	t.Logf("500 records: %s · 20000 records: %s", a.Round(time.Millisecond),
		b.Round(time.Millisecond))

	// Forty times the records must not be anything like forty times the cost.
	if b > a*4 {
		t.Errorf("editing one record costs %s in a store of 500 and %s in a "+
			"store of 20000; the write is still proportional to the store",
			a, b)
	}
}

// -- correctness -------------------------------------------------------------

func TestANestedTreeReadsBackWhatWasWritten(t *testing.T) {
	s := newStore(t)
	base := seed(t, s, 300)
	got, err := s.GetNested(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 300 {
		t.Fatalf("wrote 300 records and read back %d", len(got))
	}
	if _, ok := got["data/things/00/00/rec0"]; !ok {
		t.Error("a record is missing from the flattened tree")
	}
}

func TestAnEditReplacesOnlyItsOwnRecord(t *testing.T) {
	s := newStore(t)
	base := seed(t, s, 50)
	before, _ := s.GetNested(base)

	next, err := s.PutNested(base, []Change{{
		Path: "data/things/00/00/rec0", Value: map[string]any{"title": "new"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetNested(next)

	if len(after) != len(before) {
		t.Fatalf("the edit changed the record count: %d to %d",
			len(before), len(after))
	}
	changed := 0
	for path, oid := range after {
		if before[path] != oid {
			changed++
		}
	}
	if changed != 1 {
		t.Errorf("%d records changed identity for a one-record edit", changed)
	}
}

// Unchanged subtrees keep the object id they already had. That reuse is the
// whole mechanism: it is what makes the write proportional to the edit, and if
// it stopped happening the cost would come back silently.
func TestUnchangedSubtreesAreReused(t *testing.T) {
	s := newStore(t)
	base := seed(t, s, 600)
	root, err := s.GetTree(base)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.PutNested(base, []Change{{
		Path: "data/things/00/00/rec0", Value: map[string]any{"title": "new"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetTree(next)

	// The root's own entries: "data" must change, and nothing else may.
	for name, oid := range root {
		if name == "data" {
			if after[name] == oid {
				t.Error("the changed branch kept its id, so nothing was written")
			}
			continue
		}
		if after[name] != oid {
			t.Errorf("%q was rewritten by an edit that did not touch it", name)
		}
	}
}

func TestDeletingARecordRemovesIt(t *testing.T) {
	s := newStore(t)
	base := seed(t, s, 20)
	next, err := s.PutNested(base, []Change{{
		Path: "data/things/00/00/rec0", Delete: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNested(next)
	if _, still := got["data/things/00/00/rec0"]; still {
		t.Error("the record survived its own deletion")
	}
	if len(got) != 19 {
		t.Errorf("%d records remain, want 19", len(got))
	}
}

// Deleting the last record in a branch must not leave an empty subtree behind,
// or "does this collection exist" stops having an answer.
func TestAnEmptiedBranchIsRemoved(t *testing.T) {
	s := newStore(t)
	base, err := s.PutNested("", []Change{
		{Path: "data/only/aa/bb/rec1", Value: map[string]any{"x": 1}},
		{Path: "pages/index", Value: map[string]any{"title": "Home"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.PutNested(base, []Change{{
		Path: "data/only/aa/bb/rec1", Delete: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNested(next)
	if len(got) != 1 {
		t.Errorf("%d entries remain, want just the page: %v", len(got), got)
	}
	root, _ := s.GetTree(next)
	if _, ok := root["data"]; ok {
		t.Error("an empty data branch was left behind")
	}
}

// -- what a path may be ------------------------------------------------------

// A path is an address inside an immutable object, so a traversal is not a
// filesystem problem — it is a record written where another one is meant to
// be, and nothing on disk complains.
func TestATraversingPathIsRefused(t *testing.T) {
	s := newStore(t)
	for _, bad := range []string{
		"../escape", "data/../../etc/passwd", "data//empty", "/leading",
		"trailing/", "data/./here", "", "data/a\x00b", "data/a\nb",
	} {
		if _, err := s.PutNested("", []Change{{Path: bad,
			Value: map[string]any{"x": 1}}}); err == nil {
			t.Errorf("path %q was accepted", bad)
		}
	}
}

// A flat tree is a nested tree of depth one. Existing stores must keep
// working, unconverted.
func TestAFlatTreeStillReads(t *testing.T) {
	s := newStore(t)
	flat, err := BuildTree(s, map[string]any{
		"index": map[string]any{"title": "Home"},
		"about": map[string]any{"title": "About"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNested(flat)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["index"] == "" {
		t.Errorf("a flat tree did not read back: %v", got)
	}
	// And it can be edited nestedly without being converted first.
	next, err := s.PutNested(flat, []Change{{
		Path:  "data/users/aa/bb/" + "00000000000000000000000000000001",
		Value: map[string]any{"name": "dana"}}})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := s.GetNested(next)
	if len(after) != 3 {
		t.Errorf("%d entries after adding a record to a flat tree", len(after))
	}
}
