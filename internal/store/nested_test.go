package store

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
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
// Measured in objects written rather than in time.
//
// It used to be a ratio of two durations, on the reasoning that a threshold in
// milliseconds fails on a slow machine and passes on a fast one. The reasoning
// was right and the instrument was still wrong: a ratio of two wall-clock
// numbers is noisier than either, because a shared runner can perturb one
// measurement and not the other. It failed in CI at 5.5x against a limit of 4x
// while passing locally, which is a test reporting on the scheduler.
//
// The property is algorithmic, so it is counted algorithmically. Editing one
// record rewrites the objects on its path — the blob, and one tree per path
// segment — and that number is fixed by the depth of the path, not by how many
// records sit beside it. Forty times the records must write the same handful of
// objects. That is deterministic, fails for exactly one reason, and says what
// it means.
func TestOneEditDoesNotCostMoreAsTheStoreGrows(t *testing.T) {
	if testing.Short() {
		t.Skip("seeding twenty thousand records takes a minute")
	}
	small := newStore(t)
	smallBase := seed(t, small, 500)

	big := newStore(t)
	bigBase := seed(t, big, 20000)

	// edit changes one record and reports how many new objects that wrote.
	//
	// New ones only: an identical object is already stored under its own hash
	// and writing it again is a no-op, which is the deduplication that makes
	// this cheap in the first place.
	edit := func(s *Store, base string, title string) int {
		before := countObjects(t, s)
		if _, err := s.PutNested(base, []Change{{
			Path:  "data/things/00/00/rec0",
			Value: map[string]any{"title": title},
		}}); err != nil {
			t.Fatal(err)
		}
		return countObjects(t, s) - before
	}

	// A distinct value per edit, so the second is not deduplicated against the
	// first and measured as free.
	a := edit(small, smallBase, "edited-small")
	b := edit(big, bigBase, "edited-big")
	t.Logf("objects written — 500 records: %d · 20000 records: %d", a, b)

	if a == 0 || b == 0 {
		t.Fatalf("an edit wrote no objects (%d and %d); the measurement is "+
			"wrong and a test that measures nothing passes", a, b)
	}
	// Forty times the records must write the same handful of objects. Equal is
	// the honest expectation; the slack is for a tree that happens to split
	// differently at the two sizes, not for anything proportional.
	if b > a+2 {
		t.Errorf("editing one record writes %d object(s) in a store of 500 "+
			"and %d in a store of 20000; the write is still proportional to "+
			"the store", a, b)
	}
}

// countObjects counts what is stored, without re-hashing it.
//
// Verify would also count and would re-hash twenty thousand records to do it,
// which is a minute of work to answer a question about arithmetic.
func countObjects(t *testing.T, s *Store) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(filepath.Join(s.Root(), "objects"),
		func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && !strings.HasPrefix(d.Name(), ".") {
				n++
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	return n
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
