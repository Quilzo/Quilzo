package collection

import (
	"fmt"
	"testing"
	"time"

	"github.com/lithoform/lithoform/internal/store"
)

var when = time.Unix(1786000000, 0)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func put(t *testing.T, s *store.Store, tree, coll string, fields map[string]any) (string, Record) {
	t.Helper()
	next, r, err := Put(s, tree, coll, Record{Fields: fields}, when)
	if err != nil {
		t.Fatal(err)
	}
	return next, r
}

// -- the round trip -----------------------------------------------------------

func TestARecordSurvivesBeingWrittenAndRead(t *testing.T) {
	s := newStore(t)
	tree, r := put(t, s, "", "devices", map[string]any{
		"hostname": "laptop-14", "encrypted": true, "owner": "dana"})

	got, err := Get(s, tree, "devices", r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fields["hostname"] != "laptop-14" || got.Fields["encrypted"] != true {
		t.Errorf("read back %v", got.Fields)
	}
	if got.Created != when.Unix() || got.Updated != when.Unix() {
		t.Errorf("timestamps are %d/%d", got.Created, got.Updated)
	}
}

// An id is assigned by the store and never taken from the caller, because an
// identifier that lives in the data is one somebody can edit.
func TestAnIdIsMintedNotAccepted(t *testing.T) {
	s := newStore(t)
	_, a := put(t, s, "", "devices", map[string]any{"n": 1})
	_, b := put(t, s, "", "devices", map[string]any{"n": 2})
	if a.ID == b.ID {
		t.Fatal("two records got the same id")
	}
	if err := ValidID(a.ID); err != nil {
		t.Errorf("%q: %v", a.ID, err)
	}
	// A caller cannot smuggle one in through the fields.
	_, r, err := Put(s, "", "devices", Record{
		Fields: map[string]any{"id": "not-an-id"}}, when)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == "not-an-id" {
		t.Error("a field called id became the record's identity")
	}
}

// Created never moves, or "how long have we had this" stops having an answer.
func TestCreatedDoesNotMoveOnUpdate(t *testing.T) {
	s := newStore(t)
	tree, r := put(t, s, "", "devices", map[string]any{"n": 1})
	later := when.Add(48 * time.Hour)

	r.Fields["n"] = 2
	tree, updated, err := Put(s, tree, "devices", r, later)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Created != when.Unix() {
		t.Errorf("created moved from %d to %d", when.Unix(), updated.Created)
	}
	if updated.Updated != later.Unix() {
		t.Errorf("updated is %d, want %d", updated.Updated, later.Unix())
	}
	_ = tree
}

func TestDeletingSomethingThatIsNotThereIsRefused(t *testing.T) {
	s := newStore(t)
	tree, r := put(t, s, "", "devices", map[string]any{"n": 1})
	if _, err := Delete(s, tree, "devices", r.ID); err != nil {
		t.Fatalf("deleting a real record failed: %v", err)
	}
	// A second delete must not report success: "deleted" for something that
	// was never there hides a client working against the wrong collection.
	next, _ := Delete(s, tree, "devices", r.ID)
	if next2, err := Delete(s, next, "devices", r.ID); err == nil {
		t.Errorf("deleting twice succeeded, giving tree %s", next2)
	}
}

// -- the failure that would be worst -----------------------------------------

// The page writer builds its tree from the page set alone. Without carrying
// records across, every one of them disappears the next time somebody edits a
// page: no error, no conflict, no diff — the tree simply stops containing
// them.
func TestRecordsSurviveATreeRebuiltFromPages(t *testing.T) {
	s := newStore(t)
	tree, r := put(t, s, "", "devices", map[string]any{"hostname": "laptop-14"})

	// What a page write does: a flat tree from the pages alone.
	flat, err := store.BuildTree(s, map[string]any{
		"index": map[string]any{"title": "Home"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Get(s, flat, "devices", r.ID); err == nil {
		t.Fatal("the fixture is wrong: a flat rebuild kept the record, so " +
			"this test proves nothing")
	}

	// What it must do instead.
	carried, err := Preserve(s, tree)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := s.PutNested(flat, carried)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Get(s, kept, "devices", r.ID)
	if err != nil {
		t.Fatalf("the record did not survive the page write: %v", err)
	}
	if got.Fields["hostname"] != "laptop-14" {
		t.Errorf("it survived but changed: %v", got.Fields)
	}
	// And the page is there too.
	entries, _ := s.GetNested(kept)
	if _, ok := entries["index"]; !ok {
		t.Error("carrying the records lost the page")
	}
}

// -- listing and querying -----------------------------------------------------

func TestListingFiltersSortsAndPages(t *testing.T) {
	s := newStore(t)
	tree := ""
	for i := 0; i < 40; i++ {
		var next string
		next, _ = put(t, s, tree, "devices", map[string]any{
			"n": i, "encrypted": i%2 == 0,
			"owner": fmt.Sprintf("person%d", i%4),
		})
		tree = next
	}

	all, total, err := List(s, tree, "devices", Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != 40 || len(all) != 40 {
		t.Fatalf("listed %d of %d", len(all), total)
	}

	enc, total, _ := List(s, tree, "devices", Query{
		Equals: map[string]any{"encrypted": true}, Limit: 100})
	if total != 20 {
		t.Errorf("%d encrypted, want 20", total)
	}
	for _, r := range enc {
		if r.Fields["encrypted"] != true {
			t.Fatal("a filter let something through")
		}
	}

	// Sorted and paged, with the total still reporting the whole match.
	page, total, _ := List(s, tree, "devices", Query{
		Sort: "n", Limit: 5, Offset: 10})
	if total != 40 {
		t.Errorf("total is %d, want the full match of 40", total)
	}
	if len(page) != 5 {
		t.Fatalf("page has %d", len(page))
	}
	first, _ := toFloat(page[0].Fields["n"])
	if first != 10 {
		t.Errorf("offset 10 sorted by n starts at %v", page[0].Fields["n"])
	}
}

// An integer in a query must match an integer in a record. Both go through
// JSON, which makes everything a float64, and a query that silently returns
// nothing is the worst failure a store has because it looks like an answer.
func TestNumbersMatchAcrossAJSONRoundTrip(t *testing.T) {
	s := newStore(t)
	tree, _ := put(t, s, "", "devices", map[string]any{"port": 443})

	got, total, err := List(s, tree, "devices", Query{
		Equals: map[string]any{"port": 443}})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("an integer query matched %d records", total)
	}
}

func TestCollectionsAreDiscoveredFromTheTree(t *testing.T) {
	s := newStore(t)
	tree, _ := put(t, s, "", "devices", map[string]any{"n": 1})
	tree, _ = put(t, s, tree, "vendors", map[string]any{"n": 1})
	tree, _ = put(t, s, tree, "policies", map[string]any{"n": 1})

	names, err := Names(s, tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 || names[0] != "devices" {
		t.Errorf("found %v", names)
	}
	n, _ := Count(s, tree, "vendors")
	if n != 1 {
		t.Errorf("counted %d vendors", n)
	}
}

// -- names and ids ------------------------------------------------------------

func TestAReservedOrUnusableNameIsRefused(t *testing.T) {
	for _, bad := range []string{"pages", "", "Devices", "my devices",
		"../etc", "a/b", "9lives"} {
		if err := ValidName(bad); err == nil {
			t.Errorf("collection name %q was accepted", bad)
		}
	}
	if err := ValidName("devices"); err != nil {
		t.Errorf("a normal name was refused: %v", err)
	}
}

// An id becomes a path inside the tree, so one containing a separator would
// place a record where nothing can find it, and one containing a dot would be
// a traversal.
func TestAnUnusableIdIsRefused(t *testing.T) {
	s := newStore(t)
	// An empty id is not in this list: it means "mint one", which is the
	// intended way to create a record and is tested above.
	for _, bad := range []string{"short", "../../etc/passwd",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaZ", "aaaa/aaaa",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, _, err := Put(s, "", "devices", Record{ID: bad}, when); err == nil {
			t.Errorf("id %q was accepted", bad)
		}
	}
}

// A record's path must agree with its own id, or it is somewhere it cannot be
// found by its address.
func TestAPathAgreesWithItsId(t *testing.T) {
	id := "a3f9c0112233445566778899aabbccdd"
	p := Path("devices", id)
	if p != "data/devices/a3/f9/"+id {
		t.Errorf("path is %q", p)
	}
	coll, got, ok := IsCollectionPath(p)
	if !ok || coll != "devices" || got != id {
		t.Errorf("did not round trip: %q %q %v", coll, got, ok)
	}
	// A shard that disagrees with the id is not a record path.
	if _, _, ok := IsCollectionPath("data/devices/zz/zz/" + id); ok {
		t.Error("a mismatched shard was accepted as a record path")
	}
}

// -- batching -----------------------------------------------------------------

func TestManyRecordsInOneWrite(t *testing.T) {
	s := newStore(t)
	var batch []Record
	for i := 0; i < 200; i++ {
		batch = append(batch, Record{Fields: map[string]any{"n": i}})
	}
	tree, out, err := PutMany(s, "", "devices", batch, when)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 200 {
		t.Fatalf("wrote %d", len(out))
	}
	n, _ := Count(s, tree, "devices")
	if n != 200 {
		t.Errorf("the store holds %d", n)
	}
	seen := map[string]bool{}
	for _, r := range out {
		if seen[r.ID] {
			t.Fatal("a batch produced a duplicate id")
		}
		seen[r.ID] = true
	}
}
