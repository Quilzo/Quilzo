package site

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/store"
)

// The integration that would otherwise destroy data: a page edit must not
// remove the application's records.
func TestEditingAPageDoesNotWipeTheRecords(t *testing.T) {
	s := newStore(t)
	if _, err := SaveDraft(s, map[string]any{"index": page("Home")},
		"first", "dana"); err != nil {
		t.Fatal(err)
	}

	// A record written against the draft's tree, committed the way a record
	// write will.
	c, err := s.GetCommit(s.GetRef(RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	tree, rec, err := collection.Put(s, c.Tree, "devices",
		collection.Record{Fields: map[string]any{"hostname": "laptop-14"}},
		time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Committed the way a record write will: a commit pointing at the new
	// tree, with the current draft as its parent.
	newCommit, err := s.PutCommit(store.Commit{
		Tree: tree, Parents: []string{s.GetRef(RefDraft)},
		Message: "a record", Author: "dana", At: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRef(RefDraft, newCommit); err != nil {
		t.Fatal(err)
	}

	// Now somebody edits a page, which rebuilds the tree from the page set.
	if _, err := SaveDraft(s, map[string]any{
		"index": page("Home, rewritten"),
		"about": page("About"),
	}, "an ordinary edit", "dana"); err != nil {
		t.Fatal(err)
	}

	after, err := s.GetCommit(s.GetRef(RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	got, err := collection.Get(s, after.Tree, "devices", rec.ID)
	if err != nil {
		t.Fatalf("editing a page destroyed the records: %v", err)
	}
	if got.Fields["hostname"] != "laptop-14" {
		t.Errorf("the record survived but changed: %v", got.Fields)
	}
	pages, err := PagesAt(s, s.GetRef(RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 2 {
		t.Errorf("%d pages after the edit, want 2", len(pages))
	}
}
