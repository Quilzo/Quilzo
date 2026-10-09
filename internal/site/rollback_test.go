// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package site

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quilzo/quilzo/internal/store"
)

func save(t *testing.T, s *store.Store, body string) string {
	t.Helper()
	id, err := SaveDraft(s, map[string]any{"index": map[string]any{"title": "Home", "body": body}}, body, "dana")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Going back returns to the version that was live before, never to a save
// in between that nobody published: that one never passed the checks
// publishing makes, and going back must not be a way round them.
func TestRollbackReturnsOnlyToWhatWasLive(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := save(t, s, "first")
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	unpublished := save(t, s, "a card number nobody checked")
	second := save(t, s, "second")
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	if WasLive(s, unpublished) {
		t.Fatal("a save nobody published is recorded as having been live")
	}
	if !WasLive(s, first) || !WasLive(s, second) {
		t.Fatal("a version that was live is not recorded as such")
	}
	pub, err := Rollback(s, 1)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Published != first {
		t.Fatalf("rolled back to %s, want the earlier publication %s (the unpublished save is %s)",
			pub.Published[:12], first[:12], unpublished[:12])
	}
	// Back again goes no further than the first publication.
	if _, err := Rollback(s, 1); err == nil {
		t.Error("rolled back past the first version that was ever live")
	}
	if got := s.GetRef(RefLive); got != first {
		t.Errorf("live is %s after a refused rollback", got[:12])
	}
	// And forwards again is publishing the later one, which was live.
	if _, err := Publish(s, second); err != nil {
		t.Fatal(err)
	}
	if pubs, _ := Publications(s); len(pubs) != 2 {
		t.Errorf("publications %v, want the two versions that were live, once each", pubs)
	}
}

// A store from before the record existed starts it at its first move, with
// the version that was live until then, so one step back still works.
func TestTheRecordStartsWithWhatWasLiveBefore(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := save(t, s, "old")
	// Live set the way a store from before the record had it: the ref alone.
	if err := s.SetRef(RefLive, old); err != nil {
		t.Fatal(err)
	}
	if err := removeRecord(dir); err != nil {
		t.Fatal(err)
	}
	save(t, s, "new")
	if _, err := Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	pub, err := Rollback(s, 1)
	if err != nil {
		t.Fatal(err)
	}
	if pub.Published != old {
		t.Errorf("went back to %s, want the version live before the record began", pub.Published[:12])
	}
}

func removeRecord(dir string) error {
	return os.RemoveAll(filepath.Join(dir, "reflogs"))
}
