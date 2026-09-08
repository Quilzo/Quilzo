// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// A peer cannot store a tree whose names are not paths in this store.
//
// PutRaw checked that the bytes hash to the id it was asked for, and nothing
// else. That proves the bytes are the object requested; it cannot prove the
// object is well formed, because a peer chooses both the bytes and the name it
// offers them under — so the hash check is satisfied by any tree the peer
// likes, including one whose keys are "../../../../tmp/pwned".
//
// PutTree has always validated every segment. This path parsed nothing, and
// GetTree is a bare unmarshal, so every consumer downstream treated those keys
// as page names. `quilzo export` joined one onto an output directory and wrote
// it: arbitrary location, attacker-chosen contents, parent directories created
// on the way.
func TestAPeerCannotStoreATreeThatEscapesTheStore(t *testing.T) {
	s, err := Open(t.TempDir() + "/st")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := s.PutBlob(map[string]any{"title": "t"})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"../../../../tmp/pwned",
		"..",
		"a/../../b",
		"/etc/passwd",
		"ok/../../escape",
	} {
		payload, err := json.Marshal(map[string]string{name: blob})
		if err != nil {
			t.Fatal(err)
		}
		// The peer names it honestly: the id really is the hash of these
		// bytes, which is the only thing PutRaw used to check.
		want := ObjectID(KindTree, payload)
		if err := s.PutRaw(want, KindTree, payload); err == nil {
			t.Errorf("a tree naming %q was stored; every consumer downstream "+
				"treats that as a page name", name)
		}
	}
}

// An honest tree from a peer still replicates.
//
// The check has to refuse a traversal without refusing replication, which is
// the whole point of PutRaw existing.
func TestAPeerCanStoreAnOrdinaryTree(t *testing.T) {
	s, err := Open(t.TempDir() + "/st")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := s.PutBlob(map[string]any{"title": "t"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]string{
		"index":                  blob,
		"data/users/ab/cd/rec-1": blob,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := ObjectID(KindTree, payload)
	if err := s.PutRaw(want, KindTree, payload); err != nil {
		t.Fatalf("an ordinary nested tree was refused: %v", err)
	}
	got, err := s.GetTree(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("stored a tree of 2 and read back %d", len(got))
	}
}

// Bytes that are not a tree at all are refused as a tree.
func TestAPeerCannotStoreRubbishAsATree(t *testing.T) {
	s, err := Open(t.TempDir() + "/st")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`not json`)
	err = s.PutRaw(ObjectID(KindTree, payload), KindTree, payload)
	if err == nil {
		t.Fatal("stored bytes that do not parse as a tree")
	}
	if !strings.Contains(err.Error(), "does not parse") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}
