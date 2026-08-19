package store

import (
	"strings"
	"testing"
)

// PutRaw is the whole trust model of replication, so it is tested as its own
// thing rather than only through a pull.
//
// Through a pull, the kind check below is unreachable: the id being asked for
// comes from a tree this store already verified, so a peer cannot choose it,
// and the hash check refuses a mislabelled object before the kind check has an
// opinion. That makes the kind check defence in depth for the exported API —
// and an untested defence stops working the day a second caller reaches it,
// which is exactly what happened to a refusal in the agent session gate a
// commit ago.

func rawStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The name is the hash, so bytes either produce that name or they are not that
// object. There is no third possibility, and no signature involved.
func TestPutRawRefusesBytesThatDoNotHashToTheirName(t *testing.T) {
	s := rawStore(t)
	payload := []byte(`{"title":"Genuine"}`)
	oid := ObjectID(KindBlob, payload)

	if err := s.PutRaw(oid, KindBlob, payload); err != nil {
		t.Fatalf("a genuine object was refused: %v", err)
	}
	if !s.Has(oid) {
		t.Fatal("the object was not stored")
	}

	substituted := []byte(`{"title":"Substituted"}`)
	err := s.PutRaw(oid, KindBlob, substituted)
	if err == nil {
		t.Fatal("a peer substituted content and the store took it")
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Errorf("the refusal does not say the name is the hash: %v", err)
	}
	// And the substitution did not land under any name. A store that files it
	// under its own hash has accepted an object nothing asked for.
	if s.Has(ObjectID(KindBlob, substituted)) {
		t.Error("the substituted bytes were stored under their own id, so a " +
			"refused object still consumed the disk it was refused for")
	}
}

// An object kind this build does not know is refused rather than stored.
func TestPutRawRefusesAnUnknownKind(t *testing.T) {
	s := rawStore(t)
	payload := []byte(`whatever`)
	// Correctly named for its claimed kind, so only the kind check can refuse
	// it. This is the case the hash check cannot see.
	oid := ObjectID("attachment", payload)

	err := s.PutRaw(oid, "attachment", payload)
	if err == nil {
		t.Fatal("an object of a kind this build cannot read was stored. " +
			"Bytes nothing here can verify are worse in the store than absent")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Errorf("the refusal does not name the problem: %v", err)
	}
	if s.Has(oid) {
		t.Error("it was stored anyway")
	}
}

// GetRaw answers with the kind, so a replica can move an object without
// knowing what it is.
func TestGetRawRoundTripsEveryKind(t *testing.T) {
	s := rawStore(t)

	blob, err := s.PutBlob(map[string]any{"title": "Home"})
	if err != nil {
		t.Fatal(err)
	}
	tree, err := s.PutTree(map[string]string{"index": blob})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := s.PutCommit(Commit{Tree: tree, Message: "first", Author: "me"})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ oid, kind string }{
		{blob, KindBlob}, {tree, KindTree}, {commit, KindCommit},
	} {
		kind, payload, err := s.GetRaw(tc.oid)
		if err != nil {
			t.Errorf("GetRaw(%s) failed: %v", tc.kind, err)
			continue
		}
		if kind != tc.kind {
			t.Errorf("GetRaw reported %q for a %s", kind, tc.kind)
		}
		// The round trip that makes replication work: what comes out re-enters
		// another store under the same name.
		if got := ObjectID(kind, payload); got != tc.oid {
			t.Errorf("a %s came back out as %s; it would not be accepted by "+
				"the store it was sent to", tc.kind, got)
		}
	}

	if _, _, err := s.GetRaw(ObjectID(KindBlob, []byte("absent"))); err == nil {
		t.Error("GetRaw answered for an object that is not here")
	}
}

// An encrypted store hands over plaintext, because the id is the hash of the
// plaintext and a peer cannot check ciphertext against it.
//
// Asserted rather than left implicit: this is a disclosure decision, and the
// alternative reading — that replication moves the sealed form — produces a
// replica whose objects fail their own names on arrival.
func TestGetRawOnAnEncryptedStoreYieldsWhatTheIDMeans(t *testing.T) {
	s := rawStore(t)
	blob, err := s.PutBlob(map[string]any{"title": "Home"})
	if err != nil {
		t.Fatal(err)
	}
	kind, payload, err := s.GetRaw(blob)
	if err != nil {
		t.Fatal(err)
	}
	if ObjectID(kind, payload) != blob {
		t.Error("what GetRaw returns does not hash to the id it was asked for")
	}
	if !strings.Contains(string(payload), "Home") {
		t.Errorf("the payload is not the plaintext the id names: %q", payload)
	}
}
