// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package replica

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Pull reads the quarantine ref, decides from what it read, and writes —
// without holding anything in between.
//
// That is the arrangement internal/site's own comment describes as making a
// base check into advice:
//
//	Doing the base check and then writing without holding anything makes
//	--based-on and the API's If-Match into advice: sixteen concurrent writes
//	against one base all passed the check and all committed, and fifteen
//	edits vanished.
//
// Here the check is the fast-forward test. Two pulls from the same peer, or a
// pull racing anything else that moves that ref, can both read the same
// `was`, both conclude they fast-forward, and both write — so the second
// silently overwrites a head the first had just established, and the ancestry
// that was verified was verified against a ref that no longer holds.
//
// store.CompareAndSwapRef exists for exactly this and had no caller anywhere
// in the program.
func TestTheHeadIsOnlyMovedFromWhatWasRead(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const ref = "peer-one"

	first, err := s.PutBlob(map[string]any{"n": 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.PutBlob(map[string]any{"n": 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}

	// What Pull does: read the ref, then write.
	was := s.GetRef(ref)

	// Somebody else moves it in between.
	if err := s.SetRef(ref, first); err != nil {
		t.Fatal(err)
	}

	// The write must now be refused, because the ref is not what was read.
	err = s.CompareAndSwapRef(ref, was, second)
	if err == nil {
		t.Fatal("a ref that moved between the read and the write was " +
			"overwritten anyway, so the fast-forward check was made against " +
			"a value that no longer holds")
	}
	var moved *store.RefMoved
	if !asRefMoved(err, &moved) {
		t.Fatalf("the refusal is not a RefMoved: %v", err)
	}
	if moved.Found != first {
		t.Errorf("the error says it found %q, and the ref holds %q",
			moved.Found, first)
	}
	// And the error has to say what it found, so a caller can tell "somebody
	// else wrote" from "the store is broken".
	if !strings.Contains(err.Error(), "peer-one") {
		t.Errorf("the refusal does not name the ref: %v", err)
	}
	// The ref is untouched.
	if got := s.GetRef(ref); got != first {
		t.Errorf("the ref is %q after a refused swap", got)
	}
}

func asRefMoved(err error, out **store.RefMoved) bool {
	m, ok := err.(*store.RefMoved)
	if ok {
		*out = m
	}
	return ok
}

// A pull that succeeds still moves the ref, and one whose head is already
// current still does nothing. Regression guards for the change above: swapping
// SetRef for a compare-and-swap must not change either.
func TestAnOrdinaryPullStillMovesTheRef(t *testing.T) {
	peer, peerHead := peerStore(t, map[string]any{
		"index": map[string]any{"title": "Theirs"},
	})
	local := emptyStore(t)
	src := &storeSource{s: peer}

	res, err := Pull(context.Background(), local, src, "them", site.RefDraft, Limits{})
	if err != nil {
		t.Fatalf("an ordinary pull failed: %v", err)
	}
	if !res.FastForward {
		t.Error("a pull into an empty store is not a fast-forward")
	}
	if got := local.GetRef(QuarantineRef("them")); got != peerHead {
		t.Errorf("the quarantine ref is %q, the peer head is %q", got, peerHead)
	}

	// Again, with nothing new. The head is already current, so the
	// compare-and-swap is never reached.
	again, err := Pull(context.Background(), local, src, "them", site.RefDraft, Limits{})
	if err != nil {
		t.Fatalf("a second pull failed: %v", err)
	}
	if again.Head != peerHead {
		t.Errorf("the second pull reports head %q", again.Head)
	}
	if got := local.GetRef(QuarantineRef("them")); got != peerHead {
		t.Errorf("the second pull moved the ref to %q", got)
	}
}

// A peer whose head does not descend is still a Divergence rather than a
// Raced. The two are different things and a caller has to tell them apart:
// one is somebody's afternoon, the other is a retry.
func TestADivergentPeerIsStillADivergence(t *testing.T) {
	peer, _ := peerStore(t, map[string]any{
		"index": map[string]any{"title": "Theirs"},
	})
	local := emptyStore(t)

	// Something unrelated already at the quarantine ref.
	other, err := local.PutBlob(map[string]any{"placed": "by somebody else"})
	if err != nil {
		t.Fatal(err)
	}
	if err := local.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := local.SetRef(QuarantineRef("them"), other); err != nil {
		t.Fatal(err)
	}

	_, err = Pull(context.Background(), local, &storeSource{s: peer},
		"them", site.RefDraft, Limits{})
	var div *Divergence
	if !errors.As(err, &div) {
		t.Fatalf("a divergent peer gave %T: %v", err, err)
	}
	var raced *Raced
	if errors.As(err, &raced) {
		t.Error("a divergence was reported as a race")
	}
}

// Raced says what to do, because the transfer succeeded and only the write
// was refused: every object is present, verified and immutable.
func TestRacedSaysTheObjectsAreHere(t *testing.T) {
	e := &Raced{
		Peer: "them", Ref: "peer-them",
		Read:  "aaaaaaaaaaaabbbb",
		Found: "ccccccccccccdddd",
		Head:  "eeeeeeeeeeeeffff",
	}
	msg := e.Error()
	for _, want := range []string{"peer-them", "aaaaaaaaaaaa", "cccccccccccc",
		"nothing was written", "run the pull again"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not contain %q: %s", want, msg)
		}
	}
	// The full ids are not printed, because nothing else in this program
	// prints one.
	if strings.Contains(msg, e.Read) {
		t.Errorf("the message prints a full object id: %s", msg)
	}
}
