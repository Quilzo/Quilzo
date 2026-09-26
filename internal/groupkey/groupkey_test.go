// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package groupkey

import (
	"bytes"
	"testing"

	"github.com/quilzo/quilzo/internal/sframe"
)

func ident(t *testing.T, name string) *Identity {
	t.Helper()
	i, err := NewIdentity(name)
	if err != nil {
		t.Fatalf("NewIdentity(%s): %v", name, err)
	}
	return i
}

// call builds a group with the named people in it, returning each one's own
// view. Every view is built by running the protocol, not by copying state.
func call(t *testing.T, names ...string) ([]*Group, []*Identity) {
	t.Helper()
	ids := []*Identity{ident(t, names[0])}
	g, err := Create("standup", ids[0])
	if err != nil {
		t.Fatal(err)
	}
	views := []*Group{g}
	for _, n := range names[1:] {
		joiner := ident(t, n)
		interim := views[0].Interim()
		c, ws, err := views[0].Commit(ids[0],
			[]Change{{Kind: Add, Member: joiner.Member(0)}})
		if err != nil {
			t.Fatalf("adding %s: %v", n, err)
		}
		for i, v := range views {
			if err := v.Apply(c, ids[i]); err != nil {
				t.Fatalf("%s applying the commit that adds %s: %v",
					ids[i].Name, n, err)
			}
		}
		if len(ws) != 1 {
			t.Fatalf("%d welcomes, want 1", len(ws))
		}
		jg, err := Join(ws[0], interim, joiner)
		if err != nil {
			t.Fatalf("%s joining: %v", n, err)
		}
		views = append(views, jg)
		ids = append(ids, joiner)
	}
	return views, ids
}

// agree checks that every view holds the same epoch secret, which is the
// only thing that makes the call work.
func agree(t *testing.T, views []*Group) {
	t.Helper()
	want := views[0].Authenticator()
	if want == "" {
		t.Fatal("no authenticator")
	}
	for _, v := range views[1:] {
		if got := v.Authenticator(); got != want {
			t.Fatalf("%d sees %s and 0 sees %s", v.Me(), got, want)
		}
	}
	base, err := views[0].BaseKey(sframe.AES128GCMSHA256128)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range views[1:] {
		got, err := v.BaseKey(sframe.AES128GCMSHA256128)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(base, got) {
			t.Fatalf("index %d derived a different base key", v.Me())
		}
	}
}

func TestEverybodyReachesTheSameSecret(t *testing.T) {
	views, _ := call(t, "ada", "grace", "alan", "katherine")
	agree(t, views)
	for _, v := range views {
		if v.Size() != 4 {
			t.Fatalf("index %d sees %d people", v.Me(), v.Size())
		}
	}
}

// TestSendersDoNotShareASaltOrKey is the property SFrame's nonce
// construction depends on. Two senders with the same salt produce the same
// nonce on their first frame.
func TestSendersDoNotShareASaltOrKey(t *testing.T) {
	views, _ := call(t, "ada", "grace", "alan")
	suite := sframe.AES128GCMSHA256128
	seenKey, seenSalt, seenKID := map[string]int{}, map[string]int{},
		map[uint64]int{}
	for _, v := range views {
		k, err := v.SenderKey(suite, 0)
		if err != nil {
			t.Fatal(err)
		}
		if other, dup := seenKey[string(k.Key)]; dup {
			t.Fatalf("index %d and %d share a key", v.Me(), other)
		}
		if other, dup := seenSalt[string(k.Salt)]; dup {
			t.Fatalf("index %d and %d share a salt", v.Me(), other)
		}
		if other, dup := seenKID[k.KID]; dup {
			t.Fatalf("index %d and %d share a KID", v.Me(), other)
		}
		seenKey[string(k.Key)] = v.Me()
		seenSalt[string(k.Salt)] = v.Me()
		seenKID[k.KID] = v.Me()
	}
	// And a receiver derives the same key for a sender as the sender does.
	mine, err := views[1].SenderKey(suite, 0)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := views[0].KeyFor(suite, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mine.Key, theirs.Key) ||
		!bytes.Equal(mine.Salt, theirs.Salt) {
		t.Fatal("a receiver derives a different key for a sender than the " +
			"sender uses")
	}
}

// TestRemovalIsForwardSecret: the person who left cannot follow the call.
func TestRemovalIsForwardSecret(t *testing.T) {
	views, ids := call(t, "ada", "grace", "alan")
	gone := views[2]
	before, err := gone.BaseKey(sframe.AES128GCMSHA256128)
	if err != nil {
		t.Fatal(err)
	}

	c, _, err := views[0].Commit(ids[0], []Change{{Kind: Remove, Index: 2}})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 1} {
		if err := views[i].Apply(c, ids[i]); err != nil {
			t.Fatalf("%s: %v", ids[i].Name, err)
		}
	}
	if err := gone.Apply(c, ids[2]); err == nil {
		t.Fatal("the removed member applied the commit that removed them")
	}
	after, err := views[0].BaseKey(sframe.AES128GCMSHA256128)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("the base key did not change when somebody left")
	}
	agree(t, views[:2])
}

// TestAJoinerCannotReadTheEpochBefore.
func TestAJoinerCannotReadTheEpochBefore(t *testing.T) {
	views, ids := call(t, "ada", "grace")
	suite := sframe.AES128GCMSHA256128
	before, err := views[0].BaseKey(suite)
	if err != nil {
		t.Fatal(err)
	}

	newcomer := ident(t, "alan")
	interim := views[0].Interim()
	c, ws, err := views[0].Commit(ids[0],
		[]Change{{Kind: Add, Member: newcomer.Member(0)}})
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range views {
		if err := v.Apply(c, ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	jg, err := Join(ws[0], interim, newcomer)
	if err != nil {
		t.Fatal(err)
	}
	after, err := jg.BaseKey(suite)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("the new arrival holds the key from before they arrived")
	}
	agree(t, append(views, jg))
}

// TestUpdateChangesTheKeyThatOpensTheNextCommit is post-compromise
// security. The attacker has a copy of grace's private key; after grace
// rotates it, the next commit is sealed to a key the attacker never had.
func TestUpdateChangesTheKeyThatOpensTheNextCommit(t *testing.T) {
	views, ids := call(t, "ada", "grace")
	stolen := *ids[1] // the attacker's copy, taken before the rotation

	if err := ids[1].Rotate(); err != nil {
		t.Fatal(err)
	}
	c, _, err := views[1].Commit(ids[1],
		[]Change{{Kind: Update, Index: 1, Member: ids[1].Member(1)}})
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range views {
		if err := v.Apply(c, ids[i]); err != nil {
			t.Fatal(err)
		}
	}
	agree(t, views)

	// The epoch after the rotation. Its secret is sealed to grace's new
	// key, and the stolen one opens nothing.
	before := views[0].Epoch
	rh := views[0].rosterHash()
	interim := views[0].Interim()
	c2, _, err := views[0].Commit(ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	var mine []byte
	for _, w := range c2.Sealed {
		if w.For == 1 {
			mine = w.Sealed
		}
	}
	if mine == nil {
		t.Fatal("no sealed secret for index 1")
	}
	info := sealInfo("commit", views[0].ID, before+1, rh, interim, 0, 1)
	if _, err := ids[1].open(info, mine); err != nil {
		t.Fatalf("grace's current key should open it: %v", err)
	}
	if _, err := stolen.open(info, mine); err == nil {
		t.Fatal("the stolen key still opens the commit; rotating it " +
			"bought nothing")
	}
}

func TestACommitFromOutsideIsRefused(t *testing.T) {
	views, ids := call(t, "ada", "grace")
	outsider := ident(t, "mallory")
	c, _, err := views[0].Commit(ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Ed25519, c.MLDSA, err = outsider.sign(c.signed()); err != nil {
		t.Fatal(err)
	}
	if err := views[1].Apply(c, ids[1]); err == nil {
		t.Fatal("a commit signed by somebody outside the call was accepted")
	}
}

// TestASplitRosterIsCaught is the property most products do not have. The
// server hands one member a roster with an extra person in it.
func TestASplitRosterIsCaught(t *testing.T) {
	views, ids := call(t, "ada", "grace")
	eve := ident(t, "eve")

	c, _, err := views[0].Commit(ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	// The server rewrites the commit on its way to grace, adding Eve.
	tampered := *c
	tampered.Changes = []Change{{Kind: Add, Member: eve.Member(0)}}
	if err := views[1].Apply(&tampered, ids[1]); err == nil {
		t.Fatal("a rewritten roster was accepted")
	}

	// Even re-signed with the committer's own key, it does not get
	// through — and it is worth knowing which layer stops it. The
	// ciphertexts were sealed against the roster hash of the roster Ada
	// actually committed, so with Eve added they open to nothing. The
	// confirmation tag never gets a chance, because there is no secret to
	// compute it from.
	resigned := *c
	resigned.Changes = []Change{{Kind: Add, Member: eve.Member(0)}}
	if resigned.Ed25519, resigned.MLDSA, err = ids[0].sign(
		resigned.signed()); err != nil {
		t.Fatal(err)
	}
	err = views[1].Apply(&resigned, ids[1])
	if err == nil {
		t.Fatal("a roster split signed with the committer's own key was " +
			"accepted")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("does not open")) {
		t.Fatalf("caught, but not where expected: %v", err)
	}
}

// TestTheConfirmationTagIsChecked proves the backstop is live rather than
// decorative. The seal info catches a rewritten roster first, so the tag
// has to be tested on its own.
func TestTheConfirmationTagIsChecked(t *testing.T) {
	views, ids := call(t, "ada", "grace")
	c, _, err := views[0].Commit(ids[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := *c
	bad.Confirmation = append([]byte(nil), c.Confirmation...)
	bad.Confirmation[0] ^= 1
	err = views[1].Apply(&bad, ids[1])
	if err == nil {
		t.Fatal("a commit with the wrong confirmation tag was accepted")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("confirmation")) {
		t.Fatalf("caught, but not by the confirmation tag: %v", err)
	}
	// And the good one still applies, so the check is not simply refusing
	// everything.
	if err := views[1].Apply(c, ids[1]); err != nil {
		t.Fatalf("the untouched commit was refused: %v", err)
	}
}

func TestAWelcomeForSomebodyElseIsRefused(t *testing.T) {
	views, ids := call(t, "ada")
	joiner := ident(t, "grace")
	interim := views[0].Interim()
	_, ws, err := views[0].Commit(ids[0],
		[]Change{{Kind: Add, Member: joiner.Member(0)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Join(ws[0], interim, ident(t, "mallory")); err == nil {
		t.Fatal("a welcome addressed to somebody else was accepted")
	}
}

func TestAnEditedWelcomeIsRefused(t *testing.T) {
	views, ids := call(t, "ada", "grace")
	joiner := ident(t, "alan")
	interim := views[0].Interim()
	_, ws, err := views[0].Commit(ids[0],
		[]Change{{Kind: Add, Member: joiner.Member(0)}})
	if err != nil {
		t.Fatal(err)
	}
	w := *ws[0]
	w.Roster = append([]Member(nil), w.Roster...)
	w.Roster[0].Name = "not ada"
	if _, err := Join(&w, interim, joiner); err == nil {
		t.Fatal("a welcome with an edited roster was accepted")
	}
}

func TestEpochsAndKIDs(t *testing.T) {
	views, _ := call(t, "ada", "grace", "alan")
	g := views[0]
	if g.Epoch != 2 {
		t.Fatalf("epoch = %d, want 2", g.Epoch)
	}
	if g.IndexBits() != 2 {
		t.Fatalf("index bits = %d, want 2 for three slots", g.IndexBits())
	}
	kid, err := g.KID(2, 0)
	if err != nil {
		t.Fatal(err)
	}
	// KID = (context << (S+E)) + (index << E) + (epoch % 2^E)
	if want := uint64(2)<<EpochBits | 2; kid != want {
		t.Fatalf("kid = %#x, want %#x", kid, want)
	}
	with, err := g.KID(2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(5)<<(2+EpochBits) | 2<<EpochBits | 2; with != want {
		t.Fatalf("kid with context = %#x, want %#x", with, want)
	}
	if !g.Stale(2 + 1<<EpochBits) {
		t.Fatal("an epoch with the same low bits should be reported stale")
	}
	if g.Stale(3) {
		t.Fatal("a different epoch with different low bits is not stale")
	}
}

func TestExporterSeparatesPurposes(t *testing.T) {
	views, _ := call(t, "ada", "grace")
	g := views[0]
	a, err := g.Exporter("one", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.Exporter("two", nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two labels produced the same secret")
	}
	c, err := g.Exporter("one", []byte("x"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("two contexts produced the same secret")
	}
	if _, err := g.Exporter("", nil, 32); err == nil {
		t.Fatal("an unlabelled export was allowed")
	}
}

func TestCannotEmptyTheCall(t *testing.T) {
	views, ids := call(t, "ada")
	if _, _, err := views[0].Commit(ids[0],
		[]Change{{Kind: Remove, Index: 0}}); err == nil {
		t.Fatal("the last member removed themselves")
	}
}
