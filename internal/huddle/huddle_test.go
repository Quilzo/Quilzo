// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package huddle

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/groupkey"
	"github.com/quilzo/quilzo/internal/sframe"
)

var t0 = time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

func member(t *testing.T, name string) (*groupkey.Identity, groupkey.Member) {
	t.Helper()
	id, err := groupkey.NewIdentity(name)
	if err != nil {
		t.Fatal(err)
	}
	return id, id.Member(0)
}

func opened(t *testing.T) *Call {
	t.Helper()
	c, err := Open("standup", "the standup", "ada", t0)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestALinkOnlyBuysAKnock(t *testing.T) {
	c := opened(t)
	secret, inv, err := c.Invite(0, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 30 {
		t.Fatalf("a %d-character secret is not 160 bits", len(secret))
	}
	if strings.Contains(inv.Digest, secret) {
		t.Fatal("the call is storing the secret")
	}

	_, m := member(t, "grace")
	straight, err := c.Present(secret, "grace", m, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if straight {
		t.Fatal("the default policy knocks")
	}
	if len(c.Waiting) != 1 {
		t.Fatalf("%d waiting, want 1", len(c.Waiting))
	}
	if len(c.Seats) != 1 {
		t.Fatal("somebody in the lobby is not in the call")
	}
}

func TestAnInvitationIsSpentExpiresAndBinds(t *testing.T) {
	c := opened(t)
	_, m := member(t, "grace")

	once, _, err := c.Invite(0, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Present(once, "grace", m, t0); err != nil {
		t.Fatal(err)
	}
	_, m2 := member(t, "alan")
	if _, err := c.Present(once, "alan", m2, t0); err == nil {
		t.Fatal("a one-use invitation was used twice")
	}

	short, _, err := c.Invite(0, time.Minute, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Present(short, "alan", m2, t0.Add(2*time.Minute)); err == nil {
		t.Fatal("an expired invitation was accepted")
	}

	bound, _, err := c.Invite(0, time.Hour, t0, ForPerson("katherine"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Present(bound, "alan", m2, t0); err == nil {
		t.Fatal("a bound invitation was used by somebody else")
	}

	if _, _, err := c.Invite(0, 48*time.Hour, t0); err == nil {
		t.Fatal("an invitation was issued for longer than the cap")
	}
}

func TestRevokingAnInvitation(t *testing.T) {
	c := opened(t)
	secret, inv, err := c.Invite(0, time.Hour, t0, Reusable(5))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(inv.ID, 0, t0); err != nil {
		t.Fatal(err)
	}
	_, m := member(t, "grace")
	if _, err := c.Present(secret, "grace", m, t0); err == nil {
		t.Fatal("a revoked invitation was accepted")
	}
}

// TestEjectIsCryptographicAndMuteIsNot is the package's whole claim, driven
// against a real group rather than asserted.
func TestEjectIsCryptographicAndMuteIsNot(t *testing.T) {
	host, _ := member(t, "ada")
	g, err := groupkey.Create("standup", host)
	if err != nil {
		t.Fatal(err)
	}
	c := opened(t)

	// Grace arrives with an invitation, knocks, and is admitted — which is
	// a commit, not a flag.
	graceID, graceM := member(t, "grace")
	secret, _, err := c.Invite(0, time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Present(secret, "grace", graceM, t0); err != nil {
		t.Fatal(err)
	}
	change, err := c.Admit("grace", 0, Speaker, t0)
	if err != nil {
		t.Fatal(err)
	}
	interim := g.Interim()
	commit, welcomes, err := g.Commit(host, []groupkey.Change{change})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(commit, host); err != nil {
		t.Fatal(err)
	}
	graceG, err := groupkey.Join(welcomes[0], interim, graceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Seated("grace", graceG.Me(), Speaker, t0); err != nil {
		t.Fatal(err)
	}

	suite := sframe.AES128GCMSHA256128
	before, err := graceG.BaseKey(suite)
	if err != nil {
		t.Fatal(err)
	}

	// Muting is Agreed. Grace still holds the key.
	if err := c.Mute(graceG.Me(), 0, t0); err != nil {
		t.Fatal(err)
	}
	if ok, why := c.MaySpeak(graceG.Me()); ok || !strings.Contains(why, "ada") {
		t.Fatalf("may speak = %v (%s)", ok, why)
	}
	still, err := graceG.BaseKey(suite)
	if err != nil {
		t.Fatal(err)
	}
	if string(still) != string(before) {
		t.Fatal("muting changed the key, which would mean this package is " +
			"claiming something it cannot do")
	}

	// Ejecting is Cryptographic. Grace does not.
	drop, err := c.Eject(graceG.Me(), 0, t0)
	if err != nil {
		t.Fatal(err)
	}
	commit2, _, err := g.Commit(host, []groupkey.Change{drop})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(commit2, host); err != nil {
		t.Fatal(err)
	}
	if err := graceG.Apply(commit2, graceID); err == nil {
		t.Fatal("the ejected member followed the call")
	}
	after, err := g.BaseKey(suite)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) == string(before) {
		t.Fatal("the key did not change on ejection")
	}
	if _, ok := c.Seat(graceG.Me()); ok {
		t.Fatal("the ejected member still has a seat")
	}
}

func TestOnlyModeratorsModerate(t *testing.T) {
	c := opened(t)
	if err := c.Seated("grace", 1, Speaker, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Seated("alan", 2, Listener, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Mute(2, 1, t0); err == nil {
		t.Fatal("a speaker muted somebody")
	}
	if _, err := c.Eject(2, 1, t0); err == nil {
		t.Fatal("a speaker ejected somebody")
	}
	if err := c.Promote(1, 0, Cohost, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Mute(2, 1, t0); err != nil {
		t.Fatalf("a cohost could not mute: %v", err)
	}
}

// TestACohostCannotMakeAnotherCohost: a moderation power that can grant
// itself is bounded by nothing.
func TestACohostCannotMakeAnotherCohost(t *testing.T) {
	c := opened(t)
	for i, n := range []string{"grace", "alan"} {
		if err := c.Seated(n, i+1, Listener, t0); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Promote(1, 0, Cohost, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Promote(2, 1, Cohost, t0); err == nil {
		t.Fatal("a cohost made another cohost")
	}
	if err := c.Promote(2, 1, Speaker, t0); err != nil {
		t.Fatalf("a cohost could not promote to speaker: %v", err)
	}
}

// TestAModeratorCannotTurnOnYourMicrophone.
func TestAModeratorCannotTurnOnYourMicrophone(t *testing.T) {
	c := opened(t)
	if err := c.Seated("grace", 1, Speaker, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Mute(1, 0, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.AskToUnmute(1, 0, t0); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.MaySpeak(1); ok {
		t.Fatal("asking unmuted them")
	}
	if err := c.Unmute(1, t0); err != nil {
		t.Fatal(err)
	}
	if ok, why := c.MaySpeak(1); !ok {
		t.Fatalf("they could not unmute themselves: %s", why)
	}
}

// TestSeveralPeopleShareAtOnceUnderDifferentKeys.
func TestSeveralPeopleShareAtOnceUnderDifferentKeys(t *testing.T) {
	c := opened(t)
	for i, n := range []string{"grace", "alan"} {
		if err := c.Seated(n, i+1, Speaker, t0); err != nil {
			t.Fatal(err)
		}
	}
	a, err := c.StartShare(0, Screen, "the design", t0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.StartShare(1, Window, "the code", t0)
	if err != nil {
		t.Fatal(err)
	}
	// And one person sharing two windows at once.
	second, err := c.StartShare(1, Window, "the tests", t0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Context == second.Context {
		t.Fatal("one sender's two streams share a key context, so they " +
			"would share a key and a salt")
	}
	if len(c.Sharing()) != 3 {
		t.Fatalf("%d shares, want 3", len(c.Sharing()))
	}
	_ = a

	// The camera does not count against the screen-share cap.
	c.Policy.MaxShares = 3
	if _, err := c.StartShare(2, Camera, "", t0); err != nil {
		t.Fatalf("a camera was refused under the share cap: %v", err)
	}
	if _, err := c.StartShare(2, Screen, "", t0); err == nil {
		t.Fatal("the share cap was not applied")
	}
}

// TestSharesGetDistinctKIDsThroughTheGroup checks the connection is real:
// the context a share is allocated becomes a distinct SFrame key.
func TestSharesGetDistinctKIDsThroughTheGroup(t *testing.T) {
	host, _ := member(t, "ada")
	g, err := groupkey.Create("standup", host)
	if err != nil {
		t.Fatal(err)
	}
	c := opened(t)
	one, err := c.StartShare(0, Screen, "", t0)
	if err != nil {
		t.Fatal(err)
	}
	two, err := c.StartShare(0, Window, "", t0)
	if err != nil {
		t.Fatal(err)
	}
	suite := sframe.AES128GCMSHA256128
	ka, err := g.SenderKey(suite, one.Context)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := g.SenderKey(suite, two.Context)
	if err != nil {
		t.Fatal(err)
	}
	if ka.KID == kb.KID {
		t.Fatal("two streams from one sender got the same KID")
	}
	if string(ka.Salt) == string(kb.Salt) {
		t.Fatal("two streams from one sender share a salt, so they would " +
			"reuse a nonce")
	}
}

// TestTheHandQueueIsOrderedByTheCallNotTheClock.
func TestTheHandQueueIsOrderedByTheCallNotTheClock(t *testing.T) {
	c := opened(t)
	for i, n := range []string{"grace", "alan", "katherine"} {
		if err := c.Seated(n, i+1, Speaker, t0); err != nil {
			t.Fatal(err)
		}
	}
	// Three hands, with clocks that disagree: alan's laptop is ahead and
	// katherine's is behind, but alan raised second.
	if err := c.Signal(1, Hand, "", t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.Signal(2, Hand, "", t0.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.Signal(3, Hand, "", t0); err != nil {
		t.Fatal(err)
	}
	q := c.Queue(t0.Add(time.Minute))
	if len(q) != 3 {
		t.Fatalf("%d hands, want 3", len(q))
	}
	for i, want := range []int{1, 2, 3} {
		if q[i].Seat != want {
			t.Fatalf("position %d is seat %d, want %d; the queue followed "+
				"the clocks instead of the call", i, q[i].Seat, want)
		}
	}
	// Raising twice is raising once.
	if err := c.Signal(1, Hand, "", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(c.Queue(t0.Add(time.Minute))) != 3 {
		t.Fatal("raising a hand twice made two hands")
	}
	if err := c.Lower(1, Hand, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if q := c.Queue(t0.Add(3 * time.Minute)); len(q) != 2 || q[0].Seat != 2 {
		t.Fatalf("after lowering: %d hands, first is seat %d", len(q),
			q[0].Seat)
	}
}

func TestReactionsExpireAndHandsDoNot(t *testing.T) {
	c := opened(t)
	if err := c.Signal(0, React, "👏", t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Signal(0, Hand, "", t0); err != nil {
		t.Fatal(err)
	}
	if n := len(c.Live(t0.Add(time.Second))); n != 2 {
		t.Fatalf("%d live at one second, want 2", n)
	}
	live := c.Live(t0.Add(ReactLife + time.Second))
	if len(live) != 1 || live[0].Kind != Hand {
		t.Fatalf("after the reaction expired: %d live", len(live))
	}
	if err := c.Signal(0, React, strings.Repeat("a", 40), t0); err == nil {
		t.Fatal("a paragraph was accepted as a reaction")
	}
}

func TestLockingEmptiesTheLobby(t *testing.T) {
	c := opened(t)
	secret, _, err := c.Invite(0, time.Hour, t0, Reusable(3))
	if err != nil {
		t.Fatal(err)
	}
	_, m := member(t, "grace")
	if _, err := c.Present(secret, "grace", m, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Lock(0, t0); err != nil {
		t.Fatal(err)
	}
	if len(c.Waiting) != 0 {
		t.Fatal("locking left people waiting for a door that will not open")
	}
	_, m2 := member(t, "alan")
	if _, err := c.Present(secret, "alan", m2, t0); err == nil {
		t.Fatal("a locked call accepted an arrival")
	}
	if err := c.Unlock(0, Knock, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Present(secret, "alan", m2, t0); err != nil {
		t.Fatal(err)
	}
}

func TestStraightInIsPerInvitation(t *testing.T) {
	c := opened(t)
	open, _, err := c.Invite(0, time.Hour, t0, LetStraightIn())
	if err != nil {
		t.Fatal(err)
	}
	_, m := member(t, "grace")
	straight, err := c.Present(open, "grace", m, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !straight {
		t.Fatal("that invitation should have skipped the lobby")
	}
	if c.Policy.Admission != Knock {
		t.Fatal("one invitation changed the call's policy")
	}
}

func TestEveryControlDeclaresWhatHoldsIt(t *testing.T) {
	seen := map[Enforcement]bool{}
	for _, c := range Controls() {
		switch c.Enforcement {
		case Cryptographic, Agreed, Requested:
		default:
			t.Fatalf("%s claims %q", c.Name, c.Enforcement)
		}
		if c.How == "" || c.Enforcement.Why() == "" {
			t.Fatalf("%s says nothing about what holds it", c.Name)
		}
		seen[c.Enforcement] = true
	}
	for _, e := range []Enforcement{Cryptographic, Agreed, Requested} {
		if !seen[e] {
			t.Fatalf("no control is %s, which makes the distinction "+
				"decorative", e)
		}
	}
	if !Cryptographic.Holds() || Agreed.Holds() || Requested.Holds() {
		t.Fatal("Holds does not mean what the package says it means")
	}
}

func TestTheHostCannotBeEjectedOrDemoted(t *testing.T) {
	c := opened(t)
	if err := c.Seated("grace", 1, Speaker, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Promote(1, 0, Cohost, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Eject(0, 1, t0); err == nil {
		t.Fatal("a cohost ejected the host")
	}
	if err := c.Mute(0, 1, t0); err == nil {
		t.Fatal("a cohost muted the host")
	}
	if err := c.Handover(1, 0, t0); err != nil {
		t.Fatal(err)
	}
	if s, _ := c.Seat(1); s.Role != Host {
		t.Fatal("the chair did not pass")
	}
	if s, _ := c.Seat(0); s.Role != Cohost {
		t.Fatal("the old host is not a cohost")
	}
}

func TestTheLogIsOrdered(t *testing.T) {
	c := opened(t)
	if err := c.Seated("grace", 1, Speaker, t0); err != nil {
		t.Fatal(err)
	}
	if err := c.Mute(1, 0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := c.Unmute(1, t0); err != nil {
		t.Fatal(err)
	}
	log := c.Log()
	if len(log) < 2 {
		t.Fatalf("%d entries", len(log))
	}
	for i := 1; i < len(log); i++ {
		if log[i].Order() <= log[i-1].Order() {
			t.Fatal("the log is not in the call's order")
		}
	}
	if !strings.Contains(log[len(log)-1].Note, "unmuted") {
		t.Fatalf("the last entry is %q; the clocks won", log[len(log)-1].Note)
	}
}
