// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package lockout

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/clientip"
)

const (
	home  = "198.51.100.7:51000"
	home2 = "198.51.100.200:40000" // the same /24: still home
	away  = "203.0.113.9:1234"
)

// Failures from a place the person never signed in from lock that kind of
// place out after ten, for thirty minutes and then double that; the place
// they really use keeps working all the while.
func TestFailuresFromStrangePlacesLockThemOutAndNotThePerson(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "lockout.json")}
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	if _, err := s.Succeed("dana", home, now); err != nil {
		t.Fatal(err)
	}
	var ev Event
	for i := 1; i <= Threshold; i++ {
		_, e, err := s.Fail("dana", away, now)
		if err != nil {
			t.Fatal(err)
		}
		if i < Threshold && e != NoEvent {
			t.Fatalf("locked after %d failures", i)
		}
		ev = e
	}
	if ev != Locked {
		t.Fatalf("ten failures from a strange place locked nothing: %q", ev)
	}
	if d, _ := s.Check("dana", away, now); d.Allowed || d.RetryAfter != LockFor {
		t.Errorf("the strange place: %+v", d)
	}
	if d, _ := s.Check("dana", home2, now); !d.Allowed {
		t.Errorf("the person's own network was locked out: %+v", d)
	}
	later := now.Add(LockFor + time.Second)
	if d, _ := s.Check("dana", away, later); !d.Allowed {
		t.Errorf("the lockout did not end: %+v", d)
	}
	for i := 0; i < Threshold; i++ {
		s.Fail("dana", away, later)
	}
	if d, _ := s.Check("dana", away, later); d.RetryAfter != 2*LockFor {
		t.Errorf("the second lockout did not double: %+v", d)
	}
	held, _ := s.Held(later)
	if len(held) != 1 || held[0].Name != "dana" {
		t.Errorf("held: %+v", held)
	}
}

// The person's own mistakes, from their own place, lock nobody out of
// anywhere: only failures from strange places count towards that.
func TestFailuresFromTheirOwnPlaceLockNothing(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "lockout.json")}
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	s.Succeed("dana", home, now)
	for i := 0; i < 2*Threshold; i++ {
		if _, ev, _ := s.Fail("dana", home2, now); ev != NoEvent {
			t.Fatalf("failure %d from home was a %q", i+1, ev)
		}
	}
	if d, _ := s.Check("dana", away, now); !d.Allowed {
		t.Errorf("mistakes at home locked out somewhere else: %+v", d)
	}
}

// A hundred failures in a row, from anywhere, turn the way of signing in
// off until somebody lets it work again; a success before that starts the
// count again and is told how many came before.
func TestTheCeilingDisablesUntilUnlocked(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "lockout.json")}
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	s.Succeed("lee", home, now)
	for i := 0; i < 5; i++ {
		s.Fail("lee", home, now)
	}
	if since, _ := s.Succeed("lee", home, now); since != 5 {
		t.Errorf("five failures before a success were told as %d", since)
	}
	var ev Event
	for i := 0; i < Ceiling; i++ {
		_, ev, _ = s.Fail("lee", home, now)
	}
	if ev != Disabled {
		t.Fatalf("the ceiling disabled nothing: %q", ev)
	}
	if d, _ := s.Check("lee", home, now.Add(48*time.Hour)); d.Allowed || !d.Disabled {
		t.Errorf("a disabled account worked from its own place, or after a wait: %+v", d)
	}
	if ok, _ := s.Unlock("lee", now); !ok {
		t.Fatal("unlock found nothing")
	}
	if d, _ := s.Check("lee", home, now); !d.Allowed {
		t.Errorf("unlocked and still refused: %+v", d)
	}
	if since, _ := s.Succeed("lee", home, now); since != Ceiling {
		t.Errorf("the failures before the unlock were told as %d", since)
	}
	if held, _ := s.Unlock("lee", now); held {
		t.Error("an account nobody held was reported unlocked")
	}
	if PlaceOf("2001:db8:1:2::5") != "2001:db8:1::/48" || PlaceOf("not an address") != "" {
		t.Errorf("places: %q %q", PlaceOf("2001:db8:1:2::5"), PlaceOf("not an address"))
	}
}

// An IPv6 client is placed, as the admin hands it over.
//
// The admin passes the source internal/clientip makes, which for IPv6 is
// the client's /64 written as a prefix. PlaceOf read that as no address, so
// an IPv6 guesser was never locked out, an IPv6 person never had a
// familiar place, and a guesser could run any account straight to the
// ceiling that turns its passkeys off. The tests above used host:port, which
// is not what arrives.
func TestAnIPv6ClientHasAPlace(t *testing.T) {
	src := func(s string) string { return clientip.Source(netip.MustParseAddr(s)) }
	home6, away6 := src("2001:db8:1:2::5"), src("2001:db8:ffff:9::7")
	if PlaceOf(home6) == "" || PlaceOf(home6) == PlaceOf(away6) {
		t.Fatalf("places: %q %q", PlaceOf(home6), PlaceOf(away6))
	}
	if PlaceOf(src("2001:db8:1:77::1")) != PlaceOf(home6) {
		t.Error("another /64 in the person's /48 was a stranger")
	}
	s := Store{Path: filepath.Join(t.TempDir(), "lockout.json")}
	now := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	if _, err := s.Succeed("dana", home6, now); err != nil {
		t.Fatal(err)
	}
	var ev Event
	for i := 0; i < Threshold; i++ {
		_, ev, _ = s.Fail("dana", away6, now)
	}
	if ev != Locked {
		t.Fatalf("ten failures from a strange IPv6 network locked nothing: %q", ev)
	}
	if d, _ := s.Check("dana", away6, now); d.Allowed {
		t.Errorf("the strange IPv6 network was not locked out: %+v", d)
	}
	if d, _ := s.Check("dana", home6, now); !d.Allowed {
		t.Errorf("the person's own IPv6 network was locked out: %+v", d)
	}
	// A source that cannot be placed at all is not familiar either.
	if d, _ := s.Check("dana", "unknown", now); d.Allowed {
		t.Errorf("an unplaceable source was let through a lockout: %+v", d)
	}
}
