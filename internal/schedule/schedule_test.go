// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package schedule

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

const c1 = "1111111111111111111111111111111111111111111111111111111111111111"
const c2 = "2222222222222222222222222222222222222222222222222222222222222222"

func TestSchedulingAndFiring(t *testing.T) {
	var s Schedule
	if err := s.Add(c1, now.Add(time.Hour), Who{Name: "dana"}, "embargo lifts", now); err != nil {
		t.Fatal(err)
	}
	if len(s.Due(now)) != 0 {
		t.Error("an entry fired an hour early")
	}
	due := s.Due(now.Add(time.Hour))
	if len(due) != 1 || due[0].By != "dana" {
		t.Fatalf("got %#v", due)
	}
}

// A schedule names a commit rather than "the draft". An entry describing
// "whatever is current at nine on Friday" is a different and much worse
// instruction than the one somebody thought they were giving.
func TestAnEntryGoesStaleIfTheDraftMoves(t *testing.T) {
	var s Schedule
	if err := s.Add(c1, now.Add(time.Hour), Who{Name: "dana"}, "", now); err != nil {
		t.Fatal(err)
	}
	if states := s.Check(c1, now); states[0].Stale {
		t.Error("an entry matching the draft was reported stale")
	}
	states := s.Check(c2, now)
	if !states[0].Stale {
		t.Fatal("the draft moved and the entry was not reported stale; it would " +
			"publish content nobody has looked at since scheduling")
	}
	if states[0].Current != c2 {
		t.Error("the check does not report what the draft is now")
	}
}

// A past time either fires immediately or never, and which one should not
// depend on when a timer happens to run.
func TestAPastTimeIsRefused(t *testing.T) {
	var s Schedule
	if err := s.Add(c1, now.Add(-time.Minute), Who{Name: "dana"}, "", now); err == nil {
		t.Fatal("a time in the past was accepted")
	}
}

func TestAnAbsurdlyDistantTimeIsRefused(t *testing.T) {
	var s Schedule
	err := s.Add(c1, now.Add(2*MaxAhead), Who{Name: "dana"}, "", now)
	if err == nil {
		t.Fatal("a publication two years out was accepted")
	}
	if !strings.Contains(err.Error(), "moved on") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

func TestTheSameCommitCannotBeScheduledTwice(t *testing.T) {
	var s Schedule
	if err := s.Add(c1, now.Add(time.Hour), Who{Name: "dana"}, "", now); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(c1, now.Add(2*time.Hour), Who{Name: "sam"}, "", now); err == nil {
		t.Error("the same commit was scheduled twice; which fires would depend " +
			"on ordering")
	}
	if err := s.Add(c2, now.Add(2*time.Hour), Who{Name: "sam"}, "", now); err != nil {
		t.Errorf("a second commit was refused: %v", err)
	}
}

func TestSomethingThatIsNotACommitIsRefused(t *testing.T) {
	var s Schedule
	for _, bad := range []string{
		"", "draft", "live", "abc", strings.Repeat("z", 64),
		strings.Repeat("1", 63), strings.Repeat("1", 65), "../etc",
	} {
		if err := s.Add(bad, now.Add(time.Hour), Who{Name: "dana"}, "", now); err == nil {
			t.Errorf("%q was accepted as a commit", bad)
		}
	}
}

// A schedule that deletes entries as it fires them leaves nobody able to answer
// "what went out on Friday and who decided that", which is the first question
// an audit asks.
func TestAFiredEntryStaysInTheRecord(t *testing.T) {
	var s Schedule
	if err := s.Add(c1, now.Add(time.Hour), Who{Name: "dana"}, "embargo", now); err != nil {
		t.Fatal(err)
	}
	s.Complete(c1, "published", time.Now())

	if len(s.Pending(now)) != 0 {
		t.Error("a completed entry is still pending")
	}
	if len(s.Entries) != 1 {
		t.Fatal("the entry was deleted rather than completed")
	}
	if !s.Entries[0].Done || s.Entries[0].Result != "published" {
		t.Errorf("the outcome was not recorded: %#v", s.Entries[0])
	}
	if s.Entries[0].By != "dana" || s.Entries[0].Note != "embargo" {
		t.Error("who decided and why did not survive")
	}
}

// A cancel that removes the wrong entry is worse than one that removes none.
func TestCancellingNeedsAPrefixLongEnoughNotToCollide(t *testing.T) {
	var s Schedule
	if err := s.Add(c1, now.Add(time.Hour), Who{Name: "dana"}, "", now); err != nil {
		t.Fatal(err)
	}
	if s.Cancel("111") {
		t.Error("a three-character prefix cancelled something")
	}
	if !s.Cancel(c1[:12]) {
		t.Error("a twelve-character prefix did not cancel; that is the form the " +
			"tool prints")
	}
	if len(s.Pending(now)) != 0 {
		t.Error("the entry survived cancellation")
	}
	if s.Cancel("ffffffffffff") {
		t.Error("an unknown prefix cancelled something")
	}
}

// The next time to wake is the next entry still to come: not one already
// due, which a timer would wake for again at once, and not one that fired.
func TestNextIsTheNextEntryStillToCome(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var s Schedule
	if _, ok := s.Next(now); ok {
		t.Fatal("an empty schedule has a next time")
	}
	c1, c2, c3 := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	for _, e := range []struct {
		c  string
		in time.Duration
	}{{c1, 3 * time.Hour}, {c2, time.Hour}, {c3, 2 * time.Hour}} {
		if err := s.Add(e.c, now.Add(e.in), Who{Name: "dana", Verified: true}, "", now); err != nil {
			t.Fatal(err)
		}
	}
	if next, ok := s.Next(now); !ok || !next.Equal(now.Add(time.Hour)) {
		t.Fatalf("%v %v", next, ok)
	}
	// An hour on, c2 is due but not fired: the next to come is c3.
	if next, _ := s.Next(now.Add(time.Hour)); !next.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("woke for an entry already due: %v", next)
	}
	s.Complete(c3, "published", now.Add(2*time.Hour))
	if next, _ := s.Next(now.Add(time.Hour)); !next.Equal(now.Add(3 * time.Hour)) {
		t.Fatalf("woke for a fired entry: %v", next)
	}
	for _, e := range s.Entries {
		if e.Commit == c3 && (e.FiredAt != now.Add(2*time.Hour).Unix() || e.Result != "published") {
			t.Fatalf("%+v", e)
		}
		if e.Verified == nil || !*e.Verified || e.By != "dana" {
			t.Fatalf("who scheduled it was not kept: %+v", e)
		}
	}
}

// An entry being published is not due to anybody else, until its claim is
// old enough that whoever made it must have stopped.
func TestAClaimedEntryIsNotFiredTwice(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var s Schedule
	c := strings.Repeat("a", 64)
	if err := s.Add(c, now.Add(time.Minute), Who{Name: "dana", Verified: true}, "", now); err != nil {
		t.Fatal(err)
	}
	at := now.Add(2 * time.Minute)
	if !s.Claim(c, at) {
		t.Fatal("a due entry could not be claimed")
	}
	if len(s.Due(at)) != 0 || s.Claim(c, at.Add(time.Minute)) {
		t.Fatal("a claimed entry is due to somebody else")
	}
	if due := s.Due(at.Add(ClaimFor)); len(due) != 1 {
		t.Fatal("a claim nobody completed holds the entry for ever")
	}
	s.Complete(c, "published", at)
	if s.Entries[0].Claimed != 0 || len(s.Due(at.Add(ClaimFor))) != 0 {
		t.Fatalf("%+v", s.Entries[0])
	}
}

// What an audit record of scheduling says is one line, clipped whole: the
// command line cut it at a byte through an é, and the browser not at all.
func TestTheRecordOfSchedulingKeepsTheNoteWhole(t *testing.T) {
	note := "launch\n" + strings.Repeat("a", 192) + "é" + strings.Repeat("b", 100)
	d := Detail(c1, now.Add(time.Hour), note, "sam")
	got := d["note"]
	if !utf8.ValidString(got) || len(got) > MaxNote+len("…") || !strings.HasSuffix(got, "a…") || strings.Contains(got, "\n") {
		t.Errorf("the note was kept as %q (%d bytes)", got, len(got))
	}
	if d["scheduled"] != c1 || d["by"] != "sam" || d["at"] != "2026-08-15T13:00:00Z" {
		t.Errorf("%v", d)
	}
	if d := Detail(c1, now, "short", "sam"); d["note"] != "short" {
		t.Errorf("a short note was changed to %q", d["note"])
	}
}

// Queue tells a refusal, which is the person's to put right, from a
// schedule that could not be written, which is not.
func TestQueueTellsARefusalFromAFailure(t *testing.T) {
	sch := &Schedule{}
	update := func(fn func(*Schedule) error) error { return fn(sch) }
	if err := Queue(update, c1, now.Add(time.Hour), Who{Name: "sam"}, "", now); err != nil {
		t.Fatal(err)
	}
	var refused *Refused
	if err := Queue(update, c1, now.Add(2*time.Hour), Who{Name: "sam"}, "", now); !errors.As(err, &refused) {
		t.Errorf("scheduling one commit twice was %v, not a refusal", err)
	}
	broken := errors.New("disk full")
	if err := Queue(func(func(*Schedule) error) error { return broken }, c2, now.Add(time.Hour), Who{}, "", now); errors.As(err, &refused) || !errors.Is(err, broken) {
		t.Errorf("a schedule that could not be written was %v", err)
	}
	if err := Withdraw(update, c1[:12]); err != nil || len(sch.Pending(now)) != 0 {
		t.Errorf("withdrawing: %v, %d pending", err, len(sch.Pending(now)))
	}
	if err := Withdraw(update, c1[:12]); !errors.Is(err, ErrNothingPending) {
		t.Errorf("withdrawing what is not there: %v", err)
	}
}

func TestWhenIsATimeOrADuration(t *testing.T) {
	if at, err := ParseWhen("48h", now); err != nil || !at.Equal(now.Add(48*time.Hour)) {
		t.Errorf("48h: %v %v", at, err)
	}
	if at, err := ParseWhen("2026-09-01T09:00:00Z", now); err != nil || at.Format(time.RFC3339) != "2026-09-01T09:00:00Z" {
		t.Errorf("a timestamp: %v %v", at, err)
	}
	// Space around a time is not part of it, from any surface.
	if at, err := ParseWhen(" 48h\n", now); err != nil || !at.Equal(now.Add(48*time.Hour)) {
		t.Errorf("48h with space around it: %v %v", at, err)
	}
	sch := &Schedule{}
	if err := Queue(func(fn func(*Schedule) error) error { return fn(sch) }, c1, now.Add(time.Hour), Who{Name: "sam"}, "  launch\n", now); err != nil || sch.Entries[0].Note != "launch" {
		t.Errorf("the note was kept as %q: %v", sch.Entries[0].Note, err)
	}
	for _, s := range []string{"0s", "-1h", "soon", "", " "} {
		if _, err := ParseWhen(s, now); err == nil {
			t.Errorf("%q was read as a time", s)
		}
	}
}
