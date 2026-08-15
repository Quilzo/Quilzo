package schedule

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

const c1 = "1111111111111111111111111111111111111111111111111111111111111111"
const c2 = "2222222222222222222222222222222222222222222222222222222222222222"

func TestSchedulingAndFiring(t *testing.T) {
	var s Schedule
	if err := s.Add(c1, now.Add(time.Hour), "dana", "embargo lifts", now); err != nil {
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
	if err := s.Add(c1, now.Add(time.Hour), "dana", "", now); err != nil {
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
	if err := s.Add(c1, now.Add(-time.Minute), "dana", "", now); err == nil {
		t.Fatal("a time in the past was accepted")
	}
}

func TestAnAbsurdlyDistantTimeIsRefused(t *testing.T) {
	var s Schedule
	err := s.Add(c1, now.Add(2*MaxAhead), "dana", "", now)
	if err == nil {
		t.Fatal("a publication two years out was accepted")
	}
	if !strings.Contains(err.Error(), "moved on") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

func TestTheSameCommitCannotBeScheduledTwice(t *testing.T) {
	var s Schedule
	if err := s.Add(c1, now.Add(time.Hour), "dana", "", now); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(c1, now.Add(2*time.Hour), "sam", "", now); err == nil {
		t.Error("the same commit was scheduled twice; which fires would depend " +
			"on ordering")
	}
	if err := s.Add(c2, now.Add(2*time.Hour), "sam", "", now); err != nil {
		t.Errorf("a second commit was refused: %v", err)
	}
}

func TestSomethingThatIsNotACommitIsRefused(t *testing.T) {
	var s Schedule
	for _, bad := range []string{
		"", "draft", "live", "abc", strings.Repeat("z", 64),
		strings.Repeat("1", 63), strings.Repeat("1", 65), "../etc",
	} {
		if err := s.Add(bad, now.Add(time.Hour), "dana", "", now); err == nil {
			t.Errorf("%q was accepted as a commit", bad)
		}
	}
}

// A schedule that deletes entries as it fires them leaves nobody able to answer
// "what went out on Friday and who decided that", which is the first question
// an audit asks.
func TestAFiredEntryStaysInTheRecord(t *testing.T) {
	var s Schedule
	if err := s.Add(c1, now.Add(time.Hour), "dana", "embargo", now); err != nil {
		t.Fatal(err)
	}
	s.Complete(c1, "published")

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
	if err := s.Add(c1, now.Add(time.Hour), "dana", "", now); err != nil {
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
