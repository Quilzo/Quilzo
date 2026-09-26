// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package incident

import (
	"strings"
	"testing"
	"time"
)

// A Monday, so the business-day arithmetic is testable.
var t0 = time.Date(2026, 9, 21, 9, 0, 0, 0, time.UTC)

func declared(t *testing.T, regimes ...string) *Incident {
	t.Helper()
	i, err := Declare("inc-1", "data leaving an s3 bucket", Sev1, "ada",
		t0, regimes...)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func ladder() Ladder {
	return Ladder{Name: "security", Rungs: []Rung{
		{Who: []string{"oncall-1"}, After: 5 * time.Minute,
			Why: "primary"},
		{Who: []string{"oncall-2"}, After: 5 * time.Minute,
			Why: "secondary"},
		{Who: []string{"head-of-security"}, Why: "last resort"},
	}}
}

// TestEveryClockStartsFromADecision is the whole idea.
func TestEveryClockStartsFromADecision(t *testing.T) {
	i := declared(t, "eu", "sec")

	// Nothing is due, and that is not the same as nothing being owed.
	unstarted := i.Unstarted(t0)
	if len(unstarted) == 0 {
		t.Fatal("no obligations reported as unstarted")
	}
	for _, d := range unstarted {
		if d.Started {
			t.Fatalf("%s is both started and unstarted", d.Regime)
		}
		if !strings.Contains(d.Says(), "not the same as nothing being due") {
			t.Fatalf("says = %q", d.Says())
		}
	}

	// Awareness starts the GDPR clock and not the SEC one.
	if err := i.Decide(Aware, "ada",
		"the access log shows objects read by an unknown key", t0); err != nil {
		t.Fatal(err)
	}
	var gdpr, sec Duty
	for _, d := range i.Duties(t0) {
		switch d.Regime {
		case "GDPR Article 33":
			gdpr = d
		case "SEC Item 1.05":
			sec = d
		}
	}
	if !gdpr.Started {
		t.Fatal("awareness did not start the Article 33 clock")
	}
	if !gdpr.Due.Equal(t0.Add(72 * time.Hour)) {
		t.Fatalf("due %s, want %s", gdpr.Due, t0.Add(72*time.Hour))
	}
	if sec.Started {
		t.Fatal("awareness started the SEC clock, which runs from " +
			"determining materiality")
	}
	if !strings.Contains(sec.Says(), "material") {
		t.Fatalf("the SEC duty does not name its trigger: %q", sec.Says())
	}
}

// TestFourBusinessDaysSkipsTheWeekend.
func TestFourBusinessDaysSkipsTheWeekend(t *testing.T) {
	i := declared(t, "sec")
	// Determined material on the Thursday.
	thu := t0.Add(3 * 24 * time.Hour)
	if thu.Weekday() != time.Thursday {
		t.Fatalf("the fixture starts on %s", t0.Weekday())
	}
	if err := i.Decide(Material, "ada", "a reasonable investor would "+
		"consider this important", thu); err != nil {
		t.Fatal(err)
	}
	var sec Duty
	for _, d := range i.Duties(thu) {
		if d.Regime == "SEC Item 1.05" {
			sec = d
		}
	}
	// Thursday + 4 business days = Wednesday, not Monday.
	if sec.Due.Weekday() != time.Wednesday {
		t.Fatalf("due on a %s; four business days from Thursday is the "+
			"following Wednesday", sec.Due.Weekday())
	}
	if sec.Due.Sub(thu) != 6*24*time.Hour {
		t.Fatalf("elapsed = %s, want six calendar days", sec.Due.Sub(thu))
	}
}

// TestDORAIsTheShortestAndRunsFromClassification.
func TestDORAIsTheShortestAndRunsFromClassification(t *testing.T) {
	i := declared(t, "dora")
	if err := i.Decide(Aware, "ada", "it is plainly an incident",
		t0); err != nil {
		t.Fatal(err)
	}
	for _, d := range i.Duties(t0) {
		if d.Regime == "DORA" && d.Started {
			t.Fatal("awareness started the DORA clock; it runs from " +
				"classification as major")
		}
	}
	at := t0.Add(2 * time.Hour)
	if err := i.Decide(Major, "ada", "it meets the thresholds",
		at); err != nil {
		t.Fatal(err)
	}
	for _, d := range i.Duties(at) {
		if d.Regime != "DORA" {
			continue
		}
		if !d.Due.Equal(at.Add(4 * time.Hour)) {
			t.Fatalf("due %s", d.Due)
		}
		if !strings.Contains(d.Note, "classification") {
			t.Fatalf("the note does not say what catches people out: %q",
				d.Note)
		}
	}
}

// TestAClockCannotBeMovedAfterwards.
func TestAClockCannotBeMovedAfterwards(t *testing.T) {
	i := declared(t, "eu")
	if err := i.Decide(Aware, "ada", "the log", t0); err != nil {
		t.Fatal(err)
	}
	err := i.Decide(Aware, "grace", "actually it was later",
		t0.Add(48*time.Hour))
	if err == nil {
		t.Fatal("the start of a clock was moved")
	}
	if !strings.Contains(err.Error(), "cannot be innocent") {
		t.Fatalf("%v", err)
	}
	if err := i.Decide(Aware, "", "", t0); err == nil {
		t.Fatal("a decision with no reason was recorded")
	}
}

// TestAPageNobodyAnsweredIsNotANotification.
func TestAPageNobodyAnsweredIsNotANotification(t *testing.T) {
	i := declared(t, "eu")
	l := ladder()
	if err := i.Raise(l, t0); err != nil {
		t.Fatal(err)
	}
	if i.Engaged() {
		t.Fatal("sending a page is not somebody having it")
	}
	if len(i.Unanswered()) != 1 {
		t.Fatalf("%d unanswered", len(i.Unanswered()))
	}

	// Too soon to escalate.
	moved, err := i.Escalate(l, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if moved {
		t.Fatal("escalated inside the wait")
	}
	// Past the wait: up a rung.
	moved, err = i.Escalate(l, t0.Add(6*time.Minute))
	if err != nil || !moved {
		t.Fatalf("did not escalate: %v", err)
	}
	if i.Pages[1].Who[0] != "oncall-2" {
		t.Fatalf("escalated to %v", i.Pages[1].Who)
	}
	// And again, to the end.
	if _, err := i.Escalate(l, t0.Add(12*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !i.Exhausted(l) {
		t.Fatal("the ladder ran out and did not say so")
	}
	trouble := i.Look(l, t0.Add(15*time.Minute))
	if len(trouble) == 0 || trouble[0].Weight != NobodyHasIt {
		t.Fatalf("the worst thing is %+v", trouble)
	}
	if !strings.Contains(trouble[0].Detail, "somebody noticing") {
		t.Fatalf("detail = %q", trouble[0].Detail)
	}

	// An acknowledgement from anybody stops it.
	if err := i.Ack("grace", t0.Add(16*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !i.Engaged() || i.Exhausted(l) {
		t.Fatal("an acknowledgement did not engage")
	}
	if i.Silence(t0.Add(time.Hour)) != 0 {
		t.Fatal("silence continued after somebody took it")
	}
}

// TestALadderThatDoesNotEscalateIsRefused.
func TestALadderThatDoesNotEscalateIsRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		l    Ladder
		says string
	}{
		{"one rung", Ladder{Name: "x", Rungs: []Rung{
			{Who: []string{"a"}}}}, "does not escalate"},
		{"no wait", Ladder{Name: "x", Rungs: []Rung{
			{Who: []string{"a"}}, {Who: []string{"b"}}}}, "at once"},
		{"waits too long", Ladder{Name: "x", Rungs: []Rung{
			{Who: []string{"a"}, After: time.Hour},
			{Who: []string{"b"}}}}, "time that mattered"},
		{"last rung waits", Ladder{Name: "x", Rungs: []Rung{
			{Who: []string{"a"}, After: time.Minute},
			{Who: []string{"b"}, After: time.Minute}}}, "and then does what"},
		{"the same person twice", Ladder{Name: "x", Rungs: []Rung{
			{Who: []string{"a"}, After: time.Minute},
			{Who: []string{"a"}}}}, "pretending to escalate"},
		{"nobody", Ladder{Name: "x", Rungs: []Rung{
			{Who: nil, After: time.Minute}, {Who: []string{"b"}}}},
			"pages nobody"},
	} {
		if err := c.l.Validate(); err == nil {
			t.Errorf("%s: accepted", c.name)
		} else if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := ladder().Validate(); err != nil {
		t.Fatalf("a good ladder was refused: %v", err)
	}
}

// TestOnePersonCannotBeCommanderAndScribe.
func TestOnePersonCannotBeCommanderAndScribe(t *testing.T) {
	i := declared(t, "eu")
	if err := i.Assign(Commander, "ada", t0); err != nil {
		t.Fatal(err)
	}
	if err := i.Assign(Scribe, "ada", t0); err == nil {
		t.Fatal("one person took both roles")
	}
	if err := i.Assign(Scribe, "grace", t0); err != nil {
		t.Fatal(err)
	}
	if len(i.Unfilled()) != 1 || i.Unfilled()[0] != Comms {
		t.Fatalf("unfilled = %v", i.Unfilled())
	}
	// A sev1 with no commander is reported.
	bare := declared(t, "eu")
	found := false
	for _, tr := range bare.Look(ladder(), t0) {
		if tr.Weight == NoCommander {
			found = true
		}
	}
	if !found {
		t.Fatal("a sev1 with nobody commanding was not reported")
	}
}

// TestLateAndImminentAreRanked.
func TestLateAndImminentAreRanked(t *testing.T) {
	i := declared(t, "eu", "nis2")
	if err := i.Decide(Aware, "ada", "the log", t0); err != nil {
		t.Fatal(err)
	}
	// 25 hours in: the NIS2 early warning is late, Article 33 is not.
	now := t0.Add(25 * time.Hour)
	var late, fine int
	for _, d := range i.Duties(now) {
		if d.Late() {
			late++
		}
		if d.Started && !d.Late() && d.Within > 0 {
			fine++
		}
	}
	if late != 1 {
		t.Fatalf("%d late at 25 hours; only the 24-hour one should be", late)
	}
	if fine == 0 {
		t.Fatal("nothing is still in time")
	}
	trouble := i.Look(ladder(), now)
	if len(trouble) == 0 || trouble[0].Weight != Overdue {
		t.Fatalf("trouble = %+v", trouble)
	}

	// Inside the hour before Article 33 is due.
	soon := t0.Add(71*time.Hour + 30*time.Minute)
	found := false
	for _, d := range i.Pressing(soon) {
		if d.Regime == "GDPR Article 33" && d.Soon() {
			found = true
		}
	}
	if !found {
		t.Fatal("a deadline half an hour away was not pressing")
	}
}

// TestArticle34HasNoDeadlineAndSaysWhy.
func TestArticle34HasNoDeadlineAndSaysWhy(t *testing.T) {
	i := declared(t, "eu")
	if err := i.Decide(Personal, "ada", "the objects were customer records",
		t0); err != nil {
		t.Fatal(err)
	}
	for _, d := range i.Duties(t0) {
		if d.Regime != "GDPR Article 34" {
			continue
		}
		if !d.Started {
			t.Fatal("confirming personal data did not start Article 34")
		}
		if !d.Due.IsZero() || d.Late() {
			t.Fatal("Article 34 has no deadline and cannot be late")
		}
		if !strings.Contains(d.Says(), "without undue delay") {
			t.Fatalf("says = %q", d.Says())
		}
		if !strings.Contains(d.Note, "telling people badly") {
			t.Fatalf("note = %q", d.Note)
		}
	}
}

// TestClosingRefusesWhileAnythingIsOwed.
func TestClosingRefusesWhileAnythingIsOwed(t *testing.T) {
	i := declared(t, "eu")
	if err := i.Decide(Aware, "ada", "the log", t0); err != nil {
		t.Fatal(err)
	}
	at := t0.Add(2 * time.Hour)

	if err := i.Close("ada", "", []string{"a"}, at); err == nil {
		t.Fatal("closed with no cause")
	}
	if err := i.Close("ada", "a key leaked", nil, at); err == nil {
		t.Fatal("closed with no actions")
	}
	err := i.Close("ada", "a key leaked in a build log",
		[]string{"rotate the key"}, at)
	if err == nil {
		t.Fatal("closed over an outstanding obligation")
	}
	if !strings.Contains(err.Error(), "quietly become nobody's") {
		t.Fatalf("%v", err)
	}

	// Discharge one and rule the other out.
	if err := i.Discharge("GDPR Article 33", "ada",
		"notified at 11:40, reference ABC", at); err != nil {
		t.Fatal(err)
	}
	if err := i.Waive("GDPR Article 34", "ada",
		"the objects were encrypted and the key was not in the same "+
			"place, so Article 34(3)(a) applies", at); err != nil {
		t.Fatal(err)
	}
	if err := i.Close("ada", "a key leaked in a build log",
		[]string{"rotate the key", "stop printing env in CI"},
		at); err != nil {
		t.Fatalf("still refused: %v", err)
	}
	if i.State != Closed {
		t.Fatalf("state = %s", i.State)
	}

	// Discharged and waived are different statements.
	for _, d := range i.Duties(at) {
		switch d.Regime {
		case "GDPR Article 33":
			if !d.Done || d.Waived {
				t.Fatal("a notification was recorded as not applicable")
			}
		case "GDPR Article 34":
			if !d.Waived || d.Done {
				t.Fatal("a decision not to notify was recorded as having " +
					"notified")
			}
			if !strings.Contains(d.Why, "34(3)(a)") {
				t.Fatalf("why = %q", d.Why)
			}
		}
	}
	if err := i.Discharge("nonsense", "ada", "x", at); err == nil {
		t.Fatal("an obligation that is not in the table was discharged")
	}
	if err := i.Waive("GDPR Article 33", "ada", "", at); err == nil {
		t.Fatal("an anonymous waiver was accepted")
	}
}

// TestOnlyTheRegimesYouAreInApply.
func TestOnlyTheRegimesYouAreInApply(t *testing.T) {
	eu := declared(t, "eu")
	for _, d := range eu.Duties(t0) {
		if d.Scope != "eu" {
			t.Fatalf("an eu-only incident has a %s duty", d.Scope)
		}
	}
	none := declared(t)
	if len(none.Duties(t0)) != 0 {
		t.Fatal("an incident in no regime has duties")
	}
}

// TestTheTimelineIsOrderedByTheIncidentNotTheClock.
func TestTheTimelineIsOrderedByTheIncidentNotTheClock(t *testing.T) {
	i := declared(t, "eu")
	if err := i.Note("grace", "checked the bucket policy",
		t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := i.Note("alan", "clock is wrong on this box",
		t0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	tl := i.Timeline()
	if len(tl) < 3 {
		t.Fatalf("%d entries", len(tl))
	}
	for n := 1; n < len(tl); n++ {
		if tl[n].Order() <= tl[n-1].Order() {
			t.Fatal("the timeline is not in the incident's own order")
		}
	}
	if !strings.Contains(tl[len(tl)-1].What, "clock is wrong") {
		t.Fatalf("the clocks won: %q", tl[len(tl)-1].What)
	}
}
