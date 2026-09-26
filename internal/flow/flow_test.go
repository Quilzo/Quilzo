// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package flow

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC)

func aFlow() Flow {
	return Flow{
		Name: "incidents", What: "page the on-call for new criticals",
		Every: time.Hour,
		Steps: []Step{
			{Name: "only criticals", Kind: Keep,
				Rejects: &Exit{Kind: Drop, Why: "not worth a page at night"}},
			{Name: "add the runbook", Kind: Change},
			{Name: "page the on-call", Kind: Act, Reaches: "pagerduty",
				Retries: 3},
		},
	}
}

// TestAFilterMustSayWhereItsRejectsGo is the Zapier failure, refused at
// definition time rather than discovered in a log.
func TestAFilterMustSayWhereItsRejectsGo(t *testing.T) {
	f := aFlow()
	f.Steps[0].Rejects = nil
	err := f.Validate()
	if err == nil {
		t.Fatal("a filter with nowhere for its rejects to go was accepted")
	}
	if !strings.Contains(err.Error(), "only criticals") {
		t.Fatalf("the refusal does not name the filter: %v", err)
	}

	// Dropping is allowed, and has to be explained.
	f.Steps[0].Rejects = &Exit{Kind: Drop}
	if err := f.Validate(); err == nil {
		t.Fatal("an unexplained drop was accepted")
	}
	f.Steps[0].Rejects = &Exit{Kind: Drop, Why: "duplicates"}
	if err := f.Validate(); err != nil {
		t.Fatalf("an explained drop was refused: %v", err)
	}
	// Diverting has to name a destination.
	f.Steps[0].Rejects = &Exit{Kind: Divert}
	if err := f.Validate(); err == nil {
		t.Fatal("a divert to nowhere was accepted")
	}
}

func TestAFlowMustSayHowOftenItRuns(t *testing.T) {
	f := aFlow()
	f.Every = 0
	err := f.Validate()
	if err == nil {
		t.Fatal("a flow with no expected cadence was accepted")
	}
	if !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("the refusal does not say why it matters: %v", err)
	}
}

func TestAFlowThatNeverActsSaysSo(t *testing.T) {
	f := aFlow()
	f.Steps = f.Steps[:2]
	if err := f.Validate(); err == nil {
		t.Fatal("a flow that only filters was accepted as an automation")
	}
}

func TestStepValidation(t *testing.T) {
	for _, c := range []struct {
		name string
		s    Step
	}{
		{"no name", Step{Kind: Act, Reaches: "x"}},
		{"no kind", Step{Name: "a"}},
		{"act with no reach", Step{Name: "a", Kind: Act}},
		{"rejects on a change", Step{Name: "a", Kind: Change,
			Rejects: &Exit{Kind: Hold}}},
		{"retries on a filter", Step{Name: "a", Kind: Keep, Retries: 2,
			Rejects: &Exit{Kind: Hold}}},
		{"too many retries", Step{Name: "a", Kind: Act, Reaches: "x",
			Retries: MaxRetries + 1}},
	} {
		if err := c.s.Validate(); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	dup := aFlow()
	dup.Steps[1].Name = "only criticals"
	if err := dup.Validate(); err == nil {
		t.Fatal("two steps with one name were accepted")
	}
}

// TestARunThatLosesThingsIsTheFailure.
func TestARunThatLosesThingsIsTheFailure(t *testing.T) {
	f := aFlow()
	r := Run{Flow: f.Name, Started: t0, In: 100, Acted: 3}
	if err := r.Reject(f.Steps[0], 40); err != nil {
		t.Fatal(err)
	}
	if r.Balances() {
		t.Fatal("43 of 100 balanced")
	}
	if r.Unaccounted() != 57 {
		t.Fatalf("unaccounted = %d", r.Unaccounted())
	}
	err := r.Check()
	if err == nil {
		t.Fatal("a run that lost 57 items passed")
	}
	if !strings.Contains(err.Error(), "57") ||
		!strings.Contains(err.Error(), "quietly") {
		t.Fatalf("the refusal is not specific: %v", err)
	}

	// Account for the rest and it passes.
	if err := r.Reject(f.Steps[0], 55); err != nil {
		t.Fatal(err)
	}
	r.Fail("page the on-call", "inc-9", "rate limited", 3)
	r.Held = 1
	if err := r.Check(); err != nil {
		t.Fatalf("a balanced run was refused: %v", err)
	}
	if r.Out() != 100 {
		t.Fatalf("out = %d", r.Out())
	}
}

// TestCountingSomethingTwiceIsAlsoABug.
func TestCountingSomethingTwiceIsAlsoABug(t *testing.T) {
	r := Run{Flow: "x", In: 5, Acted: 9}
	err := r.Check()
	if err == nil {
		t.Fatal("a run that did more than it received passed")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Fatalf("the refusal does not name the bug: %v", err)
	}
}

// TestQuietIsNotTheSameAsDiscarding — conflating them is how a filter that
// started matching everything goes unnoticed for a month.
func TestQuietIsNotTheSameAsDiscarding(t *testing.T) {
	quiet := Run{Flow: "x", In: 0}
	if !quiet.Quiet() || quiet.Why() != "nothing arrived" {
		t.Fatalf("quiet run: %q", quiet.Why())
	}
	f := aFlow()
	busy := Run{Flow: "x", In: 100}
	if err := busy.Reject(f.Steps[0], 100); err != nil {
		t.Fatal(err)
	}
	if busy.Quiet() {
		t.Fatal("a run that discarded a hundred items reported as quiet")
	}
	why := busy.Why()
	if !strings.Contains(why, "none were acted on") ||
		!strings.Contains(why, "only criticals dropped 100") {
		t.Fatalf("why = %q", why)
	}
	if !strings.Contains(why, "not worth a page") {
		t.Fatalf("the stated reason for the drop is missing: %q", why)
	}
}

// TestGapsFindWhatPollingMissed.
func TestGapsFindWhatPollingMissed(t *testing.T) {
	hour := func(n int) time.Time {
		return t0.Add(time.Duration(n) * time.Hour)
	}
	runs := []Run{
		{Flow: "x", Started: hour(1), From: hour(0), To: hour(1)},
		{Flow: "x", Started: hour(2), From: hour(1), To: hour(2)},
		// The source was busy and this run started late, from where it
		// happened to be rather than where the last one stopped.
		{Flow: "x", Started: hour(5), From: hour(4), To: hour(5)},
		{Flow: "x", Started: hour(6), From: hour(5), To: hour(6)},
	}
	g := Gaps(runs)
	if len(g) != 1 {
		t.Fatalf("%d gap(s)", len(g))
	}
	if g[0].For != 2*time.Hour {
		t.Fatalf("gap = %s", g[0].For)
	}
	if !g[0].From.Equal(hour(2)) || !g[0].To.Equal(hour(4)) {
		t.Fatalf("gap is %s to %s", g[0].From, g[0].To)
	}
	// Overlapping windows lose nothing.
	overlap := []Run{
		{From: hour(0), To: hour(2)},
		{From: hour(1), To: hour(3)},
	}
	if len(Gaps(overlap)) != 0 {
		t.Fatal("overlapping windows reported a gap")
	}
	// Runs with no window are not evidence either way.
	if len(Gaps([]Run{{Started: hour(1)}, {Started: hour(9)}})) != 0 {
		t.Fatal("runs with no window produced a gap")
	}
}

// TestSilenceIsAFailure.
func TestSilenceIsAFailure(t *testing.T) {
	f := aFlow() // every hour
	if over, _ := f.Overdue(t0, t0.Add(time.Hour)); over {
		t.Fatal("a flow exactly on time was overdue")
	}
	if over, _ := f.Overdue(t0, t0.Add(80*time.Minute)); over {
		t.Fatal("a flow inside its grace was overdue")
	}
	over, by := f.Overdue(t0, t0.Add(4*time.Hour))
	if !over || by != 3*time.Hour {
		t.Fatalf("overdue = %v by %s", over, by)
	}
	if over, _ := f.Overdue(time.Time{}, t0); !over {
		t.Fatal("a flow that has never run is not overdue")
	}
}

// TestTroubleIsRankedNotThresholded.
func TestTroubleIsRankedNotThresholded(t *testing.T) {
	f := aFlow()
	hour := func(n int) time.Time {
		return t0.Add(time.Duration(n) * time.Hour)
	}
	lost := Run{Flow: f.Name, Started: hour(1), From: hour(0), To: hour(1),
		In: 10, Acted: 2}
	broke := Run{Flow: f.Name, Started: hour(4), From: hour(3), To: hour(4),
		In: 2, Acted: 0}
	broke.Fail("page the on-call", "inc-1", "rate limited", 3)
	broke.Fail("page the on-call", "inc-2", "rate limited", 3)
	broke.Held = 0
	// broke: 2 in, 0 acted, 2 failed — balances.

	got := f.Look([]Run{lost, broke}, hour(5))
	if len(got) < 3 {
		t.Fatalf("%d trouble(s): %+v", len(got), got)
	}
	if got[0].Weight != Lost {
		t.Fatalf("the worst is %s at %d, want lost", got[0].What,
			got[0].Weight)
	}
	var sawGap, sawBroke bool
	for _, tr := range got {
		if tr.Weight == Missed {
			sawGap = true
		}
		if tr.Weight == Broke {
			sawBroke = true
			if !strings.Contains(tr.Detail, "rate limited") ||
				!strings.Contains(tr.Detail, "page the on-call") {
				t.Fatalf("a failure without a diagnosis: %q", tr.Detail)
			}
		}
	}
	if !sawGap {
		t.Fatal("the two-hour gap between the runs was not reported")
	}
	if !sawBroke {
		t.Fatal("the failures were not reported")
	}
	for i := 1; i < len(got); i++ {
		if got[i].Weight > got[i-1].Weight {
			t.Fatal("trouble is not ranked")
		}
	}
}

// TestAFlowRunningAndDiscardingEverything is the failure that looks most
// like success.
func TestAFlowRunningAndDiscardingEverything(t *testing.T) {
	f := aFlow()
	var runs []Run
	for i := range 3 {
		r := Run{Flow: f.Name, Started: t0.Add(time.Duration(i) * time.Hour),
			In: 20}
		if err := r.Reject(f.Steps[0], 20); err != nil {
			t.Fatal(err)
		}
		if err := r.Check(); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, r)
	}
	got := f.Look(runs, t0.Add(2*time.Hour+30*time.Minute))
	found := false
	for _, tr := range got {
		if tr.Weight == Discarding {
			found = true
			if !strings.Contains(tr.What, "3 run(s)") ||
				!strings.Contains(tr.What, "60 item(s)") {
				t.Fatalf("what = %q", tr.What)
			}
		}
	}
	if !found {
		t.Fatal("a flow that ran three times and did nothing was reported " +
			"as healthy")
	}

	// A busy hour in the middle breaks the streak, and one barren run on
	// its own is not evidence of anything.
	runs[1].Acted = 20
	for _, tr := range f.Look(runs, t0.Add(150*time.Minute)) {
		if tr.Weight == Discarding {
			t.Fatalf("a single barren run was reported: %q", tr.What)
		}
	}
	// A quiet run does not break a streak. Nothing arrived, so nothing
	// happening is the correct outcome and is not evidence that whatever
	// was discarding things has recovered.
	runs[1] = Run{Flow: f.Name, Started: runs[1].Started, In: 0}
	if n, items := barren(runs); n != 2 || items != 40 {
		t.Fatalf("a quiet run in the middle gave a streak of %d over %d "+
			"item(s); it should join the two barren runs either side",
			n, items)
	}
}

func TestDropsAndReachesAreListable(t *testing.T) {
	f := aFlow()
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	d := f.Drops()
	if len(d) != 1 || d[0].Name != "only criticals" {
		t.Fatalf("drops = %+v", d)
	}
	r := f.Reaches()
	if len(r) != 1 || r[0] != "pagerduty" {
		t.Fatalf("reaches = %v", r)
	}
}
