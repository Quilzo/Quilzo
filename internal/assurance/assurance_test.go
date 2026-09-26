// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assurance

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

var (
	now  = time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	half = Period{From: now.Add(-182 * 24 * time.Hour), To: now}
)

func day(n int) time.Time { return half.From.Add(time.Duration(n) * 24 * time.Hour) }

func span(from, to int) Period {
	return Period{From: day(from), To: day(to)}
}

func ev(control string, from, to int, o Outcome) Evidence {
	return Evidence{
		Control: control, From: day(from), To: day(to), Outcome: o,
		What: "an export showing the setting", Source: "connector:kandji",
		Ref: "audit:9f3a", At: day(to), By: "rashik", Kind: audit.KindHuman,
	}
}

func control(id string, c Cadence) Control {
	return Control{ID: id, Name: "review of " + id, Cadence: c,
		Owner: "rashik", Automated: true}
}

// The difference between this package and a folder of screenshots.
func TestASingleDayOfEvidenceLeavesTheRestOfThePeriodVisible(t *testing.T) {
	c := control("mfa", Continuous)
	// One export, covering one day, in the middle of a six-month window.
	cov := Measure(c, []Evidence{ev("mfa", 90, 91, Operated)}, half)

	if cov.Complete() {
		t.Fatal("one day of evidence covered a six-month period")
	}
	if len(cov.Gaps) != 2 {
		t.Fatalf("%d gaps, want the time before and the time after",
			len(cov.Gaps))
	}
	if missing := missingDays(cov.Gaps); missing != 181 {
		t.Errorf("%d days missing, want 181", missing)
	}
	if !strings.Contains(cov.Why(), "nothing to show") {
		t.Errorf("the summary does not lead with the gap: %q", cov.Why())
	}
}

func TestOverlappingEvidenceIsNotCountedTwice(t *testing.T) {
	c := control("logs", Continuous)
	cov := Measure(c, []Evidence{
		ev("logs", 0, 100, Operated),
		ev("logs", 50, 182, Operated),
		ev("logs", 60, 70, Operated),
	}, half)
	if !cov.Complete() {
		t.Fatalf("gaps remain: %v", cov.Gaps)
	}
	// 182 days, not 100 + 132 + 10.
	if got := cov.Covered; got != 182*24*time.Hour {
		t.Errorf("covered %s, want the period's own length", got)
	}
	if cov.Share() < 0.999 {
		t.Errorf("share is %.3f", cov.Share())
	}
}

func TestEvidenceOutsideTheWindowIsReportedRatherThanCounted(t *testing.T) {
	c := control("pentest", Annual)
	last := Evidence{
		Control: "pentest",
		From:    half.From.Add(-400 * 24 * time.Hour),
		To:      half.From.Add(-380 * 24 * time.Hour),
		Outcome: Operated, What: "last year's report",
		Source: "person:rashik", Ref: "obj:abc",
		At: half.From.Add(-380 * 24 * time.Hour), By: "rashik",
		Kind: audit.KindHuman,
	}
	cov := Measure(c, []Evidence{last}, half)
	if cov.Observations != 0 {
		t.Errorf("%d observations from evidence about another year",
			cov.Observations)
	}
	if cov.Stale != 1 {
		t.Errorf("%d stale", cov.Stale)
	}
	if !strings.Contains(cov.Why(), "some other window") {
		t.Errorf("the summary does not say why: %q", cov.Why())
	}
}

// A quarterly review with one occurrence in six months has been shown to
// have happened, not to operate.
func TestOneOccurrenceOfAPeriodicControlIsNotProof(t *testing.T) {
	c := control("access-review", Quarterly)
	one := Measure(c, []Evidence{ev("access-review", 0, 182, Operated)}, half)
	if !one.Complete() {
		t.Fatal("the window is not covered")
	}
	if one.Proven() {
		t.Fatal("one occurrence proved a quarterly control operates")
	}
	if one.Expected != 2 {
		t.Errorf("a six-month window implies %d quarters", one.Expected)
	}
	if !strings.Contains(one.Why(), "not that it operates") {
		t.Errorf("the summary does not say what is missing: %q", one.Why())
	}

	two := Measure(c, []Evidence{
		ev("access-review", 0, 91, Operated),
		ev("access-review", 91, 182, Operated),
	}, half)
	if !two.Proven() {
		t.Error("two quarters in a six-month window is still not proof")
	}
}

func TestAPeriodTooShortForTwoCyclesSaysSoRatherThanLoweringTheBar(t *testing.T) {
	c := control("annual-review", Annual)
	month := Period{From: now.Add(-30 * 24 * time.Hour), To: now}
	cov := Measure(c, []Evidence{{
		Control: "annual-review", From: month.From, To: month.To,
		Outcome: Operated, What: "the review", Source: "person:rashik",
		Ref: "obj:1", At: month.To, By: "rashik", Kind: audit.KindHuman,
	}}, month)
	if cov.Expected != 1 {
		t.Errorf("a month implies %d annual reviews", cov.Expected)
	}
	// One is all the window can hold, so one is enough — and the point is
	// that the window, not the evidence, is the limit.
	if !cov.Proven() {
		t.Error("a one-month window was held to a two-cycle standard")
	}
}

// internal/detect refuses a rule that has never matched. The same argument.
func TestAControlThatHasNeverFailedIsReported(t *testing.T) {
	c := control("backups", Daily)
	// Forty observations that tile the window, so the only thing left to
	// remark on is the run of passes itself.
	p := span(0, 160)
	var in []Evidence
	for n := range 40 {
		in = append(in, ev("backups", n*4, n*4+5, Operated))
	}
	cov := Measure(c, in, p)
	if !cov.Complete() {
		t.Fatalf("the fixture leaves gaps: %v", cov.Gaps)
	}
	if !cov.Untested() {
		t.Fatal("forty passes and no failure was not remarked on")
	}
	if !strings.Contains(cov.Why(), "cannot report one") {
		t.Errorf("the summary does not say what else it could be: %q",
			cov.Why())
	}

	// One failure among them and it stops being suspicious: the check has
	// been shown capable of saying no.
	in[7].Outcome = Failed
	if Measure(c, in, p).Untested() {
		t.Error("a check that has reported a failure is still untested")
	}

	// And a handful of passes is not enough to conclude anything.
	if Measure(c, in[:5], p).Untested() {
		t.Error("five passes were treated as a suspicious run")
	}
}

// The single easiest way to make a gap disappear.
func TestEvidenceThatCouldNotTellCoversNothing(t *testing.T) {
	c := control("disk-encryption", Continuous)
	cov := Measure(c, []Evidence{
		ev("disk-encryption", 0, 90, Operated),
		ev("disk-encryption", 90, 182, NotObserved),
	}, half)
	if cov.Complete() {
		t.Fatal("a scanner that could not reach the fleet covered half the " +
			"period")
	}
	if cov.Unobserved != 1 {
		t.Errorf("%d unobserved", cov.Unobserved)
	}
	if missing := missingDays(cov.Gaps); missing != 92 {
		t.Errorf("%d days missing, want the 92 nobody could see", missing)
	}
	// And it is neither a pass nor a failure.
	if cov.Failures != 0 {
		t.Error("an unobserved check was counted as a failure")
	}
}

func TestAFailedObservationStillCoversItsWindow(t *testing.T) {
	c := control("patching", Weekly)
	cov := Measure(c, []Evidence{
		ev("patching", 0, 91, Operated),
		ev("patching", 91, 182, Failed),
	}, half)
	// The control did not work, and we know what happened for those days.
	// Coverage is about whether there is anything to show, not about
	// whether the answer was the one anybody wanted.
	if !cov.Complete() {
		t.Fatalf("a recorded failure left a gap: %v", cov.Gaps)
	}
	if cov.Failures != 1 {
		t.Errorf("%d failures", cov.Failures)
	}
}

func TestEvidenceWithNothingToPointAtIsRefused(t *testing.T) {
	good := ev("mfa", 0, 10, Operated)
	for name, spoil := range map[string]func(*Evidence){
		"no reference": func(e *Evidence) { e.Ref = "" },
		"no source":    func(e *Evidence) { e.Source = "" },
		"no period":    func(e *Evidence) { e.From = time.Time{} },
		"backwards":    func(e *Evidence) { e.To = e.From.Add(-time.Hour) },
		"nobody":       func(e *Evidence) { e.By = "" },
		"a model":      func(e *Evidence) { e.Kind = audit.KindAI },
		"no outcome":   func(e *Evidence) { e.Outcome = "" },
	} {
		e := good
		spoil(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("evidence with %s was accepted", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("ordinary evidence was refused: %v", err)
	}
	// The one that matters most, checked for its words.
	e := good
	e.Ref = ""
	if err := e.Validate(); !strings.Contains(err.Error(), "is a claim") {
		t.Errorf("the refusal does not say what it is: %v", err)
	}
}

func TestAModelMayGatherEvidenceAndNotAttestToIt(t *testing.T) {
	e := ev("mfa", 0, 10, Operated)
	e.Kind = audit.KindAI
	err := e.Validate()
	if err == nil {
		t.Fatal("a model attested to evidence going to an auditor")
	}
	if !strings.Contains(err.Error(), "a person attests to it") {
		t.Errorf("the refusal does not say what to do instead: %v", err)
	}
}

func TestAControlWithNoCadenceIsRefused(t *testing.T) {
	for name, c := range map[string]Control{
		"no id":      {Name: "x", Cadence: Daily},
		"no name":    {ID: "a", Cadence: Daily},
		"no cadence": {ID: "a", Name: "x"},
		"invented cadence": {ID: "a", Name: "x",
			Cadence: Cadence("whenever")},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("a control with %s was accepted", name)
		}
	}
}

// The number a compliance percentage leaves out of its denominator.
func TestReadinessLeadsWithTheControlsThatHaveNothing(t *testing.T) {
	controls := []Control{
		control("mfa", Continuous), control("logs", Continuous),
		control("access-review", Quarterly), control("pentest", Annual),
	}
	in := []Evidence{
		ev("mfa", 0, 182, Operated),
		ev("logs", 0, 90, Operated),
		ev("access-review", 0, 91, Operated),
		ev("access-review", 91, 182, Operated),
	}
	r, covs := Assess(controls, in, half)
	if r.Controls != 4 {
		t.Fatalf("%d controls", r.Controls)
	}
	if r.Silent != 1 {
		t.Errorf("%d silent, want the one with nothing at all", r.Silent)
	}
	if r.Partial != 1 {
		t.Errorf("%d partial", r.Partial)
	}
	if r.Covered != 2 {
		t.Errorf("%d covered", r.Covered)
	}
	if !strings.Contains(r.Why(), "leaves out of its denominator") {
		t.Errorf("the summary does not say what is being hidden: %q",
			r.Why())
	}
	// Worst coverage first, so the thing to do is at the top.
	if covs[0].Control != "pentest" {
		t.Errorf("the list starts with %s", covs[0].Control)
	}
	if covs[len(covs)-1].Share() < covs[0].Share() {
		t.Error("the list is not ordered by how much is missing")
	}
}

func TestFindingsSayWhatIsMissingAndWhyItMatters(t *testing.T) {
	controls := []Control{
		control("pentest", Annual),
		{ID: "logs", Name: "log retention", Cadence: Continuous},
	}
	in := []Evidence{ev("logs", 0, 90, Operated)}
	out := Findings(controls, in, half, now)
	if len(out) == 0 {
		t.Fatal("nothing was found")
	}
	var silent, gap, unowned bool
	for _, f := range out {
		switch {
		case strings.Contains(f.Title, "no evidence for"):
			silent = true
			if f.Severity != telemetry.SeverityHigh {
				t.Errorf("a control with nothing is %v", f.Severity)
			}
			if !strings.Contains(f.Evidence[0].What, "denominator") {
				t.Errorf("the evidence does not say why: %q",
					f.Evidence[0].What)
			}
		case strings.Contains(f.Title, "day(s) with nothing to show"):
			gap = true
			if !strings.Contains(f.Evidence[0].What, "gap(s)") {
				t.Errorf("the gaps are not listed: %q", f.Evidence[0].What)
			}
		case strings.Contains(f.Title, "nobody accountable"):
			unowned = true
		}
	}
	if !silent || !gap || !unowned {
		t.Errorf("missing findings: silent=%v gap=%v unowned=%v",
			silent, gap, unowned)
	}
}

func TestAGapOfHalfThePeriodOutranksAGapOfADay(t *testing.T) {
	big := severityOfGap(120, half)
	small := severityOfGap(1, half)
	if big <= small {
		t.Errorf("120 missing days is %v and 1 is %v", big, small)
	}
	if small == telemetry.SeverityHigh {
		t.Error("a single missing day is high")
	}
}

func TestMergingAndGapsAreExactAtTheEdges(t *testing.T) {
	// Touching periods merge; a one-day hole does not vanish.
	got := merge([]Period{span(0, 10), span(10, 20), span(21, 30)})
	if len(got) != 2 {
		t.Fatalf("merged into %d periods: %v", len(got), got)
	}
	if !got[0].From.Equal(day(0)) || !got[0].To.Equal(day(20)) {
		t.Errorf("first merged period is %s", got[0])
	}

	holes := gaps(span(0, 30), []Period{span(0, 10), span(20, 30)})
	if len(holes) != 1 {
		t.Fatalf("%d gaps: %v", len(holes), holes)
	}
	if !holes[0].From.Equal(day(10)) || !holes[0].To.Equal(day(20)) {
		t.Errorf("the gap is %s, want day 10 to day 20", holes[0])
	}

	// Evidence entirely outside contributes nothing and does not shift the
	// period's own bounds.
	outside := gaps(span(10, 20), []Period{span(0, 5), span(25, 30)})
	if len(outside) != 1 || !outside[0].From.Equal(day(10)) ||
		!outside[0].To.Equal(day(20)) {
		t.Errorf("evidence outside the window changed the gap: %v", outside)
	}
	if len(gaps(span(0, 10), nil)) != 1 {
		t.Error("a period with no evidence has no gap")
	}
	if len(gaps(span(0, 10), []Period{span(-5, 15)})) != 0 {
		t.Error("evidence spanning the whole period left a gap")
	}
}

func TestEveryOutcomeReachesARealAuditLog(t *testing.T) {
	dir := t.TempDir()
	k, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(audit.Options{Path: dir + "/audit.jsonl", Key: k,
		Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range Outcomes() {
		e := ev("mfa", 0, 10, o)
		if verr := e.Validate(); verr != nil {
			t.Fatalf("%s: %v", o, verr)
		}
		if _, aerr := log.Append(e.Record()); aerr != nil {
			t.Fatalf("%s: %v", o, aerr)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(Outcomes()) {
		t.Fatalf("%d entries for %d outcomes", len(events), len(Outcomes()))
	}
	// A failure is a denial, so the occasions something did not work can be
	// searched for — which is the population an auditor samples.
	var denied int
	for _, e := range events {
		if e.Outcome == audit.Denied {
			denied++
		}
	}
	if denied != 1 {
		t.Errorf("%d denials for one failure", denied)
	}
}

func TestPeriodArithmeticIsReadable(t *testing.T) {
	p := span(0, 30)
	if p.Days() != 30 {
		t.Errorf("%d days", p.Days())
	}
	if !strings.Contains(p.String(), "-") {
		t.Errorf("a period reads as %q", p.String())
	}
	if !p.Valid() {
		t.Error("an ordinary period is invalid")
	}
	if (Period{}).Valid() {
		t.Error("an empty period is valid")
	}
	if _, ok := span(0, 10).Overlap(span(20, 30)); ok {
		t.Error("disjoint periods overlap")
	}
	got, ok := span(0, 20).Overlap(span(10, 30))
	if !ok || !got.From.Equal(day(10)) || !got.To.Equal(day(20)) {
		t.Errorf("overlap is %v (%v)", got, ok)
	}
	// Touching at a point is not an overlap: a period that ends where
	// another begins shares no time.
	if _, ok := span(0, 10).Overlap(span(10, 20)); ok {
		t.Error("periods that merely touch were reported as overlapping")
	}
}

func TestMeasuringAgainstAnEmptyPeriodProducesNothingRatherThanPanicking(t *testing.T) {
	cov := Measure(control("mfa", Continuous),
		[]Evidence{ev("mfa", 0, 10, Operated)}, Period{})
	if cov.Observations != 0 || cov.Share() != 0 {
		t.Errorf("an invalid period produced %+v", cov)
	}
	if len(cov.Gaps) != 0 {
		t.Errorf("an invalid period produced %d gap(s)", len(cov.Gaps))
	}
}

// Evidence always lags. A nightly export finishes at two in the morning and
// the report runs at nine, so the last seven hours are uncovered by
// construction — and printing "0 day(s) with nothing to show" trains whoever
// reads the gap list to skip it.
func TestASliverOfLaggingEvidenceIsNotReportedAsAGap(t *testing.T) {
	c := control("mfa", Continuous)
	// The window ends now; the evidence ends seven hours ago.
	p := Period{From: now.Add(-30 * 24 * time.Hour), To: now}
	cov := Measure(c, []Evidence{{
		Control: "mfa", From: p.From, To: now.Add(-7 * time.Hour),
		Outcome: Operated, What: "every account has a second factor",
		Source: "connector:okta", Ref: "audit:1", At: now, By: "rashik",
		Kind: audit.KindHuman,
	}}, p)

	if !cov.Complete() {
		t.Fatalf("seven hours of lag was reported as a gap: %v", cov.Gaps)
	}
	if strings.Contains(cov.Why(), "0 day(s)") {
		t.Errorf("the summary prints a gap of no days: %q", cov.Why())
	}
	// And the floor is on the report, not on the arithmetic: the share still
	// reflects what the evidence actually spans.
	if cov.Share() >= 1 {
		t.Errorf("share is %.4f; the missing hours were counted as covered",
			cov.Share())
	}

	// A real gap of two days still shows.
	real := Measure(c, []Evidence{{
		Control: "mfa", From: p.From, To: now.Add(-48 * time.Hour),
		Outcome: Operated, What: "x", Source: "s", Ref: "r", At: now,
		By: "rashik", Kind: audit.KindHuman,
	}}, p)
	if real.Complete() {
		t.Error("two days of nothing was swallowed by the floor")
	}
}

// A continuous control has no cadence, so nothing implies a number of
// occurrences and the report must not invent one.
func TestAContinuousControlIsNeverShortOfOccurrences(t *testing.T) {
	c := control("logs", Continuous)
	cov := Measure(c, []Evidence{ev("logs", 0, 90, Operated)}, half)
	if cov.Expected != 0 {
		t.Errorf("a continuous control expects %d occurrences", cov.Expected)
	}
	if strings.Contains(cov.Why(), "implies 0") {
		t.Errorf("the summary says a cadence implies nothing: %q", cov.Why())
	}
	// And it does not land in the unproven count either.
	r, _ := Assess([]Control{c}, []Evidence{ev("logs", 0, 90, Operated)},
		half)
	if r.Unproven != 0 {
		t.Errorf("%d unproven; a continuous control cannot be short of a "+
			"cadence it does not have", r.Unproven)
	}
}

// A window described as two quarters is rarely exactly two quarters long, and
// truncating the division quietly halves the bar a periodic control has to
// clear. Driving it turned up the cause: the caller read the clock twice, so
// a period meant to be 182 days was 182 days less a few hundred nanoseconds,
// and one occurrence of a quarterly control read as proven.
func TestAWindowFractionallyShortOfTwoCyclesStillExpectsTwo(t *testing.T) {
	c := control("access-review", Quarterly)
	short := Period{
		From: now.Add(-182*24*time.Hour + 141*time.Nanosecond),
		To:   now,
	}
	cov := Measure(c, []Evidence{{
		Control: "access-review", From: short.From, To: short.To,
		Outcome: Operated, What: "reviewed all 40 accounts",
		Source: "person:rashik", Ref: "obj:ar", At: short.To,
		By: "rashik", Kind: audit.KindHuman,
	}}, short)

	if cov.Expected != 2 {
		t.Fatalf("a window 141ns short of two quarters expects %d",
			cov.Expected)
	}
	if cov.Proven() {
		t.Error("one occurrence of a quarterly control read as proven")
	}
	if !strings.Contains(cov.Why(), "not that it operates") {
		t.Errorf("the summary does not say what is missing: %q", cov.Why())
	}
	// And the days are in the report's own unit, because a duration
	// marshals as nanoseconds and nobody reads 15706901819006896.
	if cov.CoveredDays != 181 && cov.CoveredDays != 182 {
		t.Errorf("covered days is %d", cov.CoveredDays)
	}
}
