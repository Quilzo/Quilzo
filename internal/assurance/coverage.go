// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assurance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// What the evidence adds up to, and the four things it does not.
//
// Coverage is the union of a control's evidence intervals against the audit
// window, and the output that matters is the complement: the days for which
// this organisation has nothing to show. Everything else here exists to stop
// that number being quietly improved.

// MinObservations is how many occurrences a periodic control needs before
// the evidence shows it operating rather than having happened.
//
// Two. A quarterly access review with one occurrence in a six-month window
// has not been shown to operate, and auditors put it plainly: a window
// shorter than two cycles gives nothing to sample and no way to test around
// a gap.
const MinObservations = 2

// MinForUntested is how many passes make a run of passes suspicious.
//
// Twenty. Below that a control might simply not have been exercised yet;
// above it, a check that has never once returned a negative is the shape of
// a check pointed at the wrong thing.
const MinForUntested = 20

// Coverage is what a control's evidence shows over a period.
type Coverage struct {
	Control string `json:"control"`
	Period  Period `json:"period"`

	// Covered is how much of the period the evidence speaks to.
	Covered time.Duration `json:"covered"`
	// CoveredDays is the same in the unit the report speaks, because a
	// duration marshals as nanoseconds and nobody reads 15706901819006896.
	CoveredDays int `json:"covered_days"`
	// Gaps are the parts it does not, oldest first. The output that matters.
	Gaps []Period `json:"gaps,omitempty"`

	// Observations is how many pieces of evidence fall in the period, and
	// Failures how many of them recorded the control not working.
	Observations int `json:"observations"`
	Failures     int `json:"failures"`
	// Unobserved is evidence that could not tell either way, counted apart
	// from both because it is neither.
	Unobserved int `json:"unobserved"`

	// Expected is how many occurrences the cadence implies for this period,
	// and zero for a continuous or event-driven control.
	Expected int `json:"expected"`
	// Stale is evidence captured outside the period entirely, which is
	// reported rather than counted: last year's penetration test is real and
	// is not evidence about this year.
	Stale int `json:"stale,omitempty"`
}

// Share is how much of the period is covered, between 0 and 1.
//
// Not a compliance figure and not comparable between controls. It answers
// "how much of the window can this organisation speak to", which is a fact
// about the evidence rather than about the control.
func (c Coverage) Share() float64 {
	if c.Period.Length() <= 0 {
		return 0
	}
	return float64(c.Covered) / float64(c.Period.Length())
}

// Complete reports whether the evidence covers the whole period.
func (c Coverage) Complete() bool { return len(c.Gaps) == 0 }

// Proven reports whether a periodic control has enough occurrences to show
// it operating rather than having happened.
func (c Coverage) Proven() bool {
	if c.Expected == 0 {
		return c.Complete()
	}
	want := MinObservations
	if c.Expected < want {
		// A period too short to contain two occurrences cannot be evidence
		// of a cycle at all, whatever is in it. Saying so is more useful
		// than lowering the bar to whatever fits.
		want = c.Expected
	}
	return c.Observations >= want
}

// Untested reports whether a run of passes is long enough to be suspicious.
//
// The same argument internal/detect makes about a rule that has never
// matched: an automated check with four hundred passes and no failure is
// indistinguishable from one pointed at the wrong thing.
func (c Coverage) Untested() bool {
	return c.Observations >= MinForUntested && c.Failures == 0
}

// Why explains a coverage in one line, leading with what is missing.
func (c Coverage) Why() string {
	switch {
	case c.Observations == 0 && c.Stale > 0:
		return fmt.Sprintf(
			"nothing in the period. %d piece(s) of evidence exist and all "+
				"of them are about some other window", c.Stale)
	case c.Observations == 0:
		return "no evidence at all for this period"
	case !c.Complete() && c.Expected > 0 && !c.Proven():
		return fmt.Sprintf(
			"%d day(s) with nothing to show, and %d occurrence(s) where the "+
				"cadence implies %d", missingDays(c.Gaps), c.Observations,
			c.Expected)
	case !c.Complete():
		return fmt.Sprintf("%d day(s) with nothing to show, across %d gap(s)",
			missingDays(c.Gaps), len(c.Gaps))
	case c.Expected > 0 && !c.Proven():
		return fmt.Sprintf(
			"covered, and %d occurrence(s) where the cadence implies %d. "+
				"One occurrence shows a thing happened, not that it operates",
			c.Observations, c.Expected)
	case c.Untested():
		return fmt.Sprintf(
			"%d observation(s) and not one failure. That is either a control "+
				"that always works or a check that cannot report one",
			c.Observations)
	default:
		return fmt.Sprintf("covered, %d observation(s), %d failure(s)",
			c.Observations, c.Failures)
	}
}

func missingDays(in []Period) int {
	var total time.Duration
	for _, p := range in {
		total += p.Length()
	}
	return int(total.Hours() / 24)
}

// Measure works out what a control's evidence shows over a period.
func Measure(c Control, in []Evidence, period Period) Coverage {
	out := Coverage{Control: c.ID, Period: period}
	if !period.Valid() {
		return out
	}
	if every := c.Cadence.Every(); every > 0 {
		// Rounded, not truncated. A window described as two quarters is
		// rarely exactly two quarters long — a month is not thirty days, a
		// report runs a few minutes late — and truncating turns 1.99
		// quarters into one expected occurrence, which quietly halves the
		// bar a periodic control has to clear.
		out.Expected = int((period.Length() + every/2) / every)
		if out.Expected == 0 {
			out.Expected = 1
		}
	}

	var covers []Period
	for _, e := range in {
		if e.Control != c.ID {
			continue
		}
		clipped, ok := Period{From: e.From, To: e.To}.Overlap(period)
		if !ok {
			out.Stale++
			continue
		}
		out.Observations++
		switch e.Outcome {
		case Failed:
			out.Failures++
		case NotObserved:
			out.Unobserved++
			// Evidence that could not tell covers nothing. A scanner that
			// failed to reach a host has not shown the host compliant, and
			// counting its window as covered is the single easiest way to
			// make a gap disappear.
			continue
		}
		covers = append(covers, clipped)
	}
	for _, p := range merge(covers) {
		out.Covered += p.Length()
	}
	out.CoveredDays = int(out.Covered.Hours() / 24)
	out.Gaps = gaps(period, covers)
	return out
}

// Readiness is what a set of controls adds up to.
//
// Four counts and no percentage. A compliance score is controls-passing over
// controls-in-scope and scope is chosen by whoever wants the number; these
// are facts about the evidence, and the one that matters is Silent.
type Readiness struct {
	Period Period `json:"period"`
	// Controls is how many are in this set.
	Controls int `json:"controls"`
	// Covered have evidence for every day of the period.
	Covered int `json:"covered"`
	// Partial have some and not all.
	Partial int `json:"partial"`
	// Silent have none at all.
	//
	// The number to look at. A control with no evidence is indistinguishable
	// from a control nobody performs, and it is the one a dashboard showing
	// "98% of controls passing" leaves out of the denominator.
	Silent int `json:"silent"`
	// Unproven have coverage and too few occurrences for their cadence.
	Unproven int `json:"unproven"`
	// Untested have a long run of passes and no failure.
	Untested int `json:"untested"`
	// Unowned have nobody accountable.
	Unowned int `json:"unowned"`
}

// Why explains a readiness in one line, leading with the silent controls.
func (r Readiness) Why() string {
	if r.Controls == 0 {
		return "no controls"
	}
	if r.Silent > 0 {
		return fmt.Sprintf(
			"%d of %d control(s) have no evidence at all for %s. That is "+
				"the number a compliance percentage leaves out of its "+
				"denominator", r.Silent, r.Controls, r.Period)
	}
	if r.Partial > 0 {
		return fmt.Sprintf(
			"every control has some evidence for %s; %d of %d have gaps in "+
				"it", r.Period, r.Partial, r.Controls)
	}
	return fmt.Sprintf("%d control(s) with evidence across all of %s",
		r.Controls, r.Period)
}

// Assess measures every control and adds the result up.
func Assess(controls []Control, in []Evidence, period Period) (Readiness,
	[]Coverage) {

	out := Readiness{Period: period, Controls: len(controls)}
	var covs []Coverage
	for _, c := range controls {
		cov := Measure(c, in, period)
		covs = append(covs, cov)
		switch {
		case cov.Observations == 0:
			out.Silent++
		case cov.Complete():
			out.Covered++
		default:
			out.Partial++
		}
		if cov.Observations > 0 && cov.Expected > 0 && !cov.Proven() {
			out.Unproven++
		}
		if cov.Untested() {
			out.Untested++
		}
		if strings.TrimSpace(c.Owner) == "" {
			out.Unowned++
		}
	}
	sort.Slice(covs, func(i, j int) bool {
		if covs[i].Share() != covs[j].Share() {
			return covs[i].Share() < covs[j].Share()
		}
		return covs[i].Control < covs[j].Control
	})
	return out, covs
}

// Findings turns coverage into the register everything else works from.
func Findings(controls []Control, in []Evidence, period Period,
	now time.Time) []finding.Finding {

	byID := map[string]Control{}
	for _, c := range controls {
		byID[c.ID] = c
	}
	var out []finding.Finding
	add := func(c Control, sev telemetry.Severity, title, what string) {
		f := finding.Finding{
			Kind: finding.FromControl, Title: title, Source: "assurance",
			Entity:   telemetry.ID{Issuer: "control", Value: c.ID},
			Severity: sev, State: finding.Open, Seen: 1,
			Owner: c.Owner, First: period.From, Last: now,
			Evidence: []finding.Evidence{{
				At: now, Source: "assurance", What: what,
			}},
		}
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}

	_, covs := Assess(controls, in, period)
	for _, cov := range covs {
		c := byID[cov.Control]
		switch {
		case cov.Observations == 0 && cov.Stale > 0:
			add(c, telemetry.SeverityHigh,
				fmt.Sprintf("%s has evidence, and none of it is about %s",
					c.Name, period),
				fmt.Sprintf(
					"%d piece(s) of evidence exist for this control and all "+
						"of them fall outside the window. Last year's test "+
						"is real and is not evidence about this year",
					cov.Stale))
		case cov.Observations == 0:
			add(c, telemetry.SeverityHigh,
				fmt.Sprintf("%s has no evidence for %s", c.Name, period),
				"a control with no evidence is indistinguishable from a "+
					"control nobody performs, and it is the one a "+
					"percentage leaves out of its denominator")
		case !cov.Complete():
			add(c, severityOfGap(missingDays(cov.Gaps), period),
				fmt.Sprintf("%s has %d day(s) with nothing to show",
					c.Name, missingDays(cov.Gaps)),
				fmt.Sprintf("across %d gap(s): %s", len(cov.Gaps),
					describe(cov.Gaps)))
		}
		if cov.Observations > 0 && cov.Expected > 0 && !cov.Proven() {
			add(c, telemetry.SeverityMedium,
				fmt.Sprintf("%s happened %d time(s) where %s implies %d",
					c.Name, cov.Observations, c.Cadence, cov.Expected),
				"one occurrence shows a thing happened, not that it "+
					"operates. An auditor samples a population, and a "+
					"population of one is the thing being sampled")
		}
		if cov.Untested() {
			add(c, telemetry.SeverityLow,
				fmt.Sprintf("%s has %d observation(s) and not one failure",
					c.Name, cov.Observations),
				"either a control that always works or a check that cannot "+
					"report one. internal/detect refuses a rule that has "+
					"never matched for the same reason, and the two are "+
					"indistinguishable from the outside")
		}
		if cov.Unobserved > 0 {
			add(c, telemetry.SeverityLow,
				fmt.Sprintf("%s could not be observed %d time(s)",
					c.Name, cov.Unobserved),
				"a check that could not reach what it was pointed at has "+
					"not found it compliant and has not found it failing. "+
					"Those windows are counted as gaps rather than as "+
					"covered")
		}
		if strings.TrimSpace(c.Owner) == "" {
			add(c, telemetry.SeverityLow,
				fmt.Sprintf("%s has nobody accountable", c.Name),
				"a control with no owner is one whose evidence stops "+
					"arriving without anybody noticing that it has")
		}
	}
	return finding.Rank(out, now)
}

// severityOfGap scales with how much of the window is missing.
func severityOfGap(missing int, period Period) telemetry.Severity {
	days := period.Days()
	if days <= 0 {
		return telemetry.SeverityMedium
	}
	switch share := float64(missing) / float64(days); {
	case share >= 0.5:
		return telemetry.SeverityHigh
	case share >= 0.1:
		return telemetry.SeverityMedium
	default:
		return telemetry.SeverityLow
	}
}

// describe renders gaps the way a report does, at most three.
func describe(in []Period) string {
	var parts []string
	for i, p := range in {
		if i == 3 {
			return fmt.Sprintf("%s, and %d more",
				strings.Join(parts, "; "), len(in)-3)
		}
		parts = append(parts, p.String())
	}
	return strings.Join(parts, "; ")
}
