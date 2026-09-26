// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package assurance is evidence that a control operated over a period,
// rather than a screenshot of it working once.
//
// # What every compliance tool collects, and why it does not answer the
// question
//
// The product category is "continuous compliance" and the artefact is a
// screenshot. A picture of an MFA setting taken on 14 January is evidence
// about 14 January. The question an auditor asks is whether the control
// operated effectively *throughout the period* — that is the language of a
// SOC 2 Type II and of ISO 27001's operating effectiveness — and no
// point-in-time artefact answers it, however many of them there are.
//
// So evidence here covers a period rather than carrying a timestamp, and a
// control's coverage is the union of its evidence intervals against the audit
// window. What comes out is not a percentage. It is a list of gaps: the days
// in the period for which this organisation has nothing to show.
//
// # A control that has never failed has not been tested
//
// internal/detect refuses a rule that matches none of its own fixtures, on
// the grounds that a detection that cannot fire is not a detection. The same
// argument applies here and almost nobody makes it: an automated check that
// has returned "pass" four hundred times and "fail" never is
// indistinguishable from a check that is broken, a check pointed at the wrong
// thing, or a check whose failure path was never written.
//
// That is not a finding about the control. It is a finding about the
// evidence, and it is reported as one.
//
// # Two observations, or it happened once
//
// A quarterly access review with one occurrence in a six-month window has not
// been shown to operate. It has been shown to have happened. Auditors put it
// plainly: a window shorter than two cycles gives nothing to sample and no
// way to test around a gap. So a control declares how often it is meant to
// happen, and a period that does not contain at least two occurrences of a
// periodic control is reported as unproven rather than as covered.
//
// # There is no single percentage here, and that is deliberate
//
// A compliance score is controls-passing over controls-in-scope, and scope is
// chosen by whoever wants the number. The honest figures are the ones
// internal/workforce uses: how many controls have any evidence at all, how
// much of the period that evidence covers, and what is missing.
package assurance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// Cadence is how often a control is meant to happen.
type Cadence string

const (
	// Continuous is something always in force: a setting, an enforced
	// policy, a blocked port. Evidence for it covers a span because the
	// thing was true across that span.
	Continuous Cadence = "continuous"
	// Daily, Weekly, Monthly, Quarterly and Annual are periodic controls:
	// somebody does a thing, on a schedule.
	Daily     Cadence = "daily"
	Weekly    Cadence = "weekly"
	Monthly   Cadence = "monthly"
	Quarterly Cadence = "quarterly"
	Annual    Cadence = "annual"
	// OnEvent is a control that runs when something happens — a joiner, a
	// leaver, a change. Its population is the events, not the calendar, so
	// coverage of a period means nothing and completeness means everything.
	OnEvent Cadence = "on-event"
)

// Cadences lists them.
func Cadences() []Cadence {
	return []Cadence{Continuous, Daily, Weekly, Monthly, Quarterly, Annual,
		OnEvent}
}

func (c Cadence) known() bool {
	for _, x := range Cadences() {
		if x == c {
			return true
		}
	}
	return false
}

// Every is the interval between occurrences, or zero for the two cadences
// that do not have one.
func (c Cadence) Every() time.Duration {
	switch c {
	case Daily:
		return 24 * time.Hour
	case Weekly:
		return 7 * 24 * time.Hour
	case Monthly:
		return 30 * 24 * time.Hour
	case Quarterly:
		return 91 * 24 * time.Hour
	case Annual:
		return 365 * 24 * time.Hour
	default:
		return 0
	}
}

// Periodic reports whether this control happens on a schedule.
func (c Cadence) Periodic() bool { return c.Every() > 0 }

// Outcome is what the evidence shows.
type Outcome string

const (
	// Operated is the control did what it says.
	Operated Outcome = "operated"
	// Failed is it did not, on this occasion.
	//
	// Not a finding about the organisation so much as the thing that makes
	// the other evidence mean anything: a control with four hundred passes
	// and no failure has not been tested.
	Failed Outcome = "failed"
	// NotObserved is the check ran and could not tell.
	//
	// Kept apart from Failed for the reason telemetry keeps Failed apart
	// from Blocked: a scanner that could not reach a host has not found the
	// host compliant and has not found it non-compliant, and recording
	// either is inventing a result.
	NotObserved Outcome = "not-observed"
)

// Outcomes lists them.
func Outcomes() []Outcome { return []Outcome{Operated, Failed, NotObserved} }

func (o Outcome) known() bool {
	for _, x := range Outcomes() {
		if x == o {
			return true
		}
	}
	return false
}

// Control is something the organisation says it does.
type Control struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Cadence Cadence `json:"cadence"`
	// Owner is the person accountable. Empty is a control nobody is doing.
	Owner string `json:"owner,omitempty"`
	// Maps are the framework references this control answers to:
	// "SOC2:CC6.1", "ISO27001:A.8.2". Carried for navigation and never
	// summed into a coverage figure — see the package comment, and see
	// internal/detect on why an ATT&CK coverage percentage is dishonest for
	// exactly the same reason.
	Maps []string `json:"maps,omitempty"`
	// Entity is the company that operates this control. Empty means the
	// group, and a group control covers the companies beneath it.
	Entity string `json:"entity,omitempty"`
	// PerEntity says every company in scope has to evidence this itself.
	//
	// The difference between a group-wide identity provider, which one
	// connector evidences for everybody, and an access review, which each
	// company performs separately. Getting this wrong in the second
	// direction is the shared-control illusion: one subsidiary's review
	// reported as the group's.
	PerEntity bool `json:"per_entity,omitempty"`
	// Automated says a machine produces the evidence.
	//
	// Worth knowing because the failure modes differ: a manual control fails
	// when somebody is on holiday, and an automated one fails silently for
	// six months because a token expired.
	Automated bool `json:"automated,omitempty"`
}

// Validate refuses a control nothing can be evidenced against.
func (c Control) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("a control needs an identifier")
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf(
			"%s has no name. A control an auditor cannot read is one "+
				"somebody has to be in the room to explain", c.ID)
	}
	if !c.Cadence.known() {
		return fmt.Errorf(
			"%s happens %q. A control with no stated frequency cannot be "+
				"short of evidence, because nothing says how much there "+
				"should be", c.ID, c.Cadence)
	}
	return nil
}

// Evidence is an artefact showing a control operated across a span.
type Evidence struct {
	Control string `json:"control"`
	// From and To are the period this speaks to, not when it was captured.
	//
	// The whole difference between this package and a folder of screenshots.
	// A configuration export covers the span over which that configuration
	// was in force; an access review covers the quarter it reviewed; a log
	// retained continuously covers the days it holds.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`

	Outcome Outcome `json:"outcome"`
	// What it shows, in one line.
	What string `json:"what"`
	// Source is what produced it: a connector, a person, the audit log.
	Source string `json:"source"`
	// Ref points at the artefact: an audit entry hash, an object id, a
	// ticket. Required — see Validate.
	Ref string `json:"ref"`

	// Entity is the company this evidence speaks for.
	//
	// Empty means the group. Evidence gathered for one company never
	// evidences a sibling and never evidences the group: see
	// internal/entity on why that direction is the one everybody gets
	// wrong.
	Entity string `json:"entity,omitempty"`

	At   time.Time  `json:"at"`
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
}

// Validate refuses evidence that is a claim.
func (e Evidence) Validate() error {
	if strings.TrimSpace(e.Control) == "" {
		return fmt.Errorf("evidence needs a control")
	}
	if !e.Outcome.known() {
		return fmt.Errorf("%s: %q is not an outcome", e.Control, e.Outcome)
	}
	if e.From.IsZero() || e.To.IsZero() {
		return fmt.Errorf(
			"%s: evidence covers a period, not a moment. A screenshot taken "+
				"on one day is evidence about that day, and the question is "+
				"whether the control operated throughout", e.Control)
	}
	if e.To.Before(e.From) {
		return fmt.Errorf("%s: evidence ends before it begins", e.Control)
	}
	if strings.TrimSpace(e.What) == "" {
		return fmt.Errorf("%s: evidence that says nothing", e.Control)
	}
	if strings.TrimSpace(e.Source) == "" {
		return fmt.Errorf(
			"%s: evidence with no source cannot be re-gathered, checked, or "+
				"switched off when it turns out to be measuring the wrong "+
				"thing", e.Control)
	}
	if strings.TrimSpace(e.Ref) == "" {
		return fmt.Errorf(
			"%s: evidence with nothing to point at is a claim. An auditor "+
				"asks to see it, and \"we do that\" is the answer that "+
				"turns a two-week audit into a six-week one", e.Control)
	}
	if e.At.IsZero() {
		return fmt.Errorf("%s: evidence with no capture time", e.Control)
	}
	if strings.TrimSpace(e.By) == "" {
		return fmt.Errorf("%s: evidence nobody gathered", e.Control)
	}
	if e.Kind == audit.KindAI {
		// A model may summarise evidence and may not be the one attesting
		// to it. The same rule internal/finding applies to closing findings
		// and internal/vuln to marking something not affected, and here the
		// artefact goes to an auditor with the organisation's name on it.
		return fmt.Errorf(
			"%s: this evidence is attested by a model. An artefact going to "+
				"an auditor carries the organisation's word; a model may "+
				"gather it and a person attests to it", e.Control)
	}
	return nil
}

// detailOf is what the audit log records about a piece of evidence.
func detailOf(e Evidence) map[string]string {
	d := map[string]string{
		"control": e.Control, "what": e.What, "source": e.Source,
		"ref":  e.Ref,
		"from": e.From.UTC().Format(time.RFC3339),
		"to":   e.To.UTC().Format(time.RFC3339),
	}
	if e.Entity != "" {
		d["entity"] = e.Entity
	}
	return d
}

// Span is how long this evidence covers.
func (e Evidence) Span() time.Duration { return e.To.Sub(e.From) }

// Record turns evidence into an audit entry.
func (e Evidence) Record() audit.Record {
	outcome := audit.Success
	if e.Outcome == Failed {
		// A control that failed is recorded as a denial, so a log can be
		// searched for the occasions something did not work — which is the
		// population an auditor samples from and the one a passing
		// dashboard hides.
		outcome = audit.Denied
	}
	return audit.Record{
		Action:   "control." + string(e.Outcome),
		Resource: "/control/" + e.Control, Outcome: outcome,
		Principal: e.By, Kind: e.Kind,
		Verified: e.Kind != audit.KindUnknown,
		Detail:   detailOf(e),
	}
}

// Period is a window of time.
type Period struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Length is how long the period is.
func (p Period) Length() time.Duration { return p.To.Sub(p.From) }

// Days is the period's length in whole days, for a report somebody reads.
func (p Period) Days() int { return int(p.Length().Hours() / 24) }

// Valid reports whether the period makes sense.
func (p Period) Valid() bool {
	return !p.From.IsZero() && !p.To.IsZero() && p.To.After(p.From)
}

// String renders a period the way a report does.
func (p Period) String() string {
	return fmt.Sprintf("%s to %s", p.From.Format("2006-01-02"),
		p.To.Format("2006-01-02"))
}

// Overlap returns the part of p that is also in q, and whether there is any.
func (p Period) Overlap(q Period) (Period, bool) {
	from, to := p.From, p.To
	if q.From.After(from) {
		from = q.From
	}
	if q.To.Before(to) {
		to = q.To
	}
	if !to.After(from) {
		return Period{}, false
	}
	return Period{From: from, To: to}, true
}

// merge folds overlapping and touching periods into the fewest that cover
// the same time, oldest first.
func merge(in []Period) []Period {
	if len(in) == 0 {
		return nil
	}
	sorted := append([]Period(nil), in...)
	sort.Slice(sorted, func(i, j int) bool {
		if !sorted[i].From.Equal(sorted[j].From) {
			return sorted[i].From.Before(sorted[j].From)
		}
		return sorted[i].To.Before(sorted[j].To)
	})
	out := []Period{sorted[0]}
	for _, p := range sorted[1:] {
		last := &out[len(out)-1]
		if p.From.After(last.To) {
			out = append(out, p)
			continue
		}
		if p.To.After(last.To) {
			last.To = p.To
		}
	}
	return out
}

// MinGap is the shortest hole worth reporting.
//
// A day. Evidence always lags: a nightly export finishes at two in the
// morning and the report runs at nine, so the last seven hours of every
// window are uncovered by construction. Reporting that as a gap prints
// "0 day(s) with nothing to show" and trains whoever reads the list to skip
// it, which costs more than the seven hours are worth.
//
// It is a floor on the report and not on the arithmetic: Covered still counts
// only what the evidence actually spans, so the share of the period does not
// move.
const MinGap = 24 * time.Hour

// gaps returns the parts of the period that none of the covers touch.
func gaps(period Period, covers []Period) []Period {
	var out []Period
	at := period.From
	for _, c := range merge(covers) {
		clipped, ok := c.Overlap(period)
		if !ok {
			continue
		}
		if clipped.From.After(at) {
			out = append(out, Period{From: at, To: clipped.From})
		}
		if clipped.To.After(at) {
			at = clipped.To
		}
	}
	if at.Before(period.To) {
		out = append(out, Period{From: at, To: period.To})
	}
	kept := out[:0]
	for _, g := range out {
		if g.Length() >= MinGap {
			kept = append(kept, g)
		}
	}
	return kept
}
