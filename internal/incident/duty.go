// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package incident

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Obligation is one reporting requirement: who has to be told, how soon,
// and which decision starts the clock.
//
// A table rather than code, so a deployment can see what it is being held
// to. Not legal advice, and the package says so where somebody will read
// it: these are the published headline deadlines, the thresholds for
// whether a regime applies at all are somebody else's judgement, and the
// value here is arithmetic on a clock that has already been started by a
// decision a person made.
type Obligation struct {
	// Regime is the instrument, and Scope the sector or jurisdiction that
	// has to be in the incident's regimes for it to apply.
	Regime string `json:"regime"`
	Scope  string `json:"scope"`
	// Needs is the decision that starts this clock.
	Needs Trigger `json:"needs"`
	// Within is how long after it. Business says whether weekends count.
	Within   time.Duration `json:"within"`
	Business bool          `json:"business,omitempty"`
	// Who has to be told, and What has to be sent.
	Who  string `json:"who"`
	What string `json:"what"`
	// Note carries the thing about this one that catches people out.
	Note string `json:"note,omitempty"`
}

// Obligations is the ladder.
//
// Every one of these runs from an awareness or a determination and none of
// them runs from the end of an investigation, which is the single most
// expensive misunderstanding in this area.
var Obligations = []Obligation{
	{
		Regime: "GDPR Article 33", Scope: "eu", Needs: Aware,
		Within: 72 * time.Hour,
		Who:    "the supervisory authority", What: "a breach notification",
		Note: "seventy-two hours from awareness that a breach has likely " +
			"occurred, not from confirming it. Article 33(1) allows a late " +
			"notification with reasons, which is a worse position than an " +
			"incomplete one on time — Article 33(4) exists so information " +
			"can be sent in phases",
	},
	{
		Regime: "GDPR Article 34", Scope: "eu", Needs: Personal,
		Within: 0,
		Who:    "the people affected", What: "a notice in plain language",
		Note: "no deadline: without undue delay, and where the risk is " +
			"high. The absence of a number is not laxity, it is that " +
			"telling people badly is worse than telling them a day later",
	},
	{
		Regime: "NIS2 early warning", Scope: "nis2", Needs: Aware,
		Within: 24 * time.Hour,
		Who:    "the CSIRT or competent authority",
		What:   "an early warning",
		Note: "the shortest of the European clocks that runs from mere " +
			"awareness. It is an early warning rather than a report, so " +
			"not knowing the answer yet is not a reason to miss it",
	},
	{
		Regime: "NIS2 notification", Scope: "nis2", Needs: Aware,
		Within: 72 * time.Hour,
		Who:    "the CSIRT or competent authority",
		What:   "an incident notification with an initial assessment",
	},
	{
		Regime: "NIS2 final report", Scope: "nis2", Needs: Aware,
		Within: 30 * 24 * time.Hour,
		Who:    "the CSIRT or competent authority",
		What:   "a final report",
	},
	{
		Regime: "DORA", Scope: "dora", Needs: Major,
		Within: 4 * time.Hour,
		Who:    "the competent authority",
		What:   "an initial notification",
		Note: "the shortest clock in the set, and it runs from " +
			"classification rather than from awareness. Delaying the " +
			"classification does not delay anything else: the outer bound " +
			"is measured from awareness regardless",
	},
	{
		Regime: "SEC Item 1.05", Scope: "sec", Needs: Material,
		Within: 4 * 24 * time.Hour, Business: true,
		Who:  "the Commission, on Form 8-K",
		What: "a disclosure of a material cybersecurity incident",
		Note: "four business days from determining materiality, and the " +
			"determination itself must be made without unreasonable delay " +
			"— so not making it is not a way of avoiding it",
	},
	{
		Regime: "HIPAA breach notification", Scope: "hipaa", Needs: Health,
		Within: 60 * 24 * time.Hour,
		Who:    "the individuals affected",
		What:   "a breach notice",
	},
	{
		Regime: "CIRCIA", Scope: "circia", Needs: Aware,
		Within: 72 * time.Hour,
		Who:    "CISA", What: "a covered cyber incident report",
	},
}

// Duty is one obligation applied to one incident.
type Duty struct {
	Obligation
	// Started says the decision that starts this clock has been made.
	Started bool      `json:"started"`
	From    time.Time `json:"from,omitzero"`
	Due     time.Time `json:"due,omitzero"`
	// Left is how long remains. Negative means it is late.
	Left time.Duration `json:"left,omitempty"`
	// Done and Waived are mutually exclusive outcomes.
	Done   bool   `json:"done,omitempty"`
	Waived bool   `json:"waived,omitempty"`
	Why    string `json:"why,omitempty"`
}

// Late reports whether this is past due and not yet discharged.
func (d Duty) Late() bool {
	return d.Started && !d.Done && !d.Waived && !d.Due.IsZero() && d.Left < 0
}

// Soon reports whether this is due within the hour.
func (d Duty) Soon() bool {
	return d.Started && !d.Done && !d.Waived && d.Left > 0 &&
		d.Left <= time.Hour
}

// Says describes a duty for somebody who has to act on it.
func (d Duty) Says() string {
	switch {
	case d.Done:
		return "done"
	case d.Waived:
		return "ruled out: " + d.Why
	case !d.Started:
		return fmt.Sprintf(
			"no clock: nobody has recorded %q. That is not the same as "+
				"nothing being due — %s", d.Needs, d.Needs.Means())
	case d.Within == 0:
		return "no deadline, and expected without undue delay"
	case d.Left < 0:
		return fmt.Sprintf("late by %s", plainly(-d.Left))
	}
	return fmt.Sprintf("%s left", plainly(d.Left))
}

// Duties is every obligation that applies to this incident, soonest first.
func (i *Incident) Duties(now time.Time) []Duty {
	in := map[string]bool{}
	for _, r := range i.Regimes {
		in[r] = true
	}
	var out []Duty
	for _, o := range Obligations {
		if !in[o.Scope] {
			continue
		}
		d := Duty{Obligation: o}
		if m, ok := i.Moments[o.Needs]; ok {
			d.Started, d.From = true, m.At
			if o.Within > 0 {
				d.Due = due(m.At, o.Within, o.Business)
				d.Left = d.Due.Sub(now)
			}
		}
		if m, ok := i.Discharged[o.Regime]; ok {
			if strings.HasPrefix(m.Why, waived) {
				d.Waived, d.Why = true, strings.TrimPrefix(m.Why, waived)
			} else {
				d.Done, d.Why = true, m.Why
			}
		}
		out = append(out, d)
	}
	sort.SliceStable(out, func(a, b int) bool {
		x, y := out[a], out[b]
		// Anything with a running clock before anything without, then by
		// how little time is left.
		if x.Started != y.Started {
			return x.Started
		}
		if x.Started && x.Within > 0 && y.Within > 0 {
			return x.Left < y.Left
		}
		return x.Regime < y.Regime
	})
	return out
}

const waived = "not applicable: "

// due adds a duration, skipping weekends when the deadline is in business
// days.
//
// Weekends only. Public holidays differ by jurisdiction and change every
// year, and a table of them that is wrong is worse than no table — a
// deployment that needs them supplies the answer rather than trusting one
// guessed here. Stated because a deadline computed to the hour looks more
// authoritative than it is.
func due(from time.Time, within time.Duration, business bool) time.Time {
	if !business {
		return from.Add(within)
	}
	days := int(within / (24 * time.Hour))
	rest := within % (24 * time.Hour)
	at := from
	for days > 0 {
		at = at.Add(24 * time.Hour)
		switch at.Weekday() {
		case time.Saturday, time.Sunday:
			continue
		}
		days--
	}
	return at.Add(rest)
}

// Discharge records that an obligation was met.
func (i *Incident) Discharge(regime, by, how string, at time.Time) error {
	return i.settle(regime, by, how, at, false)
}

// Waive records that an obligation does not apply, with the reason.
//
// A separate call from Discharge because they are different statements and
// a field that conflated them would make "we told the regulator" and "we
// decided we did not have to" the same entry in the record.
func (i *Incident) Waive(regime, by, why string, at time.Time) error {
	return i.settle(regime, by, why, at, true)
}

func (i *Incident) settle(regime, by, why string, at time.Time,
	notApplicable bool) error {
	known := false
	for _, o := range Obligations {
		if o.Regime == regime {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("%q is not an obligation in the table", regime)
	}
	if strings.TrimSpace(by) == "" || strings.TrimSpace(why) == "" {
		return fmt.Errorf(
			"settling an obligation takes a name and a reason. An " +
				"anonymous one is indistinguishable from nobody having " +
				"looked")
	}
	m := Moment{At: at.UTC(), By: strings.TrimSpace(by),
		Why: strings.TrimSpace(why)}
	verb := "discharged"
	if notApplicable {
		m.Why = waived + m.Why
		verb = "ruled out"
	}
	i.Discharged[regime] = m
	i.note(by, fmt.Sprintf("%s %s: %s", verb, regime,
		strings.TrimSpace(why)), at)
	return nil
}

// Pressing is the duties that are late or due within the hour.
func (i *Incident) Pressing(now time.Time) []Duty {
	var out []Duty
	for _, d := range i.Duties(now) {
		if d.Late() || d.Soon() {
			out = append(out, d)
		}
	}
	return out
}

// Unstarted is the obligations whose clock nobody has started.
//
// The list this package exists for. "Nothing is due" and "nobody has made
// the call that makes something due" look identical on a dashboard, and
// the second one is how a team ends up three weeks into an incident a
// regulator will say was plainly reportable on day one.
func (i *Incident) Unstarted(now time.Time) []Duty {
	var out []Duty
	for _, d := range i.Duties(now) {
		if !d.Started && !d.Waived {
			out = append(out, d)
		}
	}
	return out
}

func plainly(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d second(s)", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s)", int(d.Hours()/24))
}
