// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package entity

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Measuring a control across a group, and the one decision that decides
// whether the answer is honest.
//
// A control that every company performs separately is exactly as covered as
// its worst company. Not the union of the evidence, not the average, not the
// parent's. The worst — because a group report is a claim about every company
// in it, and one that is true for four of five is false.

// Divergence is one control measured across every company in a scope.
type Divergence struct {
	Control string `json:"control"`
	Scope   string `json:"scope"`
	// PerEntity is whether each company has to evidence this itself.
	PerEntity bool `json:"per_entity"`

	// By is each company's coverage, worst first.
	By []EntityCoverage `json:"by"`
	// Worst is the coverage the group is entitled to claim.
	Worst assurance.Coverage `json:"worst"`
	// Silent names the companies with no evidence at all.
	Silent []string `json:"silent,omitempty"`
	// Relying names the companies covered by an ancestor's evidence
	// through a recorded reliance rather than by their own.
	Relying map[string]string `json:"relying,omitempty"`
	// Coverable names companies with nothing of their own where an ancestor
	// does have evidence, keyed by which ancestor.
	//
	// Separated from the rest of Silent because the work is different: this
	// is recording why the parent's control counts here, not standing up a
	// control. For a per-entity control an ancestor's evidence never
	// applies on its own — letting it would make the flag mean nothing.
	Coverable map[string]string `json:"coverable,omitempty"`
	// Assumed names companies covered by an ancestor's evidence with no
	// reliance recorded.
	//
	// The interesting one. The evidence genuinely reaches them, so nothing
	// is wrong — and at audit the subsidiary still has to explain why the
	// parent's control counts here, which is a conversation nobody has had.
	Assumed []string `json:"assumed,omitempty"`
}

// EntityCoverage is one company's standing on one control.
type EntityCoverage struct {
	Entity   string             `json:"entity"`
	Coverage assurance.Coverage `json:"coverage"`
	// From names where the evidence came from, when it was not this
	// company's own.
	From string `json:"from,omitempty"`
}

// Even reports whether every company is in the same position.
func (d Divergence) Even() bool {
	if len(d.By) < 2 {
		return true
	}
	first := d.By[0].Coverage.Complete()
	for _, e := range d.By[1:] {
		if e.Coverage.Complete() != first {
			return false
		}
	}
	return true
}

// Why explains a divergence in one line, leading with what is not covered.
func (d Divergence) Why() string {
	covered := 0
	for _, e := range d.By {
		if e.Coverage.Complete() && e.Coverage.Observations > 0 {
			covered++
		}
	}
	switch {
	case len(d.By) == 0:
		return "no companies in scope"
	case len(d.Silent) > 0 && !d.PerEntity:
		// One place operates it, and that place has nothing. Saying
		// "0 of 1 companies" here is arithmetically true and reads as a
		// puzzle.
		return fmt.Sprintf(
			"nothing evidences this anywhere. It is operated by %s for the "+
				"%d compan(ies) beneath, and %s has no evidence for the "+
				"period", d.Silent[0], len(t2n(d)), d.Silent[0])
	case len(d.Silent) > 0:
		why := fmt.Sprintf("evidenced for %d of %d compan(ies); %s",
			covered, len(d.By), nothing(d.Silent))
		if len(d.By) > 1 {
			// Only where there is a union to show. Auditing one subsidiary
			// is a real scope, and telling its report about a group
			// dashboard is telling it about somebody else's problem.
			why += ". A group report that showed the union of this would " +
				"be green"
		}
		if len(d.Coverable) > 0 {
			why += fmt.Sprintf(
				". %s an ancestor that evidences it, so the work is "+
					"recording why that counts",
				hasAn(sortedKeys(d.Coverable)))
		}
		return why
	case covered < len(d.By):
		return fmt.Sprintf(
			"evidenced for %d of %d compan(ies); the rest have gaps, and "+
				"the group is entitled to claim the worst of them",
			covered, len(d.By))
	case len(d.Assumed) > 0:
		return fmt.Sprintf(
			"evidenced everywhere; %s on an ancestor's evidence with no "+
				"reliance recorded", relyVerb(d.Assumed))
	default:
		return fmt.Sprintf("evidenced for all %d compan(ies)", len(d.By))
	}
}

// Across measures one control over every company in a scope.
func Across(t *Tree, scope string, c assurance.Control,
	evidence []assurance.Evidence, relies []Reliance,
	period assurance.Period) Divergence {

	d := Divergence{Control: c.ID, Scope: scope, PerEntity: c.PerEntity}
	companies := t.Scope(scope)
	if len(companies) == 0 {
		return d
	}
	byKey := map[string]Reliance{}
	for _, r := range relies {
		if r.Control != c.ID {
			continue
		}
		if existing, ok := byKey[r.Key()]; ok && existing.At.After(r.At) {
			continue
		}
		byKey[r.Key()] = r
	}

	// A control that is not per-entity is operated in one place and reaches
	// downwards. Measuring it once against the operator is the whole answer;
	// measuring it per company would report five gaps for one connector.
	if !c.PerEntity {
		operator := c.Entity
		if operator == "" {
			operator = t.Root()
		}
		own := forEntity(evidence, c.ID, operator, t, false)
		d.Worst = assurance.Measure(c, own, period)
		d.By = []EntityCoverage{{Entity: operator, Coverage: d.Worst}}
		for _, id := range companies {
			if id == operator || !t.Reaches(operator, id) {
				continue
			}
			if r, ok := byKey[id+"\x00"+c.ID]; ok {
				if d.Relying == nil {
					d.Relying = map[string]string{}
				}
				d.Relying[id] = r.On
				continue
			}
			d.Assumed = append(d.Assumed, id)
		}
		sort.Strings(d.Assumed)
		if d.Worst.Observations == 0 {
			d.Silent = append(d.Silent, operator)
		}
		return d
	}

	for _, id := range companies {
		own := forEntity(evidence, c.ID, id, t, false)
		ec := EntityCoverage{Entity: id,
			Coverage: assurance.Measure(c, own, period)}
		if ec.Coverage.Observations == 0 {
			// Nothing of its own. An ancestor's evidence reaches it, but
			// this control says every company performs it separately, and
			// letting a parent's evidence satisfy that quietly is the flag
			// meaning nothing. It counts only where the company has
			// recorded why it does not have to do this itself.
			r, recorded := byKey[id+"\x00"+c.ID]
			inherited := forEntity(evidence, c.ID, id, t, true)
			switch {
			case recorded && len(inherited) > 0:
				ec.Coverage = assurance.Measure(c, inherited, period)
				ec.From = fromOf(inherited)
				if d.Relying == nil {
					d.Relying = map[string]string{}
				}
				d.Relying[id] = r.On
			case len(inherited) > 0:
				// Silent, and the parent does do it. Worth separating from
				// silent-and-nobody-does-it, because the work is recording
				// a reliance rather than standing up a control.
				if d.Coverable == nil {
					d.Coverable = map[string]string{}
				}
				d.Coverable[id] = fromOf(inherited)
			}
		}
		if ec.Coverage.Observations == 0 {
			d.Silent = append(d.Silent, id)
		}
		d.By = append(d.By, ec)
	}
	sort.Strings(d.Silent)
	sort.Strings(d.Assumed)
	sort.SliceStable(d.By, func(i, j int) bool {
		if d.By[i].Coverage.Share() != d.By[j].Coverage.Share() {
			return d.By[i].Coverage.Share() < d.By[j].Coverage.Share()
		}
		return d.By[i].Entity < d.By[j].Entity
	})
	if len(d.By) > 0 {
		// The worst, which is what the group is entitled to claim.
		d.Worst = d.By[0].Coverage
	}
	return d
}

// forEntity selects the evidence that speaks for one company.
//
// With inherited set, evidence from an ancestor is included; without it, only
// the company's own. Evidence from a sibling or a descendant is never
// included either way.
func forEntity(in []assurance.Evidence, control, id string, t *Tree,
	inherited bool) []assurance.Evidence {

	var out []assurance.Evidence
	for _, e := range in {
		if e.Control != control {
			continue
		}
		at := e.Entity
		if at == "" {
			at = t.Root()
		}
		switch {
		case at == id:
			out = append(out, e)
		case inherited && t.Reaches(at, id):
			out = append(out, e)
		}
	}
	return out
}

// nothing renders a list of silent companies with a verb that agrees.
//
// One name and "have nothing" is the kind of sentence that makes a reader
// distrust everything else on the page.
func relyVerb(in []string) string {
	if len(in) == 1 {
		return in[0] + " relies"
	}
	return strings.Join(in, ", ") + " rely"
}

func nothing(in []string) string {
	if len(in) == 1 {
		return in[0] + " has nothing"
	}
	return strings.Join(in, ", ") + " have nothing"
}

func hasAn(in []string) string {
	if len(in) == 1 {
		return in[0] + " does have"
	}
	return strings.Join(in, ", ") + " do have"
}

// t2n is the companies a group control covers beneath its operator.
func t2n(d Divergence) []string {
	out := append([]string(nil), d.Assumed...)
	for k := range d.Relying {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fromOf(in []assurance.Evidence) string {
	seen := map[string]bool{}
	var out []string
	for _, e := range in {
		if !seen[e.Entity] {
			seen[e.Entity] = true
			out = append(out, e.Entity)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// Group is what a whole scope adds up to.
type Group struct {
	Scope     string           `json:"scope"`
	Period    assurance.Period `json:"period"`
	Companies int              `json:"companies"`
	Controls  int              `json:"controls"`
	// Uneven is how many controls are in a different state in different
	// companies. The number a group-level dashboard cannot show.
	Uneven int `json:"uneven"`
	// Assumed is how many controls are inherited somewhere with no
	// reliance recorded.
	Assumed int `json:"assumed"`
	// Silent is how many controls have no evidence anywhere in scope.
	Silent int `json:"silent"`
}

// Why explains a group's standing in one line.
func (g Group) Why() string {
	switch {
	case g.Companies == 0:
		return "nothing in scope"
	case g.Silent > 0:
		return fmt.Sprintf(
			"%d of %d control(s) have no evidence anywhere in the %d "+
				"compan(ies) under %s", g.Silent, g.Controls, g.Companies,
			g.Scope)
	case g.Uneven > 0:
		return fmt.Sprintf(
			"%d of %d control(s) are in a different state in different "+
				"companies. A group report showing one figure for each "+
				"would be showing the best of them", g.Uneven, g.Controls)
	case g.Assumed > 0:
		return fmt.Sprintf(
			"every control is evidenced across %d compan(ies); %d are "+
				"inherited somewhere with no reliance recorded",
			g.Companies, g.Assumed)
	default:
		return fmt.Sprintf("every control is evidenced across all %d "+
			"compan(ies) under %s", g.Companies, g.Scope)
	}
}

// Assess measures every control across a scope.
func Assess(t *Tree, scope string, controls []assurance.Control,
	evidence []assurance.Evidence, relies []Reliance,
	period assurance.Period) (Group, []Divergence) {

	g := Group{Scope: scope, Period: period,
		Companies: len(t.Scope(scope)), Controls: len(controls)}
	var out []Divergence
	for _, c := range controls {
		d := Across(t, scope, c, evidence, relies, period)
		out = append(out, d)
		if !d.Even() {
			g.Uneven++
		}
		if len(d.Assumed) > 0 {
			g.Assumed++
		}
		if len(d.Silent) == len(d.By) && len(d.By) > 0 {
			g.Silent++
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Worst.Share() != out[j].Worst.Share() {
			return out[i].Worst.Share() < out[j].Worst.Share()
		}
		return out[i].Control < out[j].Control
	})
	return g, out
}

// Findings turns divergence into the register everything else works from.
func Findings(t *Tree, g Group, in []Divergence,
	now time.Time) []finding.Finding {

	var out []finding.Finding
	add := func(d Divergence, sev telemetry.Severity, title, what string) {
		f := finding.Finding{
			Kind: finding.FromControl, Title: title, Source: "entity",
			Entity: telemetry.ID{Issuer: "control",
				Value: d.Control + "@" + d.Scope},
			Severity: sev, State: finding.Open, Seen: 1,
			First: g.Period.From, Last: now,
			Evidence: []finding.Evidence{{
				At: now, Source: "entity", What: what,
			}},
		}
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}
	for _, d := range in {
		if len(d.Silent) > 0 && len(d.Silent) < len(d.By) {
			what := fmt.Sprintf(
				"evidenced in %d of %d compan(ies) under %s. A group report "+
					"showing the union of this evidence would be green, and "+
					"the companies with nothing would be discovered by an "+
					"auditor", len(d.By)-len(d.Silent), len(d.By), d.Scope)
			if len(d.Coverable) > 0 {
				what += fmt.Sprintf(
					". %s have an ancestor that does evidence it, so the "+
						"work there is recording why that counts rather "+
						"than standing up a control",
					strings.Join(sortedKeys(d.Coverable), ", "))
			}
			add(d, telemetry.SeverityHigh,
				fmt.Sprintf("%s has no evidence in %s", d.Control,
					strings.Join(d.Silent, ", ")), what)
			continue
		}
		if !d.Even() {
			add(d, telemetry.SeverityMedium,
				fmt.Sprintf("%s is in a different state in different "+
					"companies", d.Control),
				d.Why())
		}
		if len(d.Assumed) > 0 {
			add(d, telemetry.SeverityLow,
				fmt.Sprintf("%s is inherited by %s with nothing recorded",
					d.Control, strings.Join(d.Assumed, ", ")),
				"the evidence genuinely reaches them, so nothing here is "+
					"wrong. At audit the subsidiary still has to say why "+
					"the parent's control counts for this examination, and "+
					"that is a conversation nobody has had")
		}
	}
	return finding.Rank(out, now)
}
