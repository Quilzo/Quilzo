// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package crosswalk

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// What a framework's requirements add up to, and the three ways that figure
// is usually inflated.
//
// A requirement is Met only when something is Equal to it or a Superset of
// it, and that control has evidence covering the period. Three separate
// facts, and every platform that shows one number has collapsed them:
//
//	the mapping was optimistic       partial relations counted as covered
//	the control has no evidence      mapped is not operating
//	nobody ever looked               unmapped counted out of the denominator
//
// Each is reported on its own here, because they need different work: the
// first needs a conversation about scope, the second needs a connector fixed,
// and the third needs somebody to read the standard.

// State is where one requirement stands.
type State string

const (
	// Met is something satisfies it and that something has evidence.
	Met State = "met"
	// Unevidenced is something satisfies it on paper and did not operate,
	// or operated for part of the period.
	//
	// The state most programmes are actually in, and the one a dashboard
	// built on mappings alone cannot distinguish from Met.
	Unevidenced State = "unevidenced"
	// Partial is only subset or intersecting controls address it, so a
	// remainder is named and nothing covers it.
	Partial State = "partial"
	// Declined is somebody mapped it and recorded no relationship.
	Declined State = "declined"
	// Unmapped is nobody has looked.
	Unmapped State = "unmapped"
)

// Standing is one requirement and everything known about it.
type Standing struct {
	Requirement Requirement `json:"requirement"`
	State       State       `json:"state"`
	// By are the mappings that bear on it, newest first.
	By []Mapping `json:"by,omitempty"`
	// Remainders are what the partial mappings say is left over.
	Remainders []string `json:"remainders,omitempty"`
	// Gaps names the controls that would satisfy it and have missing
	// evidence, with how many days each is short.
	Gaps map[string]int `json:"gaps,omitempty"`
}

// Why explains a requirement's standing in one line.
func (s Standing) Why() string {
	switch s.State {
	case Met:
		return fmt.Sprintf("satisfied by %s, with evidence for the period",
			strings.Join(s.controls(), ", "))
	case Unevidenced:
		var parts []string
		for _, c := range sortedKeys(s.Gaps) {
			parts = append(parts, fmt.Sprintf("%s is short %d day(s)", c,
				s.Gaps[c]))
		}
		return fmt.Sprintf(
			"mapped to %s and not evidenced: %s. A mapping says a control "+
				"would satisfy this; it says nothing about whether it ran",
			strings.Join(s.controls(), ", "), strings.Join(parts, ", "))
	case Partial:
		return fmt.Sprintf(
			"partly addressed by %s. Nothing covers: %s",
			strings.Join(s.controls(), ", "),
			strings.Join(s.Remainders, "; "))
	case Declined:
		return "considered, and recorded as not applicable here"
	default:
		return "nothing has been mapped to this, so nobody has looked at it"
	}
}

func (s Standing) controls() []string {
	var out []string
	for _, m := range s.By {
		if m.Relation != NoRelation {
			out = append(out, m.Control)
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Report is what a framework adds up to.
type Report struct {
	Framework string           `json:"framework"`
	Period    assurance.Period `json:"period"`

	Requirements int `json:"requirements"`
	Met          int `json:"met"`
	Unevidenced  int `json:"unevidenced"`
	Partial      int `json:"partial"`
	Declined     int `json:"declined"`
	Unmapped     int `json:"unmapped"`

	// EqualShare is how many of the mappings claim exact equality.
	//
	// Reported because it is the tell. Equality between one organisation's
	// control and another organisation's clause is rare; a crosswalk where
	// most relations are Equal is one somebody clicked through, and it will
	// be discovered by an auditor rather than by a report.
	EqualShare float64 `json:"equal_share"`
	Mappings   int     `json:"mappings"`
}

// SuspiciouslyEqual is the share of Equal relations above which a crosswalk
// looks like it was not read.
//
// Three in five. Equality means the two concepts are the same, and two
// organisations writing independently about access control do not produce
// the same concept more often than they produce overlapping ones.
const SuspiciouslyEqual = 0.6

// Suspicious reports whether the crosswalk looks unread.
func (r Report) Suspicious() bool {
	return r.Mappings >= 10 && r.EqualShare > SuspiciouslyEqual
}

// Why explains a report in one line, leading with what is not covered.
func (r Report) Why() string {
	switch {
	case r.Requirements == 0:
		return "no requirements"
	case r.Unmapped > 0:
		return fmt.Sprintf(
			"%d of %d requirement(s) in %s have nothing mapped to them at "+
				"all. %d are met with evidence", r.Unmapped, r.Requirements,
			r.Framework, r.Met)
	case r.Partial+r.Unevidenced > 0:
		return fmt.Sprintf(
			"%d of %d requirement(s) in %s are met with evidence; %d are "+
				"only partly addressed and %d are mapped to controls that "+
				"did not operate across the period", r.Met, r.Requirements,
			r.Framework, r.Partial, r.Unevidenced)
	default:
		return fmt.Sprintf("all %d requirement(s) in %s are met with evidence",
			r.Requirements, r.Framework)
	}
}

// Assess works out where every requirement in a framework stands.
//
// Three inputs because the answer needs three facts: what the framework asks,
// what anybody has claimed about it, and whether the claimed controls
// actually operated.
func Assess(framework string, reqs []Requirement, mappings []Mapping,
	coverage []assurance.Coverage, period assurance.Period) (Report,
	[]Standing) {

	byControl := map[string]assurance.Coverage{}
	for _, c := range coverage {
		byControl[c.Control] = c
	}
	byRequirement := map[string][]Mapping{}
	var equal, total int
	for _, m := range Latest(mappings) {
		f, _, _ := strings.Cut(m.Requirement, ":")
		if f != framework {
			continue
		}
		byRequirement[m.Requirement] = append(byRequirement[m.Requirement], m)
		total++
		if m.Relation == Equal {
			equal++
		}
	}

	report := Report{Framework: framework, Period: period,
		Requirements: len(reqs), Mappings: total}
	if total > 0 {
		report.EqualShare = float64(equal) / float64(total)
	}

	var out []Standing
	for _, req := range reqs {
		if req.Framework != framework {
			continue
		}
		s := Standing{Requirement: req, State: Unmapped,
			By: byRequirement[req.Key()]}
		sort.Slice(s.By, func(i, j int) bool {
			return s.By[i].At.After(s.By[j].At)
		})

		var satisfying, declined bool
		for _, m := range s.By {
			switch {
			case m.Relation.Satisfies():
				satisfying = true
				cov, known := byControl[m.Control]
				switch {
				case !known || cov.Observations == 0:
					if s.Gaps == nil {
						s.Gaps = map[string]int{}
					}
					s.Gaps[m.Control] = period.Days()
				case !cov.Complete():
					if s.Gaps == nil {
						s.Gaps = map[string]int{}
					}
					s.Gaps[m.Control] = missingDays(cov)
				}
			case m.Relation.Partial():
				s.Remainders = append(s.Remainders, m.Remainder)
			case m.Relation == NoRelation:
				declined = true
			}
		}

		switch {
		case satisfying && len(s.Gaps) == 0:
			s.State = Met
			report.Met++
		case satisfying:
			s.State = Unevidenced
			report.Unevidenced++
		case len(s.Remainders) > 0:
			s.State = Partial
			report.Partial++
		case declined:
			s.State = Declined
			report.Declined++
		default:
			report.Unmapped++
		}
		out = append(out, s)
	}

	// Worst first: unmapped, then partial, then unevidenced, then met.
	rank := map[State]int{Unmapped: 0, Partial: 1, Unevidenced: 2,
		Declined: 3, Met: 4}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].State] != rank[out[j].State] {
			return rank[out[i].State] < rank[out[j].State]
		}
		return out[i].Requirement.ID < out[j].Requirement.ID
	})
	return report, out
}

func missingDays(c assurance.Coverage) int {
	var total time.Duration
	for _, g := range c.Gaps {
		total += g.Length()
	}
	return int(total.Hours() / 24)
}

// Adopting is what it would take to add a framework to an existing programme.
//
// The question somebody asks before signing up for an audit, and the one a
// coverage percentage answers wrongly. It returns what is already met, what
// is partly there with the remainders named, and what nobody has looked at —
// and it never adds them into a single figure, because the three need
// different work and only one of them is a conversation about scope.
func Adopting(report Report, standings []Standing) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Adopting %s: %d of %d requirement(s) already met with "+
		"evidence.\n", report.Framework, report.Met, report.Requirements)
	if report.Unevidenced > 0 {
		fmt.Fprintf(&b, "%d are mapped to controls that did not operate "+
			"across the period; that is a connector or a process, not a "+
			"new control.\n", report.Unevidenced)
	}
	if report.Partial > 0 {
		fmt.Fprintf(&b, "%d are partly addressed, and the remainders are "+
			"written down rather than rounded up.\n", report.Partial)
	}
	if report.Unmapped > 0 {
		fmt.Fprintf(&b, "%d have nothing mapped, which is somebody reading "+
			"the standard rather than a number going up.\n", report.Unmapped)
	}
	if report.Suspicious() {
		fmt.Fprintf(&b, "\n%.0f%% of the mappings claim exact equality. Two "+
			"organisations writing independently about access control do "+
			"not produce the same concept that often, and a crosswalk that "+
			"says they do is one an auditor will take apart.\n",
			report.EqualShare*100)
	}
	return b.String()
}

// Findings turns the standings into the register everything else works from.
func Findings(report Report, standings []Standing,
	now time.Time) []finding.Finding {

	var out []finding.Finding
	add := func(s Standing, sev telemetry.Severity, title, what string) {
		f := finding.Finding{
			Kind: finding.FromControl, Title: title, Source: "crosswalk",
			Entity: telemetry.ID{Issuer: "requirement",
				Value: s.Requirement.Key()},
			Severity: sev, State: finding.Open, Seen: 1,
			First: report.Period.From, Last: now,
			Evidence: []finding.Evidence{{
				At: now, Source: "crosswalk", What: what,
			}},
		}
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}
	for _, s := range standings {
		switch s.State {
		case Unmapped:
			add(s, telemetry.SeverityMedium,
				fmt.Sprintf("%s has nothing mapped to it", s.Requirement.Key()),
				fmt.Sprintf("%q — nobody has recorded whether any control "+
					"addresses this, and an unmapped requirement is the one "+
					"a coverage percentage leaves out of its denominator",
					s.Requirement.Title))
		case Partial:
			add(s, telemetry.SeverityMedium,
				fmt.Sprintf("%s is only partly addressed",
					s.Requirement.Key()),
				fmt.Sprintf("%q — nothing covers: %s", s.Requirement.Title,
					strings.Join(s.Remainders, "; ")))
		case Unevidenced:
			add(s, telemetry.SeverityHigh,
				fmt.Sprintf("%s is mapped and not evidenced",
					s.Requirement.Key()),
				s.Why())
		}
	}
	if report.Suspicious() {
		f := finding.Finding{
			Kind: finding.FromControl, Source: "crosswalk",
			Entity: telemetry.ID{Issuer: "framework",
				Value: report.Framework},
			Severity: telemetry.SeverityLow, State: finding.Open, Seen: 1,
			First: report.Period.From, Last: now,
			Title: fmt.Sprintf(
				"%.0f%% of the %s crosswalk claims exact equality",
				report.EqualShare*100, report.Framework),
			Evidence: []finding.Evidence{{
				At: now, Source: "crosswalk",
				What: "two organisations writing independently about the " +
					"same subject do not produce the same concept that " +
					"often. A crosswalk that says they do is one somebody " +
					"clicked through, and it will be taken apart by an " +
					"auditor rather than by a report",
			}},
		}
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}
	return finding.Rank(out, now)
}
