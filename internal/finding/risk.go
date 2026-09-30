// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package finding

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Risk by entity: what several small findings about one person add up to.
//
// A queue ranks findings. Three medium findings about one person, from
// three rules on two platforms inside a day, sit in three places in it and
// each looks like something to get to later. Together they are the most
// important thing in the queue, and nothing says so.
//
// This adds them up, per person where the person is known and per
// identifier where not. The sum is made of the findings and nothing else,
// each with the points it contributed, so the screen that shows a number
// also shows where it came from. What people ruled false or benign is not
// in it, and neither is what a rule on trial raised.

// RiskWindow is how far back a finding still counts.
const RiskWindow = 14 * 24 * time.Hour

// severityPoints is what one finding of a severity is worth at full
// strength. The steps are wide on purpose: a critical finding should not be
// matched by two mediums.
func severityPoints(s telemetry.Severity) float64 {
	switch {
	case s >= telemetry.SeverityCritical:
		return 80
	case s >= telemetry.SeverityHigh:
		return 40
	case s >= telemetry.SeverityMedium:
		return 15
	}
	return 5
}

// fade is how much of its points a finding keeps at an age.
func fade(age time.Duration) float64 {
	switch {
	case age <= 24*time.Hour:
		return 1
	case age <= 7*24*time.Hour:
		return 0.5
	case age <= RiskWindow:
		return 0.25
	}
	return 0
}

// Part is one finding's share of an entity's risk.
type Part struct {
	Finding Finding `json:"finding"`
	Points  float64 `json:"points"`
}

// EntityRisk is what is open about one person or thing, added up.
type EntityRisk struct {
	// Entity is the person's address when they are known, and the
	// identifier otherwise. Person says which.
	Entity string `json:"entity"`
	Person bool   `json:"person,omitempty"`
	// Identifiers is every identifier the findings were about.
	Identifiers []string `json:"identifiers"`
	Parts       []Part   `json:"parts"`
	// Rules is how many different rules raised them.
	Rules int `json:"rules"`
	// Score is the parts' points, raised for breadth: several rules
	// agreeing is more than one rule firing several times.
	Score float64 `json:"score"`
	Band  string  `json:"band"`
}

// Why says where the score came from.
func (e EntityRisk) Why() string {
	base := 0.0
	for _, p := range e.Parts {
		base += p.Points
	}
	s := fmt.Sprintf("%d finding(s) worth %.0f", len(e.Parts), base)
	if e.Rules > 1 {
		s += fmt.Sprintf(", raised by %d different rules (×%.2f)", e.Rules,
			breadth(e.Rules))
	}
	return s
}

// breadth is the multiplier for several rules agreeing, capped at double.
func breadth(rules int) float64 {
	m := 1 + 0.25*float64(rules-1)
	if m > 2 {
		m = 2
	}
	if m < 1 {
		m = 1
	}
	return m
}

func band(score float64) string {
	switch {
	case score >= 150:
		return "critical"
	case score >= 80:
		return "high"
	case score >= 40:
		return "medium"
	}
	return "low"
}

// Risk adds up what is open, by entity, highest first.
//
// person gives the address an identifier is known by, or empty. It is how
// okta:00u1 and github:dana-gh become one row.
func Risk(findings []Finding, person func(telemetry.ID) string,
	now time.Time) []EntityRisk {

	by := map[string]*EntityRisk{}
	rules := map[string]map[string]bool{}
	ids := map[string]map[string]bool{}
	var order []string
	for _, f := range findings {
		if f.Trial || f.Entity.Zero() {
			continue
		}
		// Undecided, or looked at and real. What was ruled false, benign,
		// fixed or stale is not risk that is still there.
		if f.State != Open && f.State != Triaged {
			continue
		}
		points := severityPoints(f.Severity) * fade(now.Sub(f.Last))
		if points == 0 {
			continue
		}
		key, isPerson := f.Entity.String(), false
		switch {
		case f.Entity.Issuer == "person":
			key, isPerson = f.Entity.Value, true
		case person != nil:
			if p := person(f.Entity); p != "" {
				key, isPerson = p, true
			}
		}
		e := by[key]
		if e == nil {
			e = &EntityRisk{Entity: key, Person: isPerson}
			by[key] = e
			rules[key], ids[key] = map[string]bool{}, map[string]bool{}
			order = append(order, key)
		}
		e.Parts = append(e.Parts, Part{Finding: f, Points: points})
		rules[key][string(f.Kind)+"/"+strings.ToLower(f.Source)] = true
		ids[key][f.Entity.String()] = true
	}
	out := make([]EntityRisk, 0, len(order))
	for _, key := range order {
		e := by[key]
		e.Rules = len(rules[key])
		for id := range ids[key] {
			e.Identifiers = append(e.Identifiers, id)
		}
		sort.Strings(e.Identifiers)
		sort.SliceStable(e.Parts, func(a, b int) bool {
			return e.Parts[a].Points > e.Parts[b].Points
		})
		base := 0.0
		for _, p := range e.Parts {
			base += p.Points
		}
		e.Score = base * breadth(e.Rules)
		e.Band = band(e.Score)
		out = append(out, *e)
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Score != out[b].Score {
			return out[a].Score > out[b].Score
		}
		return out[a].Entity < out[b].Entity
	})
	return out
}
