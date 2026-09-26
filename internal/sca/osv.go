// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package sca reads a bill of materials and an advisory database and says
// which dependencies are affected — and, more usefully, which of those
// anybody can do anything about.
//
// # The two formats that won
//
// OSV is the vulnerability schema: osv.dev aggregates GitHub advisories,
// the Go vulnerability database, PyPA, RustSec and the rest into one shape,
// published as a zip per ecosystem with a modification index for
// incremental mirroring. CycloneDX is the bill of materials, and its
// dependencies graph is the part most tools throw away.
//
// # Why the graph is the point
//
// Every scanner reports that a vulnerable package is present. Almost none
// report whether the team reading it can fix it. Those are different
// questions and only the second one is work.
//
// A direct dependency with a fixed version is a version bump this
// afternoon. The same advisory against a package four levels down is a
// conversation with whoever maintains the thing above it, and possibly the
// thing above that — and until they move, the only options are a fork, a
// replacement or an accepted risk. internal/vuln already ranks by
// exploitability rather than severity, because EPSS reaches the same
// coverage as CVSS for a tenth of the remediations. This adds the other
// axis: of the things worth fixing, which can actually be fixed, and by
// whom.
//
// So every exposure here carries the path from something somebody chose
// down to the affected package, and names the nearest dependency the team
// controls. That name is the work item. "Upgrade transitive package X" is
// not an action anybody can take; "ask for, or wait for, a release of Y
// that takes X 2.4.1" is.
package sca

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/vuln"
)

// Record is one OSV advisory, as osv.dev publishes it.
type Record struct {
	ID        string     `json:"id"`
	Modified  time.Time  `json:"modified,omitzero"`
	Published time.Time  `json:"published,omitzero"`
	Withdrawn *time.Time `json:"withdrawn,omitempty"`
	Aliases   []string   `json:"aliases,omitempty"`
	Summary   string     `json:"summary,omitempty"`
	Details   string     `json:"details,omitempty"`
	Severity  []Score    `json:"severity,omitempty"`
	Affected  []Affected `json:"affected,omitempty"`
	Refs      []Ref      `json:"references,omitempty"`
	// DatabaseSpecific carries whatever the publishing database wanted to
	// add. Read loosely, for the severity word GitHub puts there.
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

// Score is a severity in whichever scheme the database used.
type Score struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected is one package and the versions of it this applies to.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []VRange `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// Package names something in an ecosystem.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// VRange is a run of affected versions, expressed as events.
//
// The event encoding is the part people get wrong reading OSV by eye: the
// list is ordered and each introduced opens a run that the next fixed or
// last_affected closes. A range with introduced "0" and no fixed means
// every version ever published is affected and none is safe yet.
type VRange struct {
	Type   string  `json:"type"`
	Events []Event `json:"events,omitempty"`
}

// Event is one boundary in a range.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Ref is a link.
type Ref struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ReadOSV parses one OSV record or an array of them.
//
// Both shapes exist in the wild: osv.dev's zips hold a file per advisory
// and every aggregator that republishes them produces an array.
func ReadOSV(in []byte) ([]Record, error) {
	trimmed := strings.TrimSpace(string(in))
	if strings.HasPrefix(trimmed, "[") {
		var rs []Record
		if err := json.Unmarshal(in, &rs); err != nil {
			return nil, fmt.Errorf("this is not a list of OSV records: %w",
				err)
		}
		return rs, nil
	}
	var r Record
	if err := json.Unmarshal(in, &r); err != nil {
		return nil, fmt.Errorf("this is not an OSV record: %w", err)
	}
	if strings.TrimSpace(r.ID) == "" {
		return nil, fmt.Errorf("this record has no id, so nothing can " +
			"refer to it")
	}
	return []Record{r}, nil
}

// Live reports whether an advisory still stands.
//
// A withdrawn advisory is not a fixed one and not a false positive: it is
// one the database has retracted, and work queued against it should be
// closed rather than quietly left.
func (r Record) Live() bool { return r.Withdrawn == nil }

// CVSS finds the base score, computing it from the vector when the
// database gave one.
//
// OSV carries a vector string rather than a number, because a vector is the
// thing that can be checked and a number is a summary of it. Every consumer
// then needs the arithmetic, so it is here rather than assumed.
func (r Record) CVSS() (float64, bool) {
	for _, s := range r.Severity {
		switch strings.ToUpper(s.Type) {
		case "CVSS_V3", "CVSS_V4":
			if v, ok := BaseScore(s.Score); ok {
				return v, true
			}
		}
	}
	return 0, false
}

// metrics are the CVSS 3.1 base metric weights, as the specification
// publishes them.
var metrics = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// prUnchanged and prChanged are privileges required, which is the one
// metric whose weight depends on another: a scope change makes gaining
// privileges worth more to an attacker, so the same PR value scores higher.
var (
	prUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
)

// BaseScore computes a CVSS 3.1 base score from its vector.
//
// The arithmetic is the specification's, including its roundup, which is
// not ordinary rounding: 4.02 becomes 4.1. Implemented in integer
// arithmetic the way CVSS 3.1 defines it, because the floating-point
// version disagrees with the specification on values that land exactly on a
// tenth, and a score that differs from the published one by 0.1 is a score
// somebody will spend an afternoon on.
func BaseScore(vector string) (float64, bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	got := map[string]string{}
	for _, p := range parts {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		got[strings.ToUpper(k)] = strings.ToUpper(v)
	}
	if v, ok := got["CVSS"]; ok && !strings.HasPrefix(v, "3") {
		// A 4.0 vector uses different metrics and a different formula.
		// Refused rather than scored with the wrong arithmetic.
		return 0, false
	}
	changed := got["S"] == "C"

	w := func(metric string) (float64, bool) {
		v, ok := got[metric]
		if !ok {
			return 0, false
		}
		f, ok := metrics[metric][v]
		return f, ok
	}
	av, ok1 := w("AV")
	ac, ok2 := w("AC")
	ui, ok3 := w("UI")
	c, ok4 := w("C")
	i, ok5 := w("I")
	a, ok6 := w("A")
	prTable := prUnchanged
	if changed {
		prTable = prChanged
	}
	pr, ok7 := prTable[got["PR"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploit := 8.22 * av * ac * pr * ui
	sum := impact + exploit
	if changed {
		sum *= 1.08
	}
	return roundup(math.Min(sum, 10)), true
}

// roundup is CVSS 3.1's, which rounds up to one decimal place.
func roundup(x float64) float64 {
	n := int(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return (math.Floor(float64(n)/10000) + 1) / 10
}

// Advisory converts an OSV record into the shape internal/vuln ranks.
//
// known is when this organisation found out, which is not when the world
// was told. internal/vuln keeps the two apart because an age computed from
// the wrong one can be halved by changing a scanner's schedule.
func (r Record) Advisory(known time.Time) vuln.Advisory {
	a := vuln.Advisory{
		ID: r.ID, Aliases: r.Aliases,
		Summary:   firstOf(r.Summary, firstLine(r.Details), r.ID),
		Published: r.Published, Known: known.UTC(),
		FixedIn: map[string]string{},
	}
	if v, ok := r.CVSS(); ok {
		a.CVSS = v
		a.Severity = band(v)
	} else if s, ok := r.word(); ok {
		a.Severity = s
	}
	for _, af := range r.Affected {
		eco, name := af.Package.Ecosystem, af.Package.Name
		if eco == "" || name == "" {
			if e, n, ok := ParsePURL(af.Package.PURL); ok {
				eco, name = e, n
			}
		}
		if eco == "" || name == "" {
			continue
		}
		key := vuln.Key(eco, name)
		for _, rg := range af.Ranges {
			var open string
			var opened bool
			for _, ev := range rg.Events {
				switch {
				case ev.Introduced != "":
					open, opened = ev.Introduced, true
				case ev.Fixed != "":
					a.Affects = append(a.Affects, vuln.Range{
						Ecosystem: eco, Package: name,
						Introduced: open, Fixed: ev.Fixed,
					})
					if _, seen := a.FixedIn[key]; !seen {
						a.FixedIn[key] = ev.Fixed
					}
					opened = false
				case ev.LastAffected != "":
					a.Affects = append(a.Affects, vuln.Range{
						Ecosystem: eco, Package: name,
						Introduced: open,
					})
					opened = false
				}
			}
			if opened {
				// An introduced with nothing closing it: every version
				// from there on is affected and no fix exists.
				a.Affects = append(a.Affects, vuln.Range{
					Ecosystem: eco, Package: name, Introduced: open,
				})
			}
		}
		if len(af.Ranges) == 0 && len(af.Versions) > 0 {
			// An enumerated list rather than a range, which some
			// databases use for ecosystems with no ordering anybody
			// agrees on.
			for _, v := range af.Versions {
				a.Affects = append(a.Affects, vuln.Range{
					Ecosystem: eco, Package: name,
					Introduced: v, Fixed: "",
				})
			}
		}
	}
	return a
}

// word reads the severity a database wrote in words, when there is no
// vector to compute from.
func (r Record) word() (telemetry.Severity, bool) {
	v, ok := r.DatabaseSpecific["severity"]
	s, isStr := v.(string)
	if !ok || !isStr {
		return 0, false
	}
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return telemetry.SeverityCritical, true
	case "HIGH":
		return telemetry.SeverityHigh, true
	case "MODERATE", "MEDIUM":
		return telemetry.SeverityMedium, true
	case "LOW":
		return telemetry.SeverityLow, true
	}
	return 0, false
}

func band(v float64) telemetry.Severity {
	switch {
	case v >= 9.0:
		return telemetry.SeverityCritical
	case v >= 7.0:
		return telemetry.SeverityHigh
	case v >= 4.0:
		return telemetry.SeverityMedium
	default:
		return telemetry.SeverityLow
	}
}

func firstOf(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return s
}
