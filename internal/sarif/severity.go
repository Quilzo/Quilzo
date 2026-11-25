// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"sort"
	"strings"
)

// How much a finding matters, what sort of finding it is, and what a log
// left out: the parts of reading a log that are the format's own rules,
// carried over with the reader from a security team's own tools. That
// reader turned results into its own alerts and wrote logs back to a code
// scanning platform; this one reads, so what turned results into alerts
// and the writer, with their tests, stayed where they were.

// Severity is how much a finding matters, on the bands a code scanning
// platform publishes for security-severity.
type Severity string

// The severities, each a band of security-severity.
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Severities is every severity, lowest first, so a count by severity is
// written in the same order every time and none is left out.
var Severities = []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Severity boundaries, as the platform publishes them.
//
// Named because the numbers are somebody else's and a reader should be able
// to check them against the source rather than against a comparison chain.
const (
	CriticalAt = 9.0
	HighAt     = 7.0
	MediumAt   = 4.0
)

// score maps a security-severity number onto a severity.
func score(f float64) Severity {
	switch {
	case f >= CriticalAt:
		return SeverityCritical
	case f >= HighAt:
		return SeverityHigh
	case f >= MediumAt:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// fromLevel maps SARIF's level onto a severity, which it is not.
//
// error, warning, note and none describe how the tool is configured, not
// how much the finding matters. This mapping exists because something has
// to be done when a tool gave nothing better, and SeverityOf says when it
// was used, so a count made with it can be recognised as one.
func fromLevel(level string) Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	}
	return SeverityLow
}

// SeverityOf is a result's severity, and whether it was read from a
// security-severity (the result's own, then its rule's) rather than stood
// in for by the level (the result's, then its rule's default).
func (r Run) SeverityOf(res Result) (s Severity, scored bool) {
	rule, _ := r.Rule(res)
	if f, ok := res.Properties.Score(); ok {
		return score(f), true
	}
	if f, ok := rule.Properties.Score(); ok {
		return score(f), true
	}
	lvl := res.Level
	if lvl == "" && rule.Configuration != nil {
		lvl = rule.Configuration.Level
	}
	return fromLevel(lvl), false
}

// Kind is what sort of finding a result is.
type Kind string

// The kinds a finding is told apart by: a weakness in code, a secret left
// in it, a dependency with a known flaw, and a configuration that is wrong.
const (
	KindWeakness      Kind = "weakness"
	KindSecret        Kind = "secret"
	KindDependency    Kind = "dependency"
	KindConfiguration Kind = "configuration"
)

// Kinds is every kind, in the order a count by kind is written.
var Kinds = []Kind{KindWeakness, KindSecret, KindDependency, KindConfiguration}

// KindOf is what sort of finding a result is, from its rule's tags and its
// own.
//
// Tags are the only place SARIF carries this and every tool spells them
// differently, so the match is on substrings and the default is a weakness,
// which is what a static analyser mostly finds and the least surprising
// thing to guess wrong.
func (r Run) KindOf(res Result) Kind {
	rule, _ := r.Rule(res)
	hay := strings.ToLower(strings.Join(append(append([]string{}, rule.Properties.Tags...), res.Properties.Tags...), " ") +
		" " + rule.ID + " " + res.RuleID + " " + r.Tool.Driver.Name)
	switch {
	case strings.Contains(hay, "secret"), strings.Contains(hay, "credential"),
		strings.Contains(hay, "token"), strings.Contains(hay, "key-leak"):
		return KindSecret
	case strings.Contains(hay, "dependency"), strings.Contains(hay, "sca"),
		strings.Contains(hay, "supply-chain"), strings.Contains(hay, "osv"),
		strings.Contains(hay, "vulnerable-package"):
		return KindDependency
	case strings.Contains(hay, "misconfig"), strings.Contains(hay, "configuration"),
		strings.Contains(hay, "iac"), strings.Contains(hay, "terraform"):
		return KindConfiguration
	}
	return KindWeakness
}

// Gap is something a tool left out of its results, and what it costs.
type Gap struct {
	// What is what was left out, in the format's own terms.
	What string `json:"what"`
	// Count is how many results left it out.
	Count int `json:"count"`
	// Costs is what leaving it out does, in a sentence this package
	// writes: no part of it is read from the log.
	Costs string `json:"costs"`
	// From is the tool that left it out of the most results, by the name
	// the log gives it, which is the log's text and not this package's.
	From string `json:"from"`
}

// Gaps is what a log's results left out, most often first: a fingerprint,
// a security severity, a file location. What a platform would accept and
// not display is Check's to say.
func (l Log) Gaps() []Gap {
	churn, levelled, placeless := map[string]int{}, map[string]int{}, map[string]int{}
	for _, run := range l.Runs {
		tool := firstOf(run.Tool.Driver.Name, "an unnamed tool")
		for _, res := range run.Results {
			if res.Churns() {
				churn[tool]++
			}
			if _, scored := run.SeverityOf(res); !scored {
				levelled[tool]++
			}
			if _, _, ok := res.Where(); !ok {
				placeless[tool]++
			}
		}
	}
	var gaps []Gap
	add := func(by map[string]int, what, costs string) {
		if n, from := worst(by); n > 0 {
			gaps = append(gaps, Gap{What: what, Count: n, Costs: costs, From: from})
		}
	}
	add(churn, "no partialFingerprints.primaryLocationLineHash",
		"the platform falls back to hashing the line, so editing it closes the alert and opens a new one. A "+
			"reformat produces a wave of new findings and a matching wave of fixed ones, and the conclusion drawn "+
			"is that the scanner is noisy")
	add(levelled, "no security-severity",
		"SARIF's level says how the tool is configured, not how much a finding matters, so these were ranked on "+
			"the wrong axis")
	add(placeless, "no file location", "nobody can open them, so they are a number rather than work")
	sort.SliceStable(gaps, func(i, j int) bool { return gaps[i].Count > gaps[j].Count })
	return gaps
}

// worst is the total of a gap and the tool responsible for most of it, the
// first by name where two are responsible for as much.
func worst(by map[string]int) (total int, from string) {
	names := make([]string, 0, len(by))
	for n, c := range by {
		names = append(names, n)
		total += c
	}
	sort.Strings(names)
	at := 0
	for _, n := range names {
		if by[n] > at {
			from, at = n, by[n]
		}
	}
	return total, from
}
