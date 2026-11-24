// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import "fmt"

// Tally is a scan as a person reads it first: how many findings there are
// of each severity, and how much of the scanner's reach the scan covered.
//
// It is counts and nothing else, by decision. The scan used to open on a
// score out of a hundred, which put a world-readable key file and an input
// nobody supplied on one scale: two installations with nothing in common
// could read the same, and the one number on the screen became the number
// that was reported and argued about instead of the findings. Counts by
// severity say what is wrong, and coverage, rules checked of rules, says
// how much of that question was asked at all, which a score folded in where
// nobody could see it. Report.Score stays in the JSON for the scripts that
// read it, and no human-readable surface reads it.
type Tally struct {
	// Severities is every severity a rule reports at, most serious first,
	// with how many findings the scan reported at it. A zero is said: a
	// severity left out reads as one forgotten, not one found clean.
	// Informational findings are counted when there are some, since no
	// rule reports at that level today.
	Severities []SeverityCount `json:"severities"`
	// Findings is every finding reported, and Suppressed those silenced
	// as accepted risks until a date.
	Findings   int `json:"findings"`
	Suppressed int `json:"suppressed"`
	// Rules is every rule the scanner has: the denominator of coverage,
	// taken from the scanner's own catalogue.
	Rules int `json:"rules"`
	// Checked is the rules that ran on the input they need, and NotChecked
	// those whose input was not supplied, so their silence is not a pass.
	Checked    int `json:"checked"`
	NotChecked int `json:"not_checked"`
}

// SeverityCount is how many findings a scan reported at one severity.
type SeverityCount struct {
	Severity Severity `json:"severity"`
	Count    int      `json:"count"`
}

// Tally is the report's counts and coverage.
func (r Report) Tally() Tally {
	t := Tally{
		Findings:   len(r.Findings),
		Suppressed: len(r.Suppressed),
		Rules:      r.Checked,
		NotChecked: len(r.Skipped),
	}
	t.Checked = t.Rules - t.NotChecked
	for _, s := range []Severity{Critical, High, Medium, Low, Info} {
		n := r.Counts[string(s)]
		if s == Info && n == 0 {
			continue
		}
		t.Severities = append(t.Severities, SeverityCount{s, n})
	}
	return t
}

// Coverage is how much the scan asked, in words: "58 of 65 rules checked".
// It is n of N and not a percentage, so the denominator is always in view.
func (t Tally) Coverage() string {
	return fmt.Sprintf("%d of %d rules checked", t.Checked, t.Rules)
}
