// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package posture

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// The tally says how many findings there are of each severity, zero
// included, and how much of the scanner's reach the scan covered: the rules
// that ran on the input they need, of every rule the scanner has.
func TestTallyCountsEverySeverityAndCoverage(t *testing.T) {
	rep := Scan(State{
		Policy: &auth.Policy{},
		Server: ServerFacts{AdminAddr: "0.0.0.0:8080"},
		Now:    now,
	}, nil)
	tl := rep.Tally()

	var got []Severity
	for _, c := range tl.Severities {
		got = append(got, c.Severity)
		if c.Count != rep.Counts[string(c.Severity)] {
			t.Errorf("the tally counts %d %s and the scan %d", c.Count, c.Severity, rep.Counts[string(c.Severity)])
		}
	}
	if want := []Severity{Critical, High, Medium, Low}; !reflect.DeepEqual(got, want) {
		t.Errorf("the tally lists %v; want every severity a rule has, most serious first, zero included: %v", got, want)
	}
	if tl.Findings != len(rep.Findings) {
		t.Errorf("the tally counts %d findings and the scan reported %d", tl.Findings, len(rep.Findings))
	}
	if tl.Rules != len(Rules()) {
		t.Errorf("coverage is out of %d rules and the scanner has %d", tl.Rules, len(Rules()))
	}
	if tl.NotChecked != len(rep.Skipped) || tl.Checked+tl.NotChecked != tl.Rules {
		t.Errorf("%d checked and %d not checked of %d rules, with %d skipped for want of input",
			tl.Checked, tl.NotChecked, tl.Rules, len(rep.Skipped))
	}
	// No tokens, no audit log and no files were given, so some rules
	// could not run: the case the coverage figure exists for.
	if tl.NotChecked == 0 {
		t.Error("control: every rule ran on a state with most of its inputs missing")
	}
	if want := fmt.Sprintf("%d of %d rules checked", tl.Checked, tl.Rules); tl.Coverage() != want {
		t.Errorf("coverage reads %q; want %q", tl.Coverage(), want)
	}
}

// An informational finding is counted when there is one, and a severity
// nothing found is still said with its zero.
func TestTallyNamesInfoOnlyWhenThereIsSome(t *testing.T) {
	rep := Report{Counts: map[string]int{string(Info): 2}, Checked: 3}
	var info int
	for _, c := range rep.Tally().Severities {
		if c.Severity == Info {
			info = c.Count
		}
	}
	if info != 2 {
		t.Errorf("two informational findings were counted as %d", info)
	}
}

// The tally holds counts, and no score: it is what every human-readable
// surface reads, so a score cannot reach one through it.
func TestTallyHoldsNoScore(t *testing.T) {
	ty := reflect.TypeOf(Tally{})
	for i := range ty.NumField() {
		f := ty.Field(i)
		if strings.Contains(strings.ToLower(f.Name+" "+f.Tag.Get("json")), "score") {
			t.Errorf("the tally carries %s, and a person reads it", f.Name)
		}
	}
}
