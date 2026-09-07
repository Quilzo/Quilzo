// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package a11y_test

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/a11y"
)

func reportFor(page string, findings ...a11y.Finding) *a11y.Report {
	r := &a11y.Report{Page: page, Findings: findings}
	// The same lists the checks produce.
	r.Checked = a11y.Covered()
	r.NotCheck = a11y.NotCovered()
	return r
}

// A criterion nobody checked gets no result, favourable or otherwise.
//
// This is the whole difference between this and a hand-written VPAT. Almost
// every one of those says "Supports" beside rows nobody tested, and a buyer
// cannot tell which were measured.
func TestUnevaluatedCriteriaAreNotClaimed(t *testing.T) {
	acr := a11y.BuildACR([]*a11y.Report{reportFor("index")})

	if len(acr.Evaluated) == 0 {
		t.Fatal("nothing was reported as evaluated")
	}
	// Criteria this program has no check for must not appear at all.
	for _, c := range acr.Evaluated {
		for _, unchecked := range []string{"1.2.2", "2.1.1", "1.4.4", "3.3.8"} {
			if c.Number == unchecked {
				t.Errorf("%s is reported as %q and this program has no check "+
					"for it", unchecked, c.Result)
			}
		}
	}
	if len(acr.NotEvaluated) == 0 {
		t.Error("the report claims to evaluate everything")
	}
}

// A finding turns Supports into Partially Supports, and names the page.
//
// A verdict with nothing behind it is the thing a reader cannot check.
func TestAFindingDowngradesTheCriterionAndNamesThePage(t *testing.T) {
	acr := a11y.BuildACR([]*a11y.Report{
		reportFor("index"),
		reportFor("about", a11y.Finding{
			Rule: "image-missing-alt", Severity: a11y.Blocking,
			Criterion: "WCAG 1.1.1", Detail: "an image has no alt",
		}),
	})

	var found bool
	for _, c := range acr.Evaluated {
		if c.Number != "1.1.1" {
			continue
		}
		found = true
		if c.Result != a11y.PartiallySupports {
			t.Errorf("1.1.1 is %q with a finding against it", c.Result)
		}
		if !strings.Contains(c.Remarks, "about") {
			t.Errorf("the remark does not name the page: %q", c.Remarks)
		}
	}
	if !found {
		t.Error("1.1.1 is missing from the report")
	}
}

// Every criterion the checks mention is reported, and none is invented.
//
// The rows come from what the checks say about themselves, so a check added
// later appears here without anybody remembering, and a check removed stops
// being claimed. That is the property that keeps a generated report true
// while the program changes underneath it.
func TestTheReportFollowsTheChecks(t *testing.T) {
	acr := a11y.BuildACR([]*a11y.Report{reportFor("index")})

	reported := map[string]bool{}
	for _, c := range acr.Evaluated {
		reported[c.Number] = true
	}

	// Every criterion named in the covered list has a row.
	for _, line := range a11y.Covered() {
		open := strings.LastIndex(line, "(")
		if open < 0 {
			continue
		}
		numbers := strings.Trim(line[open+1:], ")")
		for _, n := range strings.Split(numbers, ",") {
			n = strings.TrimSpace(n)
			if n == "" || strings.ContainsAny(n, " abcdefghijklmnopqrstuvwxyz") {
				continue
			}
			if !reported[n] {
				t.Errorf("the checks cover %s and the report omits it", n)
			}
		}
	}
}

// The caveat travels with the data, so a caller who would rather it were
// shorter cannot drop it.
func TestTheCaveatCannotBeLeftOut(t *testing.T) {
	acr := a11y.BuildACR([]*a11y.Report{reportFor("index")})
	for _, want := range []string{"not an audit", "unevaluated"} {
		if !strings.Contains(strings.ToLower(acr.Caveat), want) {
			t.Errorf("the caveat does not say %q: %s", want, acr.Caveat)
		}
	}
}

// A report over nothing says so rather than reporting clean.
func TestAnEmptyScanReportsNothing(t *testing.T) {
	acr := a11y.BuildACR(nil)
	if acr.Pages != 0 || len(acr.Evaluated) != 0 {
		t.Errorf("a scan of no pages produced %d row(s)", len(acr.Evaluated))
	}
	if acr.Caveat == "" {
		t.Error("even an empty report needs to say what it is not")
	}
}

// Criteria are ordered the way the standard numbers them.
//
// Sorted as strings, 1.4.11 comes before 1.4.2 — which reads as a mistake in a
// document somebody is checking against a numbered standard, and undermines
// the rest of it before they reach a row that matters.
func TestCriteriaAreOrderedNumerically(t *testing.T) {
	acr := a11y.BuildACR([]*a11y.Report{reportFor("index")})

	var order []string
	for _, c := range acr.Evaluated {
		order = append(order, c.Number)
	}
	for i := 1; i < len(order); i++ {
		if !numericallyBefore(order[i-1], order[i]) {
			t.Errorf("%s is listed before %s", order[i-1], order[i])
		}
	}
}

func numericallyBefore(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, y := 0, 0
		for _, r := range pa[i] {
			x = x*10 + int(r-'0')
		}
		for _, r := range pb[i] {
			y = y*10 + int(r-'0')
		}
		if x != y {
			return x < y
		}
	}
	return true
}
