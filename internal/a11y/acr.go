package a11y

import (
	"fmt"
	"sort"
	"strings"
)

// An accessibility conformance report, generated rather than written.
//
// # Why this exists
//
// A VPAT — completed, it is called an Accessibility Conformance Report — is
// increasingly the price of entry for selling software to a government or a
// large institution, and the European Accessibility Act has required technical
// documentation of conformance since June 2025.
//
// Almost every one of them is written by hand, by somebody with an interest in
// the answer, months after the software changed. The result is a document that
// says "Supports" beside criteria nobody tested, and a buyer has no way to
// tell which rows were measured and which were hoped.
//
// # What makes this one different, and it is one thing
//
// It reports only what was actually evaluated, on the content actually in this
// store, and says "Not Evaluated" everywhere else with the reason. A criterion
// this program cannot check does not get a favourable answer; it gets no
// answer, which is the truthful one.
//
// # Why it does not enumerate WCAG
//
// It would have to carry a copy of the normative success-criteria list, and a
// copy goes stale: WCAG 2.2 removed a criterion that 2.1 had, and a report
// generated from an old copy is confidently wrong in a document whose whole
// purpose is to be relied on. The same argument as the classification register
// in internal/marking — the authority publishes the list, and a stale local
// copy is worse than a pointer to it.
//
// So this reports the criteria this program evaluates, which it knows exactly,
// and states plainly that everything else is unevaluated. A reader wanting the
// full table has W3C's, and a reader wanting to know what was measured has
// this.

// Evaluation is what this program can say about one success criterion.
type Evaluation string

const (
	// Supports means every check for this criterion ran and found nothing.
	Supports Evaluation = "Supports"
	// PartiallySupports means a check for it found something.
	PartiallySupports Evaluation = "Partially Supports"
	// NotEvaluated means no automated check covers it here.
	NotEvaluated Evaluation = "Not Evaluated"
)

// Criterion is one row of the report.
type Criterion struct {
	// Number is the WCAG success criterion, e.g. "1.1.1".
	Number string `json:"number"`
	// Checks are the rules this program runs for it, in its own words.
	Checks []string `json:"checks"`
	// Result is what the scan found.
	Result Evaluation `json:"result"`
	// Remarks name the pages that failed, so a row is checkable rather than
	// a verdict.
	Remarks string `json:"remarks,omitempty"`
}

// ACR is the whole report.
type ACR struct {
	// Pages is how many were scanned. A report over nothing is a report
	// about nothing, and the number is what says which this is.
	Pages int `json:"pages"`
	// Evaluated is every criterion this program checks, with its result.
	Evaluated []Criterion `json:"evaluated"`
	// NotEvaluated is what it cannot check, in the terms it uses elsewhere.
	NotEvaluated []string `json:"not_evaluated"`
	// Caveat is what this document is not. Carried in the data rather than
	// printed by the caller, so it cannot be dropped by a caller who would
	// rather it were shorter.
	Caveat string `json:"caveat"`
}

// caveat is the paragraph that keeps this honest.
const caveat = "This report covers the success criteria this program " +
	"evaluates automatically, against the content in this store at the time " +
	"it ran. Every other criterion is unevaluated and is reported as such: a " +
	"criterion nobody checked has no result, and a favourable one would be " +
	"an invention. Research on automated accessibility testing consistently " +
	"puts the share of WCAG criteria any tool can decide at roughly a third " +
	"to a half, so a report of this kind is a starting point for an audit " +
	"and is not one. It is not an audit, not a claim of conformance, and not " +
	"a substitute for testing with the people who use assistive technology."

// BuildACR turns a set of page reports into a conformance report.
//
// The criteria come from the findings and from the covered list, which are
// both written by the checks themselves — so a check added later appears here
// without anybody remembering to add it, and a check removed stops being
// claimed.
func BuildACR(reports []*Report) ACR {
	out := ACR{Pages: len(reports), Caveat: caveat}
	if len(reports) == 0 {
		return out
	}

	// What is checked, from the first report: every page is checked the same
	// way, and the list is a property of the program rather than the page.
	checksFor := map[string][]string{}
	for _, line := range reports[0].Checked {
		for _, number := range criteriaIn(line) {
			checksFor[number] = append(checksFor[number], line)
		}
	}

	// What failed, from every page.
	failures := map[string][]string{}
	for _, r := range reports {
		for _, f := range r.Findings {
			number := strings.TrimSpace(strings.TrimPrefix(f.Criterion, "WCAG"))
			if number == "" {
				continue
			}
			failures[number] = append(failures[number], r.Page)
		}
	}

	numbers := make([]string, 0, len(checksFor))
	for n := range checksFor {
		numbers = append(numbers, n)
	}
	// A criterion that only appears in a finding is still evaluated: the check
	// exists, it just did not get named in the covered list.
	for n := range failures {
		if _, known := checksFor[n]; !known {
			numbers = append(numbers, n)
		}
	}
	// Numerically, part by part: sorted as strings, 1.4.11 comes before
	// 1.4.2, which reads as a mistake in a document somebody is checking
	// against a numbered standard.
	sort.Slice(numbers, func(i, j int) bool {
		return lessCriterion(numbers[i], numbers[j])
	})

	for _, n := range numbers {
		c := Criterion{Number: n, Checks: checksFor[n], Result: Supports}
		if pages := failures[n]; len(pages) > 0 {
			c.Result = PartiallySupports
			c.Remarks = fmt.Sprintf("%d finding(s) on: %s",
				len(pages), strings.Join(unique(pages), ", "))
		}
		out.Evaluated = append(out.Evaluated, c)
	}
	out.NotEvaluated = append([]string(nil), reports[0].NotCheck...)
	return out
}

// lessCriterion orders two success criteria the way the standard numbers them.
func lessCriterion(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, nb := atoi(pa[i]), atoi(pb[i])
		if na != nb {
			return na < nb
		}
	}
	return len(pa) < len(pb)
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// criteriaIn pulls the criterion numbers out of a line like
// "colour contrast in the theme, in both schemes (1.4.3, 1.4.11)".
//
// Parsed from the same string a person reads, rather than declared twice. Two
// declarations of the same fact are two things to keep in step, and the one
// nobody reads is the one that drifts.
func criteriaIn(line string) []string {
	open := strings.LastIndex(line, "(")
	close := strings.LastIndex(line, ")")
	if open < 0 || close < open {
		return nil
	}
	var out []string
	for _, part := range strings.Split(line[open+1:close], ",") {
		part = strings.TrimSpace(part)
		if looksLikeCriterion(part) {
			out = append(out, part)
		}
	}
	return out
}

// looksLikeCriterion accepts "1.4.11" and refuses prose.
func looksLikeCriterion(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
