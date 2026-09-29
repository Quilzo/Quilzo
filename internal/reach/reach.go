// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package reach answers whether a vulnerable function is used at all.
//
// # The number everybody quotes
//
// Semgrep looked at eleven hundred repositories and found about two
// percent of dependency alerts were reachable. That is the largest single
// reduction available in this area and it is why every vendor now leads
// with reachability: a queue of four hundred findings where eight matter
// is a queue somebody can work.
//
// # The two things the number hides
//
// The first is that reachability is not a property of a scanner. It is a
// property of the advisory. To ask whether a vulnerable function is called
// you have to know which function, and most advisory formats do not say.
// CVE does not. GitHub's advisories do not. The Go vulnerability database
// does, in ecosystem_specific.imports, which is why Go tooling can do this
// and why the same tool against a Python project is doing something else
// and calling it the same thing.
//
// The second is that the published figures are for direct dependencies.
// Transitive ones are matched by version and not analysed — and transitive
// is where most findings are. So a report saying two percent are reachable
// is describing a filter that ran on a minority of the queue, and the
// ninety-eight percent includes everything nobody looked at.
//
// Both of those collapse into one failure: unanalysed and unreachable look
// identical on a dashboard. A finding nobody could assess and a finding
// somebody assessed and cleared both appear as absence, and only one of
// them is safe. So this has four verdicts rather than two, and the two
// extra ones are the point.
//
// # What this does and does not prove
//
// A reference is an upper bound on reachability from the code that was read,
// and the code that was read is this module and nothing else. Vendored
// dependencies, the module cache and the standard library are not walked.
//
// So NotReferenced says this module does not call the symbol itself. It does
// not say nothing calls it: a vulnerable crypto/x509 function is reached by
// every http.Get without the program ever naming it, and a dependency can call
// a vulnerable function in another dependency the same way. That is a real and
// useful fact — it is most of what separates a direct exposure from one that
// arrives through somebody else's code — and it is not a proof of
// unreachability. Only a call graph over the whole program is, which is what
// govulncheck builds.
//
// The consequence for callers: NotReferenced may propose a VEX statement, and
// a person signs it with the question of indirect reach in front of them. It
// must never close a finding on its own.
//
// If a symbol is mentioned, it might be called, or it might sit in a branch
// nothing takes. Saying "referenced" rather than "reachable" for that case
// costs a little precision and buys the property that the tool never claims
// something is exploitable when it only knows the name appears.
package reach

import (
	"fmt"
	"sort"
	"strings"
)

// Verdict is what could be established about one advisory against one
// codebase.
type Verdict string

const (
	// NotReferenced: this module's own source never names the vulnerable
	// symbol, so it does not call it directly. Dependencies and the standard
	// library were not read and may still reach it — see the package note.
	NotReferenced Verdict = "not-referenced"
	// Referenced: the symbol is mentioned. It may be called, or it may sit
	// in a branch nothing takes — a call graph would narrow it and this
	// does not claim to have one.
	Referenced Verdict = "referenced"
	// Unanalysed: the advisory names no symbol, so there is nothing to
	// look for. Not a clean result and not a dirty one.
	Unanalysed Verdict = "unanalysed"
	// NoSource: there is no source for this dependency to analyse, which
	// is the ordinary case for a transitive package nobody vendored.
	NoSource Verdict = "no-source"
)

// Verdicts in the order a queue is worked.
var Verdicts = []Verdict{Referenced, Unanalysed, NoSource, NotReferenced}

// Known reports whether a verdict is one of the four.
func (v Verdict) Known() bool {
	for _, c := range Verdicts {
		if c == v {
			return true
		}
	}
	return false
}

// Settled reports whether anything was actually established.
//
// The question a filter rate has to be honest about. Only two of the four
// verdicts are conclusions; the other two are the absence of one, and
// counting them as clean is how a two percent figure is manufactured.
func (v Verdict) Settled() bool {
	return v == NotReferenced || v == Referenced
}

// Clears reports whether this verdict removes a finding from the queue.
func (v Verdict) Clears() bool { return v == NotReferenced }

// Why explains a verdict in the words somebody triaging needs.
func (v Verdict) Why() string {
	switch v {
	case NotReferenced:
		return "this module's own code never names the vulnerable symbol, " +
			"so it does not call it directly. Dependencies and the standard " +
			"library were not read and can still reach it, so this is " +
			"grounds for a VEX statement a person signs, not for closing " +
			"the finding"
	case Referenced:
		return "the symbol is mentioned in this source. It may be called, " +
			"or it may sit in a branch nothing takes — this looked for the " +
			"name and does not claim to have followed the calls"
	case Unanalysed:
		return "the advisory names no affected symbol, so there is nothing " +
			"to look for. Most advisory formats carry none: CVE does not, " +
			"and neither do GitHub's. This is not a clean result"
	case NoSource:
		return "there is no source for this dependency here, which is the " +
			"ordinary case for something pulled in four levels down. " +
			"Nothing was examined"
	}
	return string(v)
}

// Ecosystem is whether a package ecosystem's advisories carry the symbol
// data reachability needs.
//
// A property of the ecosystem rather than of any scanner, and the reason
// "we do reachability" needs a caveat nobody gives it.
type Ecosystem struct {
	Name string `json:"name"`
	// Symbols says advisories in this ecosystem name affected functions.
	Symbols bool `json:"symbols"`
	// Where names the field they are in, when there is one.
	Where string `json:"where,omitempty"`
	Note  string `json:"note,omitempty"`
}

// Ecosystems is what each one supports.
func Ecosystems() []Ecosystem {
	return []Ecosystem{
		{
			Name: "Go", Symbols: true,
			Where: "ecosystem_specific.imports[].symbols",
			Note: "the one ecosystem where the toolchain, the module " +
				"system and the vulnerability database all name symbols " +
				"the same way. Everything below is a consequence of that " +
				"not being true elsewhere",
		},
		{
			Name: "npm", Symbols: false,
			Note: "advisories describe the vulnerability in prose. A " +
				"scanner claiming reachability here is inferring the " +
				"symbol from the text or from its own database",
		},
		{Name: "PyPI", Symbols: false,
			Note: "as npm, and harder: a dynamic import cannot be resolved " +
				"statically, so even with symbols a reference is a weaker " +
				"bound"},
		{Name: "Maven", Symbols: false},
		{Name: "crates.io", Symbols: false,
			Note: "RustSec records a function in prose for some advisories " +
				"and not in a field anything can read"},
		{Name: "NuGet", Symbols: false},
		{Name: "RubyGems", Symbols: false},
		{Name: "Packagist", Symbols: false},
	}
}

// Supports reports whether an ecosystem's advisories name symbols.
func Supports(ecosystem string) (Ecosystem, bool) {
	for _, e := range Ecosystems() {
		if strings.EqualFold(e.Name, ecosystem) {
			return e, e.Symbols
		}
	}
	return Ecosystem{Name: ecosystem}, false
}

// Result is one advisory assessed against one codebase.
type Result struct {
	Advisory string  `json:"advisory"`
	Package  string  `json:"package"`
	Verdict  Verdict `json:"verdict"`
	// Symbols are the affected symbols the advisory named, and Found the
	// ones this source mentions.
	Symbols []string `json:"symbols,omitempty"`
	Found   []string `json:"found,omitempty"`
	// Where are the files a symbol was mentioned in, so somebody can go
	// and look rather than take this on trust.
	Where []string `json:"where,omitempty"`
}

// Says describes a result.
func (r Result) Says() string {
	switch r.Verdict {
	case NotReferenced:
		return fmt.Sprintf(
			"%s affects %s and names %d symbol(s), none of which appear "+
				"here", r.Advisory, r.Package, len(r.Symbols))
	case Referenced:
		return fmt.Sprintf("%s affects %s and this source mentions %s",
			r.Advisory, r.Package, strings.Join(r.Found, ", "))
	case Unanalysed:
		return fmt.Sprintf(
			"%s affects %s and names no symbol, so nothing could be "+
				"checked", r.Advisory, r.Package)
	case NoSource:
		return fmt.Sprintf(
			"%s affects %s and there is no source for it here",
			r.Advisory, r.Package)
	}
	return r.Advisory
}

// Filter is what a set of results does to a queue, honestly.
//
// The number a vendor quotes and the number worth having are different,
// and both are here. Cleared over Total is what a marketing page reports.
// Cleared over Settled is the rate among findings anything was actually
// established about, and the gap between them is how much of the filter
// was silence.
type Filter struct {
	Total   int `json:"total"`
	Cleared int `json:"cleared"`
	Kept    int `json:"kept"`
	// Silent is the findings nothing could be said about: no symbol in the
	// advisory, or no source to look at.
	Silent   int             `json:"silent"`
	Settled  int             `json:"settled"`
	ByReason map[Verdict]int `json:"by_reason"`
}

// Measure summarises a set of results.
func Measure(in []Result) Filter {
	f := Filter{Total: len(in), ByReason: map[Verdict]int{}}
	for _, r := range in {
		f.ByReason[r.Verdict]++
		switch {
		case r.Verdict.Clears():
			f.Cleared++
			f.Settled++
		case r.Verdict.Settled():
			f.Kept++
			f.Settled++
		default:
			f.Silent++
		}
	}
	return f
}

// Claimed is the filter rate over everything, which is the figure a
// product page reports.
func (f Filter) Claimed() float64 {
	if f.Total == 0 {
		return 0
	}
	return float64(f.Cleared) / float64(f.Total)
}

// Real is the filter rate among findings something was established about.
func (f Filter) Real() float64 {
	if f.Settled == 0 {
		return 0
	}
	return float64(f.Cleared) / float64(f.Settled)
}

// Honest reports whether the two rates are close enough that quoting the
// first is not misleading.
//
// A tenth. Below that the headline figure is mostly silence, and a report
// that led with it would be doing the thing this package exists to avoid.
func (f Filter) Honest() bool {
	if f.Total == 0 {
		return true
	}
	return float64(f.Silent)/float64(f.Total) <= 0.1
}

// Why describes a filter, leading with the part that is usually left out.
func (f Filter) Why() string {
	if f.Total == 0 {
		return "nothing was assessed"
	}
	out := fmt.Sprintf(
		"%d of %d finding(s) cleared, which is %.0f%%", f.Cleared, f.Total,
		f.Claimed()*100)
	if f.Silent == 0 {
		return out + ". Every finding was assessed, so that figure is what " +
			"it looks like"
	}
	return out + fmt.Sprintf(
		". But %d of them could not be assessed at all — %d because the "+
			"advisory names no symbol and %d because there is no source "+
			"here — so among the %d anything was established about, the "+
			"rate is %.0f%%. Unassessed and cleared look the same on a "+
			"dashboard and only one of them is safe",
		f.Silent, f.ByReason[Unanalysed], f.ByReason[NoSource], f.Settled,
		f.Real()*100)
}

// Worst orders results so the ones somebody has to look at come first.
func Worst(in []Result) []Result {
	rank := map[Verdict]int{
		Referenced: 0, Unanalysed: 1, NoSource: 2, NotReferenced: 3,
	}
	out := append([]Result(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Verdict] != rank[out[j].Verdict] {
			return rank[out[i].Verdict] < rank[out[j].Verdict]
		}
		return out[i].Advisory < out[j].Advisory
	})
	return out
}
