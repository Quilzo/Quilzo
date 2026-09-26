// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package vuln is a vulnerability queue that is not sorted by severity.
//
// # The arithmetic everybody has and nobody uses
//
// CVSS measures how bad a vulnerability would be if it were exploited. It is
// a severity, and FIRST says so. Every scanner sorts by it anyway, so every
// team works down a list of Criticals while the Medium with a public exploit
// in active use sits at number four hundred.
//
// The measurements are not close. Cyentia and FIRST held coverage constant at
// 82% of vulnerabilities that turn out to be exploited: an EPSS-driven
// strategy reaches it by remediating just under 14,000 CVEs, and a
// CVSS-seven-and-above strategy reaches the same coverage by remediating
// about 110,000. Eight times the work for the same result. Roughly 6% of
// published CVEs are ever exploited at all, so a queue ordered by severity
// spends most of its effort on the 94%.
//
// So severity is a tiebreak here and nothing more. The order is: somebody has
// attested that this is being exploited, then the probability that it will
// be, then whether it is reachable, then how long we have known — and CVSS
// last, to break ties among things that are otherwise equal.
//
// # Exploited is a claim with an author
//
// Every product treats "in CISA's KEV" as a boolean called exploited. That
// stopped being defensible in November 2025, when ENISA became a CVE Root for
// European entities and the EUVD began maintaining its own known-exploited
// data reflecting European visibility. There are now at least two such lists
// and they do not agree, because they are two agencies' threat priorities
// rather than two measurements of one fact.
//
// A deployment in Europe whose tooling defines exploitation as "CISA says so"
// has adopted one government's priorities as the definition. Exploited here
// is a list of attestations, each with who said it and when, and a finding
// names the source.
//
// # A version comparison that cannot decide says affected
//
// Ecosystems version things differently and no comparator is right for all of
// them. The failure direction is the whole question: a comparison that cannot
// parse a version and answers "not affected" silently closes a finding, and
// nobody ever looks at it again. Here it answers "cannot tell", which ranks
// as affected and says why.
package vuln

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Attestation is somebody saying a vulnerability is being exploited.
type Attestation struct {
	// By is who says so: "cisa-kev", "enisa-euvd", a vendor, or this
	// organisation's own observation, which is the most credible of all and
	// the one no feed will ever carry.
	By string    `json:"by"`
	At time.Time `json:"at"`
	// Ref points at the evidence.
	Ref string `json:"ref,omitempty"`
	// Note is what was actually observed, where the source says.
	Note string `json:"note,omitempty"`
}

// Validate refuses an attestation nobody can follow up.
func (a Attestation) Validate() error {
	if strings.TrimSpace(a.By) == "" {
		return fmt.Errorf(
			"an attestation of exploitation needs a source. \"Exploited\" " +
				"with nobody's name on it is a boolean pretending to be a " +
				"fact, and the two lists that publish these do not agree")
	}
	if a.At.IsZero() {
		return fmt.Errorf("%s does not say when it said so", a.By)
	}
	return nil
}

// Advisory is what the world says about one vulnerability.
type Advisory struct {
	// ID is the primary identifier: a CVE, a GHSA, a vendor's own.
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary"`

	// Published is when the world was told. Known is when this organisation
	// found out, which is the clock every deadline here runs on.
	//
	// Separate for the reason the spool keeps two clocks and a breach notice
	// keeps two dates: a vulnerability disclosed in March and picked up by a
	// scanner in September has an age of six months or of nothing at all,
	// depending which date somebody chose, and a metric that can be halved
	// by changing a scanner's schedule is not a metric.
	Published time.Time `json:"published,omitempty"`
	Known     time.Time `json:"known"`

	// CVSS is the base score, and Severity the band. Both a severity.
	CVSS     float64            `json:"cvss,omitempty"`
	Severity telemetry.Severity `json:"severity,omitempty"`

	// EPSS is the probability of exploitation in the next thirty days, and
	// is treated as a probability rather than as a fourth severity band.
	EPSS   float64   `json:"epss,omitempty"`
	EPSSAt time.Time `json:"epss_at,omitempty"`

	// Exploited is who has attested to exploitation. Empty is not "no".
	Exploited []Attestation `json:"exploited,omitempty"`

	// Affects are the ranges this applies to, and FixedIn the first version
	// that is not affected, by ecosystem and package.
	Affects []Range           `json:"affects,omitempty"`
	FixedIn map[string]string `json:"fixed_in,omitempty"`
}

// Range is one package this advisory applies to.
type Range struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	// Introduced and Fixed bound the affected versions. An empty Fixed means
	// no fix exists yet, which changes what the work is rather than how
	// urgent it is.
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Key is how a package is named across the two halves.
func Key(ecosystem, name string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + ":" +
		strings.ToLower(strings.TrimSpace(name))
}

// Validate refuses an advisory nothing can be decided from.
func (a Advisory) Validate() error {
	if strings.TrimSpace(a.ID) == "" {
		return fmt.Errorf("an advisory needs an identifier")
	}
	if strings.TrimSpace(a.Summary) == "" {
		return fmt.Errorf("%s says nothing about what it is", a.ID)
	}
	if a.Known.IsZero() {
		return fmt.Errorf(
			"%s does not say when this organisation found out. Every "+
				"deadline here runs from that, and running it from the "+
				"publication date makes a scanner's schedule the thing that "+
				"decides whether a team is on time", a.ID)
	}
	if a.EPSS < 0 || a.EPSS > 1 {
		return fmt.Errorf(
			"%s has an EPSS of %v. It is a probability between 0 and 1, not "+
				"a percentage and not a score out of ten", a.ID, a.EPSS)
	}
	if a.CVSS < 0 || a.CVSS > 10 {
		return fmt.Errorf("%s has a CVSS of %v", a.ID, a.CVSS)
	}
	for _, at := range a.Exploited {
		if err := at.Validate(); err != nil {
			return fmt.Errorf("%s: %w", a.ID, err)
		}
	}
	for _, r := range a.Affects {
		if strings.TrimSpace(r.Package) == "" ||
			strings.TrimSpace(r.Ecosystem) == "" {
			return fmt.Errorf("%s affects a package with no name", a.ID)
		}
	}
	return nil
}

// Attested reports whether anybody says this is being exploited, and who.
func (a Advisory) Attested() (bool, []string) {
	var who []string
	for _, at := range a.Exploited {
		who = append(who, at.By)
	}
	sort.Strings(who)
	return len(who) > 0, who
}

// Fresh reports whether the EPSS figure is recent enough to act on.
//
// EPSS is recomputed daily and moves: a vulnerability at 0.02 the day it is
// published can be at 0.7 a week later when an exploit lands. A figure from
// last month is a figure about last month, and a queue ordered by it is
// ordered by what was probable then.
func (a Advisory) Fresh(now time.Time) bool {
	return !a.EPSSAt.IsZero() && now.Sub(a.EPSSAt) <= 7*24*time.Hour
}

// Component is one thing installed somewhere.
type Component struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// Where it is installed, issuer-qualified like everything else.
	Where telemetry.ID `json:"where"`
	// Direct says this is something somebody chose, rather than something
	// pulled in by something they chose.
	//
	// Not a severity and not a discount. It decides what the work is: a
	// direct dependency is a version bump, and a transitive one four levels
	// down is a conversation with whoever owns the thing above it.
	Direct bool `json:"direct,omitempty"`
	// Reachable records whether the vulnerable code is on a path this
	// deployment can execute. Unknown by default; see Exposure.
	Reachable *bool `json:"reachable,omitempty"`
}

// Key is this component's package identity.
func (c Component) Key() string { return Key(c.Ecosystem, c.Name) }

// Validate refuses a component nothing can be matched against.
func (c Component) Validate() error {
	if strings.TrimSpace(c.Ecosystem) == "" {
		return fmt.Errorf(
			"%q does not say what ecosystem it is from. \"jackson\" in Maven "+
				"and \"jackson\" in npm are different packages with "+
				"different advisories", c.Name)
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("a component needs a name")
	}
	if strings.TrimSpace(c.Version) == "" {
		return fmt.Errorf(
			"%s has no version, so nothing can say whether it is affected",
			c.Key())
	}
	if c.Where.Zero() {
		return fmt.Errorf("%s is not installed anywhere", c.Key())
	}
	if c.Where.Issuer == "" {
		return fmt.Errorf("%s is installed on %q, which names no system",
			c.Key(), c.Where.Value)
	}
	return nil
}

// Verdict is what a version comparison concluded.
type Verdict string

const (
	// Vulnerable is the installed version is in an affected range.
	Vulnerable Verdict = "vulnerable"
	// Patched is it is at or past a fixed version.
	Patched Verdict = "patched"
	// Outside is it is below the introduced version.
	Outside Verdict = "outside"
	// Undecided is the versions could not be compared.
	//
	// Ranks as vulnerable, deliberately. A comparator that cannot parse a
	// version and answers "patched" closes a finding nobody looks at again,
	// and the ecosystems where parsing fails — distribution packages with
	// epochs, vendor builds, anything with a local suffix — are exactly the
	// ones where the answer matters.
	Undecided Verdict = "undecided"
)

// Applies decides whether an advisory affects an installed component.
func (a Advisory) Applies(c Component) (Verdict, string) {
	var best Verdict = Outside
	var why string
	var matched bool
	for _, r := range a.Affects {
		if Key(r.Ecosystem, r.Package) != c.Key() {
			continue
		}
		matched = true
		v, reason := r.covers(c.Version)
		switch v {
		case Vulnerable:
			return Vulnerable, reason
		case Undecided:
			best, why = Undecided, reason
		case Patched:
			if best != Undecided {
				best, why = Patched, reason
			}
		}
	}
	if !matched {
		return Outside, fmt.Sprintf("%s does not mention %s", a.ID, c.Key())
	}
	return best, why
}

func (r Range) covers(version string) (Verdict, string) {
	if r.Introduced != "" {
		cmp, ok := Compare(version, r.Introduced)
		if !ok {
			return Undecided, fmt.Sprintf(
				"cannot compare %s against %s, so this reads as affected "+
					"rather than being closed on a guess", version,
				r.Introduced)
		}
		if cmp < 0 {
			return Outside, fmt.Sprintf("%s is before %s", version,
				r.Introduced)
		}
	}
	if r.Fixed == "" {
		return Vulnerable, "no fixed version has been published"
	}
	cmp, ok := Compare(version, r.Fixed)
	if !ok {
		return Undecided, fmt.Sprintf(
			"cannot compare %s against the fix in %s, so this reads as "+
				"affected rather than being closed on a guess", version,
			r.Fixed)
	}
	if cmp >= 0 {
		return Patched, fmt.Sprintf("%s is at or past the fix in %s",
			version, r.Fixed)
	}
	return Vulnerable, fmt.Sprintf("%s is before the fix in %s", version,
		r.Fixed)
}

// Compare orders two versions. The bool is false when it cannot tell.
//
// Dotted numeric segments, with an optional pre-release suffix after a hyphen
// that sorts before the release. That covers semantic versioning and most of
// what language ecosystems use, and it deliberately does not try to cover
// distribution packages with epochs and revisions, or vendor builds, or
// anything with a local suffix.
//
// Returning false for those is the whole point. A comparator that guesses at
// 1:2.4.57-2ubuntu2 is a comparator that will one day guess "patched", and
// the finding it closes is gone.
func Compare(a, b string) (int, bool) {
	an, apre, aok := parse(a)
	bn, bpre, bok := parse(b)
	if !aok || !bok {
		return 0, false
	}
	for i := 0; i < len(an) || i < len(bn); i++ {
		av, bv := 0, 0
		if i < len(an) {
			av = an[i]
		}
		if i < len(bn) {
			bv = bn[i]
		}
		if av != bv {
			if av < bv {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case apre == bpre:
		return 0, true
	case apre == "":
		// 1.2.3 is after 1.2.3-rc1.
		return 1, true
	case bpre == "":
		return -1, true
	case apre < bpre:
		// Two pre-releases, compared as strings. It gets alpha before beta
		// before rc by luck of the alphabet and rc10 before rc9 by the same
		// luck running out; that is a real limit, and it decides only the
		// order of two pre-release builds of the same version.
		return -1, true
	default:
		return 1, true
	}
}

// preWords are the suffixes that unambiguously mean "before the release".
//
// A closed list, because the same syntax means the opposite in packaging:
// 1.2.3-rc1 is before 1.2.3 and 1.2.3-0ubuntu1 is after it. Anything not on
// this list is refused, which reads as affected.
var preWords = []string{"alpha", "beta", "rc", "pre", "preview", "dev",
	"snapshot", "nightly", "canary"}

// prerelease reports whether a hyphen suffix is a recognised pre-release.
func prerelease(s string) bool {
	low := strings.ToLower(s)
	for _, w := range preWords {
		rest, ok := strings.CutPrefix(low, w)
		if !ok {
			continue
		}
		rest = strings.TrimLeft(rest, ".-_")
		if rest == "" {
			return true
		}
		if _, err := strconv.Atoi(rest); err == nil {
			return true
		}
	}
	return false
}

// parse splits a version into numeric segments and a pre-release suffix.
func parse(v string) ([]int, string, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return nil, "", false
	}
	// Build metadata is not part of the order, per semver, and is dropped.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre, v = v[i+1:], v[:i]
		if !prerelease(pre) {
			// A hyphen suffix is a semver pre-release or a distribution
			// revision, and they sort in opposite directions: 1.2.3-rc1
			// comes before 1.2.3 and 1.2.3-1 comes after it. Only the
			// conventional pre-release words are recognised; everything
			// else is refused rather than guessed at.
			return nil, "", false
		}
	}
	if v == "" {
		return nil, "", false
	}
	var out []int
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			// An epoch, a revision, a vendor suffix, a date-based scheme
			// with letters in it. Not guessed at.
			return nil, "", false
		}
		out = append(out, n)
	}
	return out, pre, true
}
