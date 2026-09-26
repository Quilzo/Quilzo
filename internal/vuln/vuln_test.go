// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package vuln

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

var now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func where(n int) telemetry.ID {
	return telemetry.ID{Issuer: "kandji", Value: fmt.Sprintf("MBP-%04d", n)}
}

func comp(name, version string, n int) Component {
	return Component{Ecosystem: "npm", Name: name, Version: version,
		Where: where(n), Direct: true}
}

func advisory(id string, cvss, epss float64) Advisory {
	return Advisory{
		ID: id, Summary: "something is wrong",
		Published: now.Add(-30 * 24 * time.Hour),
		Known:     now.Add(-3 * 24 * time.Hour),
		CVSS:      cvss, EPSS: epss, EPSSAt: now.Add(-time.Hour),
		Affects: []Range{{Ecosystem: "npm", Package: "left-pad",
			Introduced: "1.0.0", Fixed: "1.3.0"}},
	}
}

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

// The argument of the whole package, as a test: a Medium somebody has
// attested is being exploited outranks a Critical nobody has.
func TestAKnownExploitedMediumOutranksAnUnexploitedCritical(t *testing.T) {
	quiet := advisory("CVE-2026-0001", 9.8, 0.0004)
	loud := advisory("CVE-2026-0002", 5.3, 0.02)
	loud.Exploited = []Attestation{{By: "cisa-kev", At: now.Add(-time.Hour),
		Ref: "BOD 26-04"}}

	out := Rank([]Exposure{
		{Advisory: quiet, Component: comp("left-pad", "1.2.0", 1),
			Verdict: Vulnerable},
		{Advisory: loud, Component: comp("left-pad", "1.2.0", 2),
			Verdict: Vulnerable},
	}, now)

	if out[0].Advisory.ID != "CVE-2026-0002" {
		t.Fatalf("the queue starts with %s (CVSS %.1f); a scanner sorting "+
			"by severity puts the 9.8 first and the team works on it for a "+
			"week", out[0].Advisory.ID, out[0].Advisory.CVSS)
	}
	if !strings.Contains(out[0].Explain(now), "cisa-kev") {
		t.Errorf("the explanation does not name who says so: %q",
			out[0].Explain(now))
	}
}

// Since ENISA became a CVE Root in November 2025 there are two known-exploited
// lists with different national visibility, and they do not agree.
func TestExploitedIsAClaimWithAnAuthorRatherThanABoolean(t *testing.T) {
	a := advisory("CVE-2026-0003", 6.1, 0.01)
	a.Exploited = []Attestation{
		{By: "enisa-euvd", At: now.Add(-24 * time.Hour)},
	}
	yes, who := a.Attested()
	if !yes || len(who) != 1 || who[0] != "enisa-euvd" {
		t.Fatalf("attested %v by %v", yes, who)
	}

	// Two agencies agreeing is more than one asserting, and the weight says
	// so rather than treating "exploited" as a flag that is already set.
	both := a
	both.Exploited = append(both.Exploited, Attestation{By: "cisa-kev",
		At: now.Add(-2 * time.Hour)})
	one := Exposure{Advisory: a, Component: comp("left-pad", "1.2.0", 1),
		Verdict: Vulnerable}
	two := Exposure{Advisory: both, Component: comp("left-pad", "1.2.0", 1),
		Verdict: Vulnerable}
	if two.Weight(now) <= one.Weight(now) {
		t.Error("a second independent attestation changed nothing")
	}

	// And an attestation with nobody's name on it is refused.
	if err := (Attestation{At: now}).Validate(); err == nil {
		t.Error("an anonymous claim of exploitation was accepted")
	}
}

func TestAStaleProbabilityIsDiscountedRatherThanTrusted(t *testing.T) {
	fresh := advisory("CVE-2026-0004", 5.0, 0.4)
	stale := advisory("CVE-2026-0005", 5.0, 0.4)
	stale.EPSSAt = now.Add(-30 * 24 * time.Hour)

	if !fresh.Fresh(now) {
		t.Error("an hour-old figure is stale")
	}
	if stale.Fresh(now) {
		t.Error("a month-old figure is fresh")
	}
	a := Exposure{Advisory: fresh, Component: comp("left-pad", "1.2.0", 1),
		Verdict: Vulnerable}
	b := Exposure{Advisory: stale, Component: comp("left-pad", "1.2.0", 1),
		Verdict: Vulnerable}
	if b.Weight(now) >= a.Weight(now) {
		t.Error("a month-old probability counted as much as today's")
	}
	if !strings.Contains(b.Explain(now), "over a week old") {
		t.Errorf("the explanation does not say the figure is old: %q",
			b.Explain(now))
	}
}

// The failure direction is the whole question.
func TestAVersionItCannotCompareReadsAsAffected(t *testing.T) {
	a := advisory("CVE-2026-0006", 7.5, 0.05)
	a.Affects = []Range{{Ecosystem: "deb", Package: "openssl",
		Introduced: "1.1.1", Fixed: "3.0.2-0ubuntu1.6"}}
	c := Component{Ecosystem: "deb", Name: "openssl",
		Version: "3.0.2-0ubuntu1.2", Where: where(1)}

	verdict, why := a.Applies(c)
	if verdict != Undecided {
		t.Fatalf("a distribution version compared as %s; a comparator that "+
			"guesses here will one day guess \"patched\" and the finding is "+
			"gone", verdict)
	}
	if !strings.Contains(why, "rather than being closed on a guess") {
		t.Errorf("the reason does not say why: %q", why)
	}
	// And it ranks as present rather than disappearing.
	e := Exposure{Advisory: a, Component: c, Verdict: verdict, Why: why}
	if e.Weight(now) == 0 {
		t.Error("an undecided comparison dropped out of the queue")
	}
	if !strings.Contains(e.Explain(now), "cannot compare") {
		t.Errorf("the explanation hides it: %q", e.Explain(now))
	}
}

func TestVersionComparisonAgreesWithSemverAndRefusesTheRest(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.0", 1},
		{"2.0.0", "10.0.0", -1},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3-rc1", "1.2.3", -1},
		{"1.2.3+build7", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
	} {
		got, ok := Compare(c.a, c.b)
		if !ok {
			t.Errorf("Compare(%q,%q) could not decide", c.a, c.b)
			continue
		}
		if got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	for _, v := range []string{
		// An epoch, a distribution revision, a build with letters in it.
		// A hyphen suffix means the opposite in packaging from what it
		// means in semver: 1.2.3-rc1 is before 1.2.3 and 1.2.3-1 is after.
		"1:2.4.57-2ubuntu2", "3.0.2-0ubuntu1.6", "1.2.3-1", "", "latest",
		"1.2.3a", "1.2.3-20260101",
	} {
		if _, ok := Compare(v, "1.2.3"); ok {
			t.Errorf("Compare guessed at %q", v)
		}
	}
	// Calendar versions that are all digits and dots compare fine, and that
	// is correct rather than lucky: 2024.03.1 is genuinely before 2024.04.1.
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"20240301", "20240401", -1},
		{"2024.03.1", "2024.04.1", -1},
		{"2024.03.1", "2024.3.1", 0},
	} {
		got, ok := Compare(c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("Compare(%q,%q) = %d (%v), want %d", c.a, c.b, got, ok,
				c.want)
		}
	}
}

func TestSomethingWithNoFixSaysWhatTheWorkIs(t *testing.T) {
	a := advisory("CVE-2026-0007", 8.1, 0.03)
	a.Affects = []Range{{Ecosystem: "npm", Package: "left-pad",
		Introduced: "1.0.0"}}
	e := Exposure{Advisory: a, Component: comp("left-pad", "1.2.0", 1)}
	e.Verdict, e.Why = a.Applies(e.Component)

	if e.Verdict != Vulnerable {
		t.Fatalf("verdict is %s", e.Verdict)
	}
	if _, ok := e.Fixable(); ok {
		t.Fatal("a fix was reported where none is published")
	}
	if !strings.Contains(e.Explain(now), "mitigation or a recorded") {
		t.Errorf("the explanation does not say what to do instead: %q",
			e.Explain(now))
	}
}

// not_affected without a justification from the closed list is the way a
// queue gets emptied without anybody saying anything.
func TestNotAffectedNeedsAJustificationFromTheList(t *testing.T) {
	base := Assessment{
		Advisory: "CVE-2026-0001", Component: "npm:left-pad",
		Status: NotAffected, At: now, By: "rashik", Kind: audit.KindHuman,
		Because: "the parser is never called on untrusted input",
	}
	if err := base.Validate(); err == nil {
		t.Fatal("not_affected with no justification was accepted")
	} else if !strings.Contains(err.Error(), "we looked and it is fine") {
		t.Errorf("the refusal does not say why the list is closed: %v", err)
	}

	base.Justification = "we checked"
	if err := base.Validate(); err == nil {
		t.Fatal("an invented justification was accepted")
	}

	base.Justification = VulnerableCodeNotInExecutePath
	if err := base.Validate(); err != nil {
		t.Fatalf("an OpenVEX justification was refused: %v", err)
	}
	if base.Record().Outcome != audit.Denied {
		t.Error("deciding not to fix something reads in the log the same " +
			"as fixing it")
	}
}

// under_investigation reads as work in progress and behaves as closed.
func TestAnInvestigationExpiresAndComesBack(t *testing.T) {
	a := Assessment{
		Advisory: "CVE-2026-0001", Component: "npm:left-pad",
		Status: UnderInvestigation, At: now, By: "rashik",
		Kind: audit.KindHuman, Because: "asking the vendor",
	}
	if err := a.Validate(); err == nil {
		t.Fatal("an investigation with no end was accepted")
	} else if !strings.Contains(err.Error(), "behaves as closed") {
		t.Errorf("the refusal does not say what goes wrong: %v", err)
	}

	a.Until = now.Add(60 * 24 * time.Hour)
	if err := a.Validate(); err == nil {
		t.Fatal("a two-month investigation was accepted")
	}

	a.Until = now.Add(7 * 24 * time.Hour)
	if err := a.Validate(); err != nil {
		t.Fatalf("a week-long investigation was refused: %v", err)
	}
	if !a.Silences(now) {
		t.Error("a live investigation does not take it out of the queue")
	}
	later := now.Add(8 * 24 * time.Hour)
	if a.Silences(later) {
		t.Error("a lapsed investigation still silences")
	}
	if !a.Lapsed(later) {
		t.Error("it did not lapse")
	}

	// And it returns at more than it left with, so it is visible rather
	// than quietly reappearing at the bottom.
	e := Exposure{Advisory: advisory("CVE-2026-0001", 5.0, 0.01),
		Component: comp("left-pad", "1.2.0", 1), Verdict: Vulnerable,
		Assessed: a}
	plain := e
	plain.Assessed = Assessment{}
	if e.Weight(later) <= plain.Weight(later) {
		t.Error("a lapsed investigation returns below where it started")
	}
	if !strings.Contains(e.Explain(later), "lapsed") {
		t.Errorf("the explanation does not mention it: %q", e.Explain(later))
	}
}

func TestAModelMayProposeAnAssessmentAndNotSignOne(t *testing.T) {
	a := Assessment{
		Advisory: "CVE-2026-0001", Component: "npm:left-pad",
		Status: NotAffected, Justification: ComponentNotPresent,
		At: now, By: "assistant", Kind: audit.KindAI,
		Because: "the package is not in the lockfile",
	}
	err := a.Validate()
	if err == nil {
		t.Fatal("a model marked a vulnerability not applicable")
	}
	if !strings.Contains(err.Error(), "a person signs it") {
		t.Errorf("the refusal does not say what to do instead: %v", err)
	}
}

func TestAnAssessmentWithNoEvidenceIsRefused(t *testing.T) {
	a := Assessment{
		Advisory: "CVE-2026-0001", Component: "npm:left-pad",
		Status: Fixed, At: now, By: "rashik", Kind: audit.KindHuman,
	}
	if err := a.Validate(); err == nil {
		t.Fatal("an assessment with no reason was accepted")
	}
}

func TestMatchAppliesTheNarrowerAssessment(t *testing.T) {
	a := advisory("CVE-2026-0008", 7.0, 0.02)
	inv := []Component{comp("left-pad", "1.2.0", 1),
		comp("left-pad", "1.2.0", 2)}
	// One statement about every installation, one about a single host.
	assessments := []Assessment{
		{Advisory: a.ID, Component: "npm:left-pad", Status: NotAffected,
			Justification: VulnerableCodeNotInExecutePath, At: now,
			By: "rashik", Kind: audit.KindHuman,
			Because: "the padding helper is never called"},
		{Advisory: a.ID, Component: "npm:left-pad",
			Where: where(2).String(), Status: Affected, At: now,
			By: "rashik", Kind: audit.KindHuman,
			Because: "this build does call it, from the importer"},
	}
	out := Match([]Advisory{a}, inv, assessments, now)
	if len(out) != 2 {
		t.Fatalf("%d exposures", len(out))
	}
	var silenced, live int
	for _, e := range out {
		if e.Silenced {
			silenced++
			continue
		}
		live++
		if e.Component.Where != where(2) {
			t.Errorf("the wrong host is still in the queue: %s",
				e.Component.Where)
		}
	}
	if silenced != 1 || live != 1 {
		t.Errorf("%d silenced, %d live", silenced, live)
	}
}

func TestTheNewestAssessmentWins(t *testing.T) {
	a := advisory("CVE-2026-0009", 7.0, 0.02)
	inv := []Component{comp("left-pad", "1.2.0", 1)}
	out := Match([]Advisory{a}, inv, []Assessment{
		{Advisory: a.ID, Component: "npm:left-pad", Status: NotAffected,
			Justification: ComponentNotPresent, At: now.Add(-48 * time.Hour),
			By: "rashik", Kind: audit.KindHuman, Because: "thought it was gone"},
		{Advisory: a.ID, Component: "npm:left-pad", Status: Affected,
			At: now, By: "rashik", Kind: audit.KindHuman,
			Because: "it is in the lockfile after all"},
	}, now)
	if len(out) != 1 || out[0].Silenced {
		t.Fatal("an older assessment overruled somebody changing their mind")
	}
}

// The most useful thing that can be done with EPSS, and nobody does it.
func TestExpectedExploitationsIsTheSumAndConcentratesAtTheTop(t *testing.T) {
	var in []Exposure
	// Four hundred rows of nearly nothing.
	for n := range 400 {
		a := advisory(fmt.Sprintf("CVE-2026-1%03d", n), 7.5, 0.0005)
		in = append(in, Exposure{Advisory: a,
			Component: comp("left-pad", "1.2.0", n), Verdict: Vulnerable})
	}
	// Twelve that matter.
	for n := range 12 {
		a := advisory(fmt.Sprintf("CVE-2026-9%03d", n), 5.0, 0.3)
		in = append(in, Exposure{Advisory: a,
			Component: comp("left-pad", "1.2.0", 900+n), Verdict: Vulnerable})
	}
	ranked := Rank(in, now)

	head, all, share := Concentration(ranked, 12, now)
	if all < 3.5 || all > 4.0 {
		t.Errorf("the queue's expected exploitations are %.2f", all)
	}
	if share < 0.85 {
		t.Errorf("the top twelve carry %.0f%% of the risk; the point of the "+
			"figure is that it says the rest can wait", share*100)
	}
	if head <= 0 {
		t.Error("the head carries nothing")
	}

	// The same CVE on forty hosts is one prediction about one vulnerability.
	one := advisory("CVE-2026-7777", 9.0, 0.5)
	var fleet []Exposure
	for n := range 40 {
		fleet = append(fleet, Exposure{Advisory: one,
			Component: comp("left-pad", "1.2.0", n), Verdict: Vulnerable})
	}
	if got := Expected(fleet, now); got != 0.5 {
		t.Errorf("forty hosts gave an expected %.1f; a fleet size became a "+
			"risk figure", got)
	}
}

func TestSilencedExposuresAreNotInTheArithmetic(t *testing.T) {
	a := advisory("CVE-2026-0010", 9.0, 0.6)
	e := Exposure{Advisory: a, Component: comp("left-pad", "1.2.0", 1),
		Verdict: Vulnerable, Silenced: true,
		Assessed: Assessment{Status: NotAffected,
			Justification: VulnerableCodeNotPresent,
			Because:       "the vulnerable module is stripped at build"}}
	if got := Expected([]Exposure{e}, now); got != 0 {
		t.Errorf("a not_affected exposure contributed %.2f", got)
	}
	if e.Weight(now) != 0 {
		t.Error("it is still in the queue")
	}
	if !strings.Contains(e.Explain(now), "not_affected") {
		t.Errorf("it does not say why it is quiet: %q", e.Explain(now))
	}
}

func TestSeverityInTheRegisterFollowsTheEvidenceNotTheBaseScore(t *testing.T) {
	attested := advisory("CVE-2026-0011", 4.3, 0.01)
	attested.Exploited = []Attestation{{By: "cisa-kev", At: now}}
	if got := severityOf(Exposure{Advisory: attested}, now); got !=
		telemetry.SeverityCritical {
		t.Errorf("an attested 4.3 is %v in the register", got)
	}
	quiet := advisory("CVE-2026-0012", 9.8, 0.0001)
	if got := severityOf(Exposure{Advisory: quiet}, now); got ==
		telemetry.SeverityCritical {
		t.Error("a 9.8 nobody is exploiting is critical in the register, " +
			"which is the thing this package exists to stop")
	}
}

func TestFindingsCarryTheReasonAndNotJustTheIdentifier(t *testing.T) {
	a := advisory("CVE-2026-0013", 7.5, 0.2)
	out := Findings(Match([]Advisory{a},
		[]Component{comp("left-pad", "1.2.0", 1)}, nil, now), now)
	if len(out) != 1 {
		t.Fatalf("%d findings", len(out))
	}
	f := out[0]
	if !strings.Contains(f.Title, "upgrade to 1.3.0") {
		t.Errorf("the title does not say what to do: %q", f.Title)
	}
	if !strings.Contains(f.Evidence[0].What, "chance of exploitation") {
		t.Errorf("the evidence does not say why it is here: %q",
			f.Evidence[0].What)
	}
	// From when we knew, not when it was published: a scanner's schedule
	// must not be the thing that decides whether a team is on time.
	if !f.First.Equal(a.Known) {
		t.Errorf("the finding ages from %s, not from when we found out",
			f.First)
	}
}

func TestAnAdvisoryOrComponentThatCannotBeUsedIsRefused(t *testing.T) {
	for name, a := range map[string]Advisory{
		"no id":         {Summary: "x", Known: now},
		"no summary":    {ID: "CVE-1", Known: now},
		"no known date": {ID: "CVE-1", Summary: "x"},
		"epss as a percentage": {ID: "CVE-1", Summary: "x", Known: now,
			EPSS: 42},
		"cvss out of range": {ID: "CVE-1", Summary: "x", Known: now,
			CVSS: 11},
	} {
		if err := a.Validate(); err == nil {
			t.Errorf("an advisory with %s was accepted", name)
		}
	}
	for name, c := range map[string]Component{
		"no ecosystem": {Name: "jackson", Version: "1", Where: where(1)},
		"no version":   {Ecosystem: "npm", Name: "x", Where: where(1)},
		"nowhere":      {Ecosystem: "npm", Name: "x", Version: "1"},
		"no issuer": {Ecosystem: "npm", Name: "x", Version: "1",
			Where: telemetry.ID{Value: "host-1"}},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("a component with %s was accepted", name)
		}
	}
}

func TestUnknownReachabilitySitsBetweenTheTwoAnswers(t *testing.T) {
	a := advisory("CVE-2026-0014", 7.0, 0.01)
	build := func(r *bool) Exposure {
		c := comp("left-pad", "1.2.0", 1)
		c.Reachable = r
		return Exposure{Advisory: a, Component: c, Verdict: Vulnerable}
	}
	reachable := build(yes()).Weight(now)
	unknown := build(nil).Weight(now)
	unreachable := build(no()).Weight(now)
	if !(reachable > unknown && unknown > unreachable) {
		t.Fatalf("reachable %.0f, unknown %.0f, unreachable %.0f: treating "+
			"unknown as unreachable sinks everything nobody has analysed, "+
			"which is most things", reachable, unknown, unreachable)
	}
}

func TestEveryStatusReachesARealAuditLog(t *testing.T) {
	dir := t.TempDir()
	k, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(audit.Options{Path: dir + "/audit.jsonl", Key: k,
		Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range Statuses() {
		a := Assessment{Advisory: "CVE-2026-0001",
			Component: "npm:left-pad", Status: s, At: now, By: "rashik",
			Kind: audit.KindHuman, Because: "checked"}
		if s == NotAffected {
			a.Justification = ComponentNotPresent
		}
		if s == UnderInvestigation {
			a.Until = now.Add(48 * time.Hour)
		}
		if verr := a.Validate(); verr != nil {
			t.Fatalf("%s: %v", s, verr)
		}
		if _, aerr := log.Append(a.Record()); aerr != nil {
			t.Fatalf("%s: %v", s, aerr)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(Statuses()) {
		t.Fatalf("%d entries for %d statuses", len(events), len(Statuses()))
	}
}

// One CVE on forty laptops is one job. A queue that spends forty rows on it
// pushes the next vulnerability off the page, which is how a scanner's output
// gets read down to row twenty and no further.
func TestTheQueueGroupsByVulnerabilityAndNotByHost(t *testing.T) {
	loud := advisory("CVE-2026-9999", 5.0, 0.8)
	loud.Exploited = []Attestation{{By: "cisa-kev", At: now}}
	quiet := advisory("CVE-2026-8888", 9.8, 0.3)

	var in []Exposure
	for n := range 40 {
		in = append(in, Exposure{Advisory: loud,
			Component: comp("left-pad", "1.2.0", n), Verdict: Vulnerable})
	}
	in = append(in, Exposure{Advisory: quiet,
		Component: comp("left-pad", "1.2.0", 99), Verdict: Vulnerable})

	groups := Groups(Rank(in, now))
	if len(groups) != 2 {
		t.Fatalf("%d groups for two vulnerabilities", len(groups))
	}
	if groups[0].Advisory.ID != loud.ID {
		t.Errorf("the queue starts with %s", groups[0].Advisory.ID)
	}
	if groups[0].Assets() != 40 {
		t.Errorf("the first group covers %d assets", groups[0].Assets())
	}
	// The second vulnerability is on the first page rather than on the
	// third, which is the whole point.
	if groups[1].Advisory.ID != quiet.ID {
		t.Errorf("the second row is %s", groups[1].Advisory.ID)
	}
	if !strings.Contains(groups[0].Where(3), "and 37 more") {
		t.Errorf("the asset list does not summarise: %q", groups[0].Where(3))
	}
	// And the arithmetic agrees with the display: one CVE counted once.
	if got := Expected(Flatten(groups[:1]), now); got != 0.8 {
		t.Errorf("forty rows of one CVE counted as %.1f", got)
	}
	if len(Flatten(groups)) != len(in) {
		t.Error("grouping lost exposures")
	}
}
