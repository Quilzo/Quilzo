// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package vuln

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

func fixedAt(id, introduced, fixed string, epss float64) Advisory {
	a := advisory(id, 7, epss)
	a.Affects = []Range{{Ecosystem: "npm", Package: "left-pad",
		Introduced: introduced, Fixed: fixed}}
	return a
}

// The weight is the sum of its terms and of nothing else: a screen that
// prints the terms has printed the whole reason.
func TestTheWeightIsExactlyItsTerms(t *testing.T) {
	a := advisory("CVE-2026-0100", 8.1, 0.31)
	a.Exploited = []Attestation{{By: "cisa-kev", At: now}}
	c := comp("left-pad", "1.2.0", 1)
	c.Reachable = yes()
	e := Exposure{Advisory: a, Component: c, Verdict: Vulnerable}
	var sum float64
	names := map[string]bool{}
	for _, term := range e.Terms(now) {
		sum += term.Points
		names[term.Name] = true
		if strings.TrimSpace(term.Why) == "" {
			t.Errorf("%s is worth %.0f and says nothing about why",
				term.Name, term.Points)
		}
	}
	if math.Abs(sum-e.Weight(now)) > 1e-9 {
		t.Errorf("the terms add to %.2f and the weight is %.2f", sum,
			e.Weight(now))
	}
	for _, want := range []string{"Exploited", "Probability", "Reachability",
		"Direct dependency", "Age", "Severity"} {
		if !names[want] {
			t.Errorf("no term for %s", want)
		}
	}
	e.Silenced = true
	if len(e.Terms(now)) != 0 || e.Weight(now) != 0 {
		t.Error("something assessed away still has a weight")
	}
}

// Three advisories, three fixes: the upgrade is to the highest of them, and
// it is one row.
func TestAnUpgradeIsTheLowestVersionThatClearsEverything(t *testing.T) {
	advs := []Advisory{
		fixedAt("CVE-A", "1.0.0", "1.2.5", 0.10),
		fixedAt("CVE-B", "1.0.0", "1.4.0", 0.20),
		fixedAt("CVE-C", "1.1.0", "1.3.1", 0.05),
	}
	inv := []Component{comp("left-pad", "1.2.0", 1),
		comp("left-pad", "1.1.0", 2), comp("left-pad", "1.2.0", 3)}
	ups := Upgrades(Match(advs, inv, nil, now), advs, now)
	if len(ups) != 1 {
		t.Fatalf("%d upgrades for one package", len(ups))
	}
	u := ups[0]
	if u.To != "1.4.0" {
		t.Errorf("upgrade to %q; 1.4.0 is the lowest that clears all three",
			u.To)
	}
	if len(u.Clears) != 3 || len(u.Leaves) != 0 || u.Assets != 3 {
		t.Errorf("clears %v, leaves %v, on %d assets", u.Clears, u.Leaves,
			u.Assets)
	}
	if strings.Join(u.Versions, ",") != "1.1.0,1.2.0" {
		t.Errorf("installed versions: %v", u.Versions)
	}
	// Each advisory once, however many machines carry it.
	if math.Abs(u.Expected-0.35) > 1e-9 {
		t.Errorf("expected exploitation removed is %.2f, not 0.35",
			u.Expected)
	}
}

// An advisory fixed on two release lines has two answers, and somebody on
// the newer line is not told to downgrade.
func TestTheFixIsTheOneForTheInstalledLine(t *testing.T) {
	a := advisory("CVE-LINES", 7, 0.1)
	a.Affects = []Range{
		{Ecosystem: "npm", Package: "left-pad", Introduced: "1.0.0",
			Fixed: "1.2.5"},
		{Ecosystem: "npm", Package: "left-pad", Introduced: "2.0.0",
			Fixed: "2.0.3"},
	}
	inv := []Component{comp("left-pad", "2.0.1", 1)}
	ups := Upgrades(Match([]Advisory{a}, inv, nil, now), []Advisory{a}, now)
	if len(ups) != 1 || ups[0].To != "2.0.3" {
		t.Fatalf("somebody on 2.0.1 was sent to %+v", ups)
	}
}

// The target is checked against every advisory, not only the open ones: an
// upgrade that lands on a version with a fixable problem moves past it, and
// one that lands on an unfixable problem says so.
func TestAnUpgradeDoesNotLandOnSomethingKnownToBeBroken(t *testing.T) {
	open := fixedAt("CVE-OPEN", "1.0.0", "1.3.0", 0.1)
	// Introduced in 1.3.0, so the installed 1.2.0 is outside it and it is
	// not in the queue — but 1.3.0 is where the naive upgrade lands.
	later := fixedAt("CVE-LATER", "1.3.0", "1.3.2", 0.4)
	unfixed := fixedAt("CVE-UNFIXED", "1.3.0", "", 0.01)
	inv := []Component{comp("left-pad", "1.2.0", 1)}

	known := []Advisory{open, later}
	ups := Upgrades(Match(known, inv, nil, now), known, now)
	if len(ups) != 1 || ups[0].To != "1.3.2" {
		t.Fatalf("the upgrade lands on %+v, inside CVE-LATER", ups)
	}
	if len(ups[0].Into) != 0 {
		t.Errorf("a clean target was reported as broken: %v", ups[0].Into)
	}

	known = []Advisory{open, unfixed}
	ups = Upgrades(Match(known, inv, nil, now), known, now)
	if ups[0].To != "1.3.0" || strings.Join(ups[0].Into, ",") != "CVE-UNFIXED" {
		t.Errorf("an upgrade into an unfixed advisory did not say so: %+v",
			ups[0])
	}
}

// Nothing to upgrade to is a different kind of work, and sorts last.
func TestSomethingWithNoFixIsADecisionNotAnUpgrade(t *testing.T) {
	nofix := fixedAt("CVE-NOFIX", "1.0.0", "", 0.9)
	nofix.Affects[0].Package = "is-odd"
	fix := fixedAt("CVE-FIX", "1.0.0", "1.3.0", 0.01)
	inv := []Component{comp("left-pad", "1.2.0", 1), comp("is-odd", "1.0.0", 1)}
	known := []Advisory{nofix, fix}
	ups := Upgrades(Match(known, inv, nil, now), known, now)
	if len(ups) != 2 || ups[0].Name != "left-pad" || ups[1].To != "" {
		t.Fatalf("order and targets: %+v", ups)
	}
	if len(ups[1].Leaves) != 1 ||
		!strings.Contains(ups[1].Leaves[0].Why, "no fix") {
		t.Errorf("the unfixable one does not say why: %+v", ups[1].Leaves)
	}
	// What is being exploited goes first whatever the probabilities say.
	fix.Exploited = []Attestation{{By: "cisa-kev", At: now}}
	big := fixedAt("CVE-BIG", "1.0.0", "2.0.0", 0.9)
	big.Affects[0].Package = "is-even"
	known = []Advisory{big, fix}
	inv = []Component{comp("is-even", "1.0.0", 1), comp("left-pad", "1.2.0", 1)}
	ups = Upgrades(Match(known, inv, nil, now), known, now)
	if ups[0].Name != "left-pad" || !ups[0].Exploited {
		t.Errorf("an exploited vulnerability's upgrade is not first: %+v", ups)
	}
}

// Something assessed away is not work, so it is not in the plan.
func TestWhatIsDecidedAwayIsNotInThePlan(t *testing.T) {
	a := fixedAt("CVE-A", "1.0.0", "1.3.0", 0.1)
	inv := []Component{comp("left-pad", "1.2.0", 1)}
	as := []Assessment{{Advisory: "CVE-A", Component: "npm:left-pad",
		Status: NotAffected, Justification: VulnerableCodeNotPresent,
		At: now.Add(-time.Hour), By: "dana", Because: "read the code"}}
	if ups := Upgrades(Match([]Advisory{a}, inv, as, now), []Advisory{a},
		now); len(ups) != 0 {
		t.Errorf("an upgrade was planned for something not affected: %+v", ups)
	}
}

func accept(until time.Time) Assessment {
	return Assessment{Advisory: "CVE-A", Component: "npm:left-pad",
		Status: Affected, At: now, By: "dana", Owner: "sam",
		Because: "vendor fix lands with the October release", Until: until,
		Kind: audit.KindHuman}
}

// An acceptance takes a row out of the queue until its date, and then the
// row is back at more than it left with.
func TestAnAcceptanceHasAnOwnerAndAnEndAndComesBack(t *testing.T) {
	ok := accept(now.Add(30 * 24 * time.Hour))
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if !ok.Accepted() || !ok.Silences(now) {
		t.Error("an acceptance in force did not take the row out")
	}
	if ok.Record().Action != "vuln.accepted" {
		t.Errorf("recorded as %s", ok.Record().Action)
	}

	none := ok
	none.Owner = " "
	if none.Validate() == nil {
		t.Error("accepted with nobody to answer for it")
	}
	long := accept(now.Add(MaxAcceptance + 24*time.Hour))
	if long.Validate() == nil {
		t.Error("accepted for longer than the ceiling")
	}
	past := accept(now.Add(-time.Hour))
	if past.Validate() == nil {
		t.Error("accepted until a moment already gone")
	}
	ai := ok
	ai.Kind = audit.KindAI
	if ai.Validate() == nil {
		t.Error("a model accepted a risk")
	}
	// Plain "affected" with no date is a statement, not an acceptance: it
	// silences nothing.
	plain := ok
	plain.Until, plain.Owner = time.Time{}, ""
	if plain.Validate() != nil || plain.Silences(now) || plain.Accepted() {
		t.Error("a bare affected statement hid a row")
	}

	a := fixedAt("CVE-A", "1.0.0", "1.3.0", 0.1)
	inv := []Component{comp("left-pad", "1.2.0", 1)}
	during := Match([]Advisory{a}, inv, []Assessment{ok}, now)
	if !during[0].Silenced || during[0].Weight(now) != 0 {
		t.Fatal("the accepted row is still in the queue")
	}
	later := now.Add(31 * 24 * time.Hour)
	after := Match([]Advisory{a}, inv, []Assessment{ok}, later)
	if after[0].Silenced {
		t.Fatal("an acceptance outlived its date")
	}
	fresh := Match([]Advisory{a}, inv, nil, later)
	if after[0].Weight(later) <= fresh[0].Weight(later) {
		t.Error("a lapsed acceptance came back no higher than a row " +
			"nobody had looked at")
	}
	if !strings.Contains(after[0].Explain(later), "an acceptance by dana lapsed") {
		t.Errorf("it does not say what lapsed: %s", after[0].Explain(later))
	}
}

func TestTheTallyCountsEachKindOfDecisionOnce(t *testing.T) {
	a := fixedAt("CVE-A", "1.0.0", "1.3.0", 0.10)
	b := fixedAt("CVE-B", "1.0.0", "1.3.0", 0.20)
	b.Exploited = []Attestation{{By: "cisa-kev", At: now}}
	c := fixedAt("CVE-C", "1.0.0", "1.3.0", 0.30)
	inv := []Component{comp("left-pad", "1.2.0", 1), comp("left-pad", "1.2.0", 2)}
	acc := accept(now.Add(24 * time.Hour))
	acc.Advisory = "CVE-C"
	tally := Summarise(Match([]Advisory{a, b, c}, inv, []Assessment{acc}, now),
		now)
	if tally.Vulnerabilities != 2 || tally.Exposures != 4 ||
		tally.Exploited != 1 || tally.Accepted != 2 {
		t.Errorf("%+v", tally)
	}
	if math.Abs(tally.Expected-0.30) > 1e-9 {
		t.Errorf("expected %.2f; the accepted one is not in the sum",
			tally.Expected)
	}
	b2, _ := json.Marshal(tally)
	if strings.Contains(string(b2), "MBP-") {
		t.Error("the trend names a machine")
	}
}

func TestADraftVEXDocumentSaysWhatIsDecidedAndNotWhoOrWhy(t *testing.T) {
	as := []Assessment{
		{Advisory: "CVE-A", Component: "npm:left-pad", Status: NotAffected,
			Justification: VulnerableCodeNotInExecutePath,
			Impact:        "the padding function is never called with user input",
			At:            now.Add(-2 * time.Hour), By: "dana",
			Because: "grepped every caller; ticket SEC-881"},
		// Superseded by the one above it in time.
		{Advisory: "CVE-A", Component: "npm:left-pad", Status: Affected,
			At: now.Add(-3 * time.Hour), By: "dana", Because: "first look"},
		{Advisory: "CVE-B", Component: "go:golang.org/x/net",
			Status: UnderInvestigation, At: now.Add(-20 * 24 * time.Hour),
			Until: now.Add(-10 * 24 * time.Hour), By: "sam", Because: "asked"},
		accept(now.Add(24 * time.Hour)),
	}
	as[3].Advisory = "CVE-C"
	d, err := Draft(as, "Example Ltd", "https://example.test/vex/1", now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(d)
	text := string(raw)
	for _, banned := range []string{"dana", "sam", "SEC-881", "grepped"} {
		if strings.Contains(text, banned) {
			t.Errorf("the document carries %q, which is internal", banned)
		}
	}
	if len(d.Statements) != 2 {
		t.Fatalf("%d statements; the lapsed investigation is nobody's "+
			"statement and the superseded one is not current", len(d.Statements))
	}
	if d.Statements[0].Status != NotAffected ||
		d.Statements[0].Justification != string(VulnerableCodeNotInExecutePath) ||
		d.Statements[0].Products[0].ID != "pkg:npm/left-pad" {
		t.Errorf("%+v", d.Statements[0])
	}
	if d.Statements[1].Status != Affected || d.Statements[1].Action == "" {
		t.Errorf("affected with no action statement, which the format "+
			"requires: %+v", d.Statements[1])
	}
	if !strings.Contains(text, `"@context":"https://openvex.dev/ns/v0.2.0"`) {
		t.Error("no context")
	}
	if purl("go:golang.org/x/net") != "pkg:golang/golang.org/x/net" {
		t.Errorf("go module as %s", purl("go:golang.org/x/net"))
	}
	if _, err := Draft(as, "", "x", now); err == nil {
		t.Error("a statement with no author")
	}
}
