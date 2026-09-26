// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package crosswalk

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/audit"
)

var (
	now    = time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	period = assurance.Period{From: now.Add(-182 * 24 * time.Hour), To: now}
)

func req(id, title string) Requirement {
	return Requirement{Framework: "ISO27001", ID: id, Title: title}
}

func mapped(control, requirement string, rel Relation) Mapping {
	m := Mapping{
		Control: control, Requirement: requirement, Relation: rel,
		Rationale: "read both and compared them", At: now, By: "rashik",
		Kind: audit.KindHuman,
	}
	if rel.Partial() {
		m.Remainder = "the database's local accounts, which this does not touch"
	}
	return m
}

// Evidence for a control that covered the whole period.
func covered(control string) assurance.Coverage {
	return assurance.Coverage{Control: control, Period: period,
		Covered: period.Length(), Observations: 26}
}

// Evidence with sixty days missing.
func short(control string) assurance.Coverage {
	return assurance.Coverage{Control: control, Period: period,
		Covered: 122 * 24 * time.Hour, Observations: 18,
		Gaps: []assurance.Period{{
			From: period.From.Add(60 * 24 * time.Hour),
			To:   period.From.Add(120 * 24 * time.Hour),
		}},
	}
}

// The thing every platform gets wrong: a row of framework tags read as
// equality, and a requirement counted as covered because somebody clicked it.
func TestAPartialMappingNeverBecomesACoveredRequirement(t *testing.T) {
	reqs := []Requirement{req("A.8.5", "secure authentication")}
	report, standings := Assess("ISO27001", reqs,
		[]Mapping{mapped("mfa", "ISO27001:A.8.5", SubsetOf)},
		[]assurance.Coverage{covered("mfa")}, period)

	if report.Met != 0 {
		t.Fatalf("%d requirement(s) met from a subset mapping", report.Met)
	}
	if report.Partial != 1 {
		t.Fatalf("%d partial", report.Partial)
	}
	if standings[0].State != Partial {
		t.Errorf("state is %s", standings[0].State)
	}
	// And the remainder is named, which is the whole reason to record a
	// partial relation rather than ticking the requirement.
	if !strings.Contains(standings[0].Why(), "local accounts") {
		t.Errorf("the remainder is not in the explanation: %q",
			standings[0].Why())
	}

	// Superset does satisfy it.
	report, _ = Assess("ISO27001", reqs,
		[]Mapping{mapped("mfa", "ISO27001:A.8.5", SupersetOf)},
		[]assurance.Coverage{covered("mfa")}, period)
	if report.Met != 1 {
		t.Errorf("a superset mapping with evidence met %d", report.Met)
	}
}

func TestOnlyEqualAndSupersetSatisfy(t *testing.T) {
	for rel, want := range map[Relation]bool{
		Equal: true, SupersetOf: true,
		SubsetOf: false, Intersects: false, NoRelation: false,
	} {
		if rel.Satisfies() != want {
			t.Errorf("%s satisfies = %v", rel, rel.Satisfies())
		}
	}
	for rel, want := range map[Relation]bool{
		SubsetOf: true, Intersects: true,
		Equal: false, SupersetOf: false, NoRelation: false,
	} {
		if rel.Partial() != want {
			t.Errorf("%s partial = %v", rel, rel.Partial())
		}
	}
}

// A mapping says a control would satisfy a requirement. It says nothing about
// whether the control ran.
func TestAMappedRequirementWithNoEvidenceIsNotMet(t *testing.T) {
	reqs := []Requirement{req("A.8.5", "secure authentication")}
	m := []Mapping{mapped("mfa", "ISO27001:A.8.5", Equal)}

	// Sixty days of the period have no evidence for the control.
	report, standings := Assess("ISO27001", reqs, m,
		[]assurance.Coverage{short("mfa")}, period)
	if report.Met != 0 {
		t.Fatal("a requirement was met by a control that stopped reporting")
	}
	if report.Unevidenced != 1 {
		t.Fatalf("%d unevidenced", report.Unevidenced)
	}
	if standings[0].Gaps["mfa"] != 60 {
		t.Errorf("the gap is reported as %d days", standings[0].Gaps["mfa"])
	}
	if !strings.Contains(standings[0].Why(), "says nothing about whether") {
		t.Errorf("the explanation does not say what a mapping is: %q",
			standings[0].Why())
	}

	// And a control nobody has any evidence for at all is the whole period.
	report, standings = Assess("ISO27001", reqs, m, nil, period)
	if report.Unevidenced != 1 || standings[0].Gaps["mfa"] != period.Days() {
		t.Errorf("a control with no evidence is short %d day(s)",
			standings[0].Gaps["mfa"])
	}
}

func TestNobodyLookingIsDifferentFromSomebodyDeciding(t *testing.T) {
	reqs := []Requirement{
		req("A.8.5", "secure authentication"),
		req("A.5.7", "threat intelligence"),
	}
	report, standings := Assess("ISO27001", reqs, []Mapping{
		mapped("nothing", "ISO27001:A.5.7", NoRelation),
	}, nil, period)

	if report.Unmapped != 1 || report.Declined != 1 {
		t.Fatalf("%d unmapped, %d declined", report.Unmapped, report.Declined)
	}
	// Unmapped sorts first, because it is the one that is work.
	if standings[0].State != Unmapped {
		t.Errorf("the list starts with %s", standings[0].State)
	}
	if !strings.Contains(standings[0].Why(), "nobody has looked") {
		t.Errorf("the explanation is %q", standings[0].Why())
	}
	for _, s := range standings {
		if s.State == Declined &&
			!strings.Contains(s.Why(), "not applicable") {
			t.Errorf("a declined requirement reads as %q", s.Why())
		}
	}
}

// The tell. Equality between one organisation's control and another's clause
// is rare, and a crosswalk full of it is one somebody clicked through.
func TestACrosswalkThatIsMostlyEqualIsCalledOut(t *testing.T) {
	var reqs []Requirement
	var maps []Mapping
	for n := range 20 {
		id := fmt.Sprintf("A.%d", n)
		reqs = append(reqs, req(id, "a clause"))
		maps = append(maps, mapped("everything", "ISO27001:"+id, Equal))
	}
	report, standings := Assess("ISO27001", reqs, maps,
		[]assurance.Coverage{covered("everything")}, period)

	if !report.Suspicious() {
		t.Fatalf("twenty mappings all claiming equality (%.0f%%) passed "+
			"without comment", report.EqualShare*100)
	}
	advice := Adopting(report, standings)
	if !strings.Contains(advice, "take apart") {
		t.Errorf("the advice does not say what happens next: %q", advice)
	}
	out := Findings(report, standings, now)
	var called bool
	for _, f := range out {
		if strings.Contains(f.Title, "claims exact equality") {
			called = true
		}
	}
	if !called {
		t.Error("nothing in the register says the crosswalk looks unread")
	}

	// A mixed crosswalk is not remarked on.
	maps[0].Relation, maps[0].Remainder = SubsetOf, "the rest of it"
	for n := 1; n < 9; n++ {
		maps[n].Relation, maps[n].Remainder = Intersects, "the rest of it"
	}
	mixed, _ := Assess("ISO27001", reqs, maps, nil, period)
	if mixed.Suspicious() {
		t.Errorf("a crosswalk that is %.0f%% equal was called suspicious",
			mixed.EqualShare*100)
	}
	// And a handful of mappings is not enough to conclude anything.
	few, _ := Assess("ISO27001", reqs[:3], maps[:3], nil, period)
	if few.Suspicious() {
		t.Error("three mappings were treated as a pattern")
	}
}

func TestAPartialMappingWithNoRemainderIsRefused(t *testing.T) {
	m := mapped("mfa", "ISO27001:A.8.5", SubsetOf)
	m.Remainder = ""
	err := m.Validate()
	if err == nil {
		t.Fatal("a subset mapping with nothing left over was accepted")
	}
	if !strings.Contains(err.Error(), "rather than ticking the requirement") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	// And the reverse: a satisfying relation that names a remainder is
	// contradicting itself.
	full := mapped("mfa", "ISO27001:A.8.5", Equal)
	full.Remainder = "something"
	if err := full.Validate(); err == nil {
		t.Fatal("an equal mapping that leaves something over was accepted")
	}
}

func TestAMappingWithNoRationaleIsRefused(t *testing.T) {
	m := mapped("mfa", "ISO27001:A.8.5", Equal)
	m.Rationale = ""
	err := m.Validate()
	if err == nil {
		t.Fatal("a mapping with no rationale was accepted")
	}
	if !strings.Contains(err.Error(), "8477") {
		t.Errorf("the refusal does not cite where the requirement comes "+
			"from: %v", err)
	}
}

func TestAnInventedRelationIsRefused(t *testing.T) {
	m := mapped("mfa", "ISO27001:A.8.5", Equal)
	m.Relation = "mostly"
	err := m.Validate()
	if err == nil {
		t.Fatal("a sixth relationship was accepted")
	}
	if !strings.Contains(err.Error(), "no other tool can read") {
		t.Errorf("the refusal does not say what is lost: %v", err)
	}
}

func TestARequirementWithoutAFrameworkIsRefused(t *testing.T) {
	m := mapped("mfa", "A.8.5", Equal)
	err := m.Validate()
	if err == nil {
		t.Fatal("a bare clause number was accepted as a requirement")
	}
	if !strings.Contains(err.Error(), "both have a clause called 6.1") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

func TestAModelMayProposeACrosswalkAndNotSignOne(t *testing.T) {
	m := mapped("mfa", "ISO27001:A.8.5", Equal)
	m.Kind = audit.KindAI
	err := m.Validate()
	if err == nil {
		t.Fatal("a model asserted that a control answers a clause")
	}
	if !strings.Contains(err.Error(), "good use of one") {
		t.Errorf("the refusal does not say what a model is for here: %v",
			err)
	}
}

func TestSomebodyChangingTheirMindIsNotAConflict(t *testing.T) {
	old := mapped("mfa", "ISO27001:A.8.5", Equal)
	old.At = now.Add(-48 * time.Hour)
	fresh := mapped("mfa", "ISO27001:A.8.5", SubsetOf)

	got := Latest([]Mapping{old, fresh})
	if len(got) != 1 {
		t.Fatalf("%d mappings for one pair", len(got))
	}
	if got[0].Relation != SubsetOf {
		t.Errorf("the older mapping won: %s", got[0].Relation)
	}
}

// The question somebody asks before signing up for an audit, and the one a
// coverage percentage answers wrongly.
func TestAdoptingAFrameworkSaysWhatEachPieceOfWorkIs(t *testing.T) {
	reqs := []Requirement{
		req("A.8.5", "secure authentication"),
		req("A.8.2", "privileged access rights"),
		req("A.5.7", "threat intelligence"),
		req("A.8.16", "monitoring activities"),
	}
	maps := []Mapping{
		mapped("mfa", "ISO27001:A.8.5", SupersetOf),
		mapped("access-review", "ISO27001:A.8.2", SubsetOf),
		mapped("detections", "ISO27001:A.8.16", Equal),
	}
	cov := []assurance.Coverage{covered("mfa"), covered("access-review"),
		short("detections")}

	report, standings := Assess("ISO27001", reqs, maps, cov, period)
	if report.Met != 1 || report.Partial != 1 || report.Unevidenced != 1 ||
		report.Unmapped != 1 {
		t.Fatalf("met %d, partial %d, unevidenced %d, unmapped %d",
			report.Met, report.Partial, report.Unevidenced, report.Unmapped)
	}

	advice := Adopting(report, standings)
	// Three different kinds of work, said as three different things.
	for _, want := range []string{
		"1 of 4 requirement(s) already met",
		"not a new control",
		"remainders are written down rather than rounded up",
		"reading the standard rather than a number going up",
	} {
		if !strings.Contains(advice, want) {
			t.Errorf("the advice does not say %q:\n%s", want, advice)
		}
	}
	// And the report leads with what nobody has looked at.
	if !strings.Contains(report.Why(), "nothing mapped to them at all") {
		t.Errorf("the summary is %q", report.Why())
	}
}

func TestFindingsSeparateTheThreeKindsOfGap(t *testing.T) {
	reqs := []Requirement{
		req("A.8.5", "secure authentication"),
		req("A.8.2", "privileged access rights"),
		req("A.5.7", "threat intelligence"),
	}
	maps := []Mapping{
		mapped("mfa", "ISO27001:A.8.5", Equal),
		mapped("access-review", "ISO27001:A.8.2", Intersects),
	}
	report, standings := Assess("ISO27001", reqs, maps,
		[]assurance.Coverage{short("mfa"), covered("access-review")}, period)
	out := Findings(report, standings, now)

	var unmapped, partial, unevidenced bool
	for _, f := range out {
		switch {
		case strings.Contains(f.Title, "nothing mapped"):
			unmapped = true
		case strings.Contains(f.Title, "only partly addressed"):
			partial = true
			if !strings.Contains(f.Evidence[0].What, "nothing covers") {
				t.Errorf("the remainder is missing: %q", f.Evidence[0].What)
			}
		case strings.Contains(f.Title, "mapped and not evidenced"):
			unevidenced = true
		}
	}
	if !unmapped || !partial || !unevidenced {
		t.Errorf("unmapped=%v partial=%v unevidenced=%v",
			unmapped, partial, unevidenced)
	}
}

func TestOneFrameworksMappingsDoNotCountTowardsAnother(t *testing.T) {
	reqs := []Requirement{req("A.8.5", "secure authentication")}
	soc2 := mapped("mfa", "SOC2:CC6.1", Equal)
	report, _ := Assess("ISO27001", reqs, []Mapping{soc2},
		[]assurance.Coverage{covered("mfa")}, period)
	if report.Met != 0 || report.Unmapped != 1 {
		t.Fatalf("a SOC 2 mapping satisfied an ISO requirement: met %d, "+
			"unmapped %d", report.Met, report.Unmapped)
	}
	if report.Mappings != 0 {
		t.Errorf("%d mappings counted from another framework",
			report.Mappings)
	}
}

func TestEveryRelationReachesARealAuditLog(t *testing.T) {
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
	for _, rel := range Relations() {
		m := mapped("mfa", "ISO27001:A.8.5", rel)
		if verr := m.Validate(); verr != nil {
			t.Fatalf("%s: %v", rel, verr)
		}
		if _, aerr := log.Append(m.Record()); aerr != nil {
			t.Fatalf("%s: %v", rel, aerr)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(Relations()) {
		t.Fatalf("%d entries for %d relations", len(events), len(Relations()))
	}
}

func TestEveryRelationSaysWhatItMeans(t *testing.T) {
	for _, rel := range Relations() {
		if d := rel.Describe(); d == "" || d == string(rel) {
			t.Errorf("%s describes itself as %q", rel, d)
		}
	}
}
