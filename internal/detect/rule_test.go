// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

var at = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func event(source string, fields map[string]string) telemetry.Event {
	e := telemetry.Event{
		Time: at, Received: at.Add(time.Second),
		Class: telemetry.ClassAuthentication, Activity: 1,
		Severity: telemetry.SeverityMedium, Source: source,
		Actor: telemetry.ID{Issuer: "okta", Value: "u-1"},
		Raw:   map[string]string{},
	}
	for k, v := range fields {
		e.Raw[k] = v
	}
	return e
}

func mfaRule() Rule {
	return Rule{
		ID: "okta-mfa-disabled", Title: "MFA removed from an account",
		Why:     "Removing a factor is a step in an account takeover.",
		Blind:   "Does not see a factor removed through the API with a token.",
		Sources: []string{"okta/system"},
		When: Predicate{All: []Predicate{
			{Match: &Match{Field: "raw.event", Op: Equals,
				Values: []string{"user.mfa.factor.deactivate"}}},
			{Match: &Match{Field: "disposition", Op: Equals,
				Values: []string{"allowed"}}},
		}},
		Severity:  telemetry.SeverityHigh,
		Technique: []string{"T1556.006"},
		Fixtures: []Fixture{
			{Name: "a factor is removed", Match: true, Event: func() telemetry.Event {
				e := event("okta/system", map[string]string{
					"event": "user.mfa.factor.deactivate"})
				e.Disposition = telemetry.DispositionAllowed
				return e
			}()},
			{Name: "a removal that was blocked", Match: false,
				Event: func() telemetry.Event {
					e := event("okta/system", map[string]string{
						"event": "user.mfa.factor.deactivate"})
					e.Disposition = telemetry.DispositionBlocked
					return e
				}()},
			{Name: "an ordinary sign-in", Match: false,
				Event: func() telemetry.Event {
					e := event("okta/system", map[string]string{
						"event": "user.session.start"})
					e.Disposition = telemetry.DispositionAllowed
					return e
				}()},
		},
	}
}

func TestARuleMatchesWhatItWasWrittenFor(t *testing.T) {
	r := mfaRule()
	if err := r.Validate(); err != nil {
		t.Fatalf("a complete rule was refused: %v", err)
	}
	for _, res := range r.Test() {
		if !res.OK() {
			t.Errorf("%s", res.Why())
		}
	}
}

// -- the failure that is silent ----------------------------------------------

func TestARuleThatCannotFireIsRefused(t *testing.T) {
	// The measured state of the field is that 13-18% of deployed rules never
	// fire under any input. They pass review and sit on the coverage chart.
	// Nothing about the text reveals which ones.
	r := mfaRule()
	for i := range r.Fixtures {
		r.Fixtures[i].Match = false
	}
	err := r.Validate()
	if err == nil {
		t.Fatal("a rule with nothing showing it can fire was accepted")
	}
	if !strings.Contains(err.Error(), "fire") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

func TestARuleThatOnlyFiresIsRefused(t *testing.T) {
	// A rule shown to fire and not shown to discriminate. The way a detection
	// fails in production is by matching something benign that looks adjacent.
	r := mfaRule()
	r.Fixtures = r.Fixtures[:1]
	err := r.Validate()
	if err == nil {
		t.Fatal("a rule with no benign fixture was accepted")
	}
	if !strings.Contains(err.Error(), "discriminate") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

func TestAFieldTheDataDoesNotHaveIsRefused(t *testing.T) {
	// The commonest cause of a rule that runs nightly and matches nothing.
	// It is a typo, and it is invisible: the rule is syntactically perfect.
	r := mfaRule()
	r.When.All[0].Match.Field = "raw.evnt"
	err := r.Validate()
	if err == nil {
		t.Fatal("a rule reading a field no fixture carries was accepted")
	}
	if !strings.Contains(err.Error(), "raw.evnt") {
		t.Errorf("the refusal does not name the field: %v", err)
	}
}

func TestARuleWithNoSourceIsRefused(t *testing.T) {
	// A rule with no source gets broader every time a connector is added,
	// without anybody editing it.
	r := mfaRule()
	r.Sources = nil
	if err := r.Validate(); err == nil {
		t.Error("a rule that reads every source was accepted")
	}
}

func TestARuleDoesNotReadASourceItDidNotDeclare(t *testing.T) {
	r := mfaRule()
	e := event("entra/audit", map[string]string{
		"event": "user.mfa.factor.deactivate"})
	e.Disposition = telemetry.DispositionAllowed
	if r.Matches(e) {
		t.Error("a rule written for Okta matched an Entra event; the " +
			"question it is answering is not the one its author considered")
	}
}

// -- the predicate ------------------------------------------------------------

func TestAnEmptyConditionIsRefusedRatherThanDefaulted(t *testing.T) {
	// It is either "match everything" or "match nothing", and which one
	// should never be decided by a zero value.
	r := mfaRule()
	r.When = Predicate{}
	if err := r.Validate(); err == nil {
		t.Error("an empty condition was accepted")
	}
	// And if one is reached anyway, it matches nothing rather than everything.
	if eval(Predicate{}, map[string]string{"a": "b"}) {
		t.Error("an empty condition matched an event")
	}
}

func TestACombinedConditionIsRefused(t *testing.T) {
	// Which applies first would be decided by evaluation order, and nobody
	// reviewing the rule would see that.
	r := mfaRule()
	r.When = Predicate{
		All:   []Predicate{{Match: &Match{Field: "source", Op: Exists}}},
		Match: &Match{Field: "source", Op: Exists},
	}
	if err := r.Validate(); err == nil {
		t.Error("a condition that is both an 'all' and a comparison was accepted")
	}
}

func TestComparisonIsCaseFolded(t *testing.T) {
	// A Windows source spells a username three ways in one day. A rule that
	// matches two of them is the silent kind of broken.
	f := map[string]string{"actor": "OKTA:U-1"}
	m := Match{Field: "actor", Op: Equals, Values: []string{"okta:u-1"}}
	if !m.eval(f) {
		t.Error("equals did not fold case")
	}
	m = Match{Field: "actor", Op: Contains, Values: []string{"u-1"}}
	if !m.eval(f) {
		t.Error("contains did not fold case")
	}
}

func TestANumericComparisonRefusesText(t *testing.T) {
	// "10" sorts below "9" as text, and a severity threshold that behaves
	// that way is worse than none because it looks like it is working.
	if !compare(Above, "10", "9") {
		t.Error("10 is not above 9")
	}
	if compare(Above, "high", "9") {
		t.Error("a non-numeric value was compared numerically")
	}
	// And through the field surface, where severity is a number as a string.
	f := map[string]string{"severity": "4"}
	m := Match{Field: "severity", Op: Above, Values: []string{"3"}}
	if !m.eval(f) {
		t.Error("severity 4 is not above 3")
	}
}

func TestExistsAsksAboutPresenceAndNotValue(t *testing.T) {
	f := map[string]string{"raw.factor": ""}
	m := Match{Field: "raw.factor", Op: Exists}
	if !m.eval(f) {
		t.Error("a field present with an empty value was reported absent")
	}
	m = Match{Field: "raw.missing", Op: Exists}
	if m.eval(f) {
		t.Error("an absent field was reported present")
	}
}

func TestExistsWithValuesIsRefused(t *testing.T) {
	r := mfaRule()
	r.When = Predicate{Match: &Match{
		Field: "source", Op: Exists, Values: []string{"okta/system"}}}
	if err := r.Validate(); err == nil {
		t.Error("a presence test that also compares values was accepted; " +
			"one of the two is not what was meant")
	}
}

func TestAnEmptyValueIsRefused(t *testing.T) {
	// With contains it matches every event that has the field at all, which
	// is not what anybody writing "" intends.
	r := mfaRule()
	r.When = Predicate{Match: &Match{
		Field: "source", Op: Contains, Values: []string{""}}}
	if err := r.Validate(); err == nil {
		t.Error("a comparison against an empty value was accepted")
	}
}

func TestNotInverts(t *testing.T) {
	inner := Predicate{Match: &Match{Field: "source", Op: Equals,
		Values: []string{"okta/system"}}}
	f := map[string]string{"source": "okta/system"}
	if !eval(inner, f) {
		t.Fatal("the inner condition does not match")
	}
	if eval(Predicate{Not: &inner}, f) {
		t.Error("not did not invert")
	}
}

func TestNestingIsBounded(t *testing.T) {
	// A rule is data, and data from a file somebody generated nests as deeply
	// as the generator felt like.
	p := Predicate{Match: &Match{Field: "source", Op: Exists}}
	for range MaxDepth + 4 {
		p = Predicate{All: []Predicate{p}}
	}
	r := mfaRule()
	r.When = p
	if err := r.Validate(); err == nil {
		t.Error("a condition nested past the bound was accepted")
	}
}

// -- what a rule reads --------------------------------------------------------

func TestTheFieldsARuleReadsAreReported(t *testing.T) {
	// Sorted, because this is what an author is shown and a list that
	// reorders between runs is one nobody can diff.
	got := mfaRule().Fields()
	want := []string{"disposition", "raw.event"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the rule reads %v, wanted %v", got, want)
	}
}

func TestAFailingFixtureSaysWhichWayItFailed(t *testing.T) {
	// The two directions are different problems. A missed detection is a gap;
	// a false positive is a cost paid by whoever reads the alert.
	missed := Result{Rule: "r", Fixture: "f", Want: true, Got: false}
	if !strings.Contains(missed.Why(), "asserted to catch") {
		t.Errorf("a miss reads as: %s", missed.Why())
	}
	noisy := Result{Rule: "r", Fixture: "f", Want: false, Got: true}
	if !strings.Contains(noisy.Why(), "benign") {
		t.Errorf("a false positive reads as: %s", noisy.Why())
	}
	if (Result{Want: true, Got: true}).Why() != "" {
		t.Error("a passing result explains itself")
	}
}
