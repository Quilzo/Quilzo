// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/posture"
)

// A control a rule checks, a setting implements or a parameter belongs to
// has a statement, so the plan cannot fall behind the code.
func TestEveryCitedControlHasAStatement(t *testing.T) {
	have := map[string]bool{}
	for _, im := range table {
		have[Normal(im.Control)] = true
	}
	need := map[string]string{}
	for _, r := range posture.Rules() {
		for _, c := range r.Controls {
			need[Normal(c)] = "rule " + r.ID
		}
	}
	for _, s := range config.All() {
		for _, c := range s.Controls {
			need[Normal(c)] = "setting " + s.Key
		}
	}
	for _, p := range odp.Params {
		need[Normal(p.Control)] = "parameter " + p.ID
	}
	for c, by := range need {
		if !have[c] {
			t.Errorf("%s is cited by %s and has no implementation statement", c, by)
		}
	}
}

// Each statement is well formed: a real-looking id, once, a title, a
// statement, and a customer part wherever the customer has one.
func TestEveryStatementIsComplete(t *testing.T) {
	id := regexp.MustCompile(`^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?$`)
	seen := map[string]bool{}
	for _, im := range table {
		if !id.MatchString(im.Control) {
			t.Errorf("%q is not a control id", im.Control)
		}
		if seen[Normal(im.Control)] {
			t.Errorf("%s twice", im.Control)
		}
		seen[Normal(im.Control)] = true
		if im.Title == "" || len(im.Statement) < 40 {
			t.Errorf("%s has no title or a statement too short to test", im.Control)
		}
		switch im.Responsibility {
		case Quilzo:
			if im.Customer != "" {
				t.Errorf("%s is Quilzo's alone and names a customer part", im.Control)
			}
		case Shared, Customer:
			if im.Customer == "" {
				t.Errorf("%s is %s and does not say the customer's part", im.Control, im.Responsibility)
			}
		default:
			t.Errorf("%s has no responsibility", im.Control)
		}
		if strings.Contains(strings.ToLower(im.Statement), "compliant") {
			t.Errorf("%s claims compliance; a statement says what the software does", im.Control)
		}
	}
}

func TestControlsAreFoundAndOrderedAsTheCatalogueWritesThem(t *testing.T) {
	if Normal("AC-02(05)") != "ac-2.5" || Normal("ac-2.5") != "ac-2.5" {
		t.Fatal(Normal("AC-02(05)"))
	}
	im, ok := Lookup("ac-7")
	if !ok || len(im.Rules) == 0 || len(im.Settings) == 0 || len(im.Params) == 0 {
		t.Fatalf("AC-7 not joined to its rules, settings and parameters: %+v", im)
	}
	all := All()
	for i := 1; i < len(all); i++ {
		if Less(all[i].Control, all[i-1].Control) {
			t.Fatalf("%s before %s", all[i-1].Control, all[i].Control)
		}
	}
	if !Less("AC-2", "AC-2(3)") || !Less("AC-2(7)", "AC-3") || !Less("AC-7", "AC-11") {
		t.Fatal("order")
	}
}

// The pledge is seven goals in CISA's order, each with a position that
// says what is not done where something is not.
func TestThePledgeIsAnsweredGoalByGoal(t *testing.T) {
	if len(Pledge) != 7 {
		t.Fatalf("%d goals", len(Pledge))
	}
	for i, g := range Pledge {
		if g.N != i+1 || g.Title == "" || g.Asks == "" || len(g.Position) < 60 {
			t.Errorf("goal %d is incomplete", i+1)
		}
		switch g.Standing {
		case Met, Partly, NotYet:
		default:
			t.Errorf("goal %d has no standing", g.N)
		}
		if g.Standing != Met && !strings.Contains(strings.ToLower(g.Position), "not") {
			t.Errorf("goal %d is %s and its position does not say what is not done", g.N, g.Standing)
		}
	}
}

// The plan is held to the baseline the owner chose, splits each control
// between Quilzo and the organisation, and marks partial what the scan
// says is failing.
func TestThePlanSplitsEachControlAndShowsWhatFails(t *testing.T) {
	if _, err := SystemSecurityPlan(SSPInput{Impact: "severe"}); err == nil {
		t.Fatal("an impact level that is not FIPS 199")
	}
	plan, err := SystemSecurityPlan(SSPInput{Impact: "moderate", SystemID: "x", At: time.Now(),
		Failing: map[string][]string{"ac-7": {"policy.unmet: auth.throttle.after = 9"}}})
	if err != nil {
		t.Fatal(err)
	}
	body := plan.SystemSecurityPlan
	if !strings.HasSuffix(body.ImportProfile.Href, "MODERATE-baseline_profile.json") ||
		body.SystemCharacteristics.SecuritySensitivityLevel != "fips-199-moderate" {
		t.Fatalf("not held to the moderate baseline: %+v", body.ImportProfile)
	}
	for _, r := range body.ControlImplementation.ImplementedRequirements {
		im, _ := Lookup(r.ControlID)
		var quilzo, org bool
		for _, b := range r.ByComponents {
			if b.ResponsibleRoles[0].RoleID == "provider" {
				quilzo = true
				if r.ControlID == "ac-7" && b.ImplementationStatus.State != "partial" {
					t.Error("AC-7 is failing and shown as implemented")
				}
				if r.ControlID == "ac-3" && b.ImplementationStatus.State != "implemented" {
					t.Error("AC-3 passes and is not shown as implemented")
				}
			} else {
				org = true
			}
		}
		if quilzo != (im.Responsibility != Customer) || org != (im.Customer != "") {
			t.Errorf("%s is %s and its parts are quilzo=%v organisation=%v", r.ControlID, im.Responsibility, quilzo, org)
		}
	}
}

// AU-10 said publications "are timestamped and anchored" and that content
// and media "carry signed provenance", and it flows into the component
// definition and the system security plan an assessor tests. Timestamping
// and anchoring are commands somebody runs: no job and no publish hook does
// either. A page's provenance is a record bound to the hash of its content,
// not a signature; only images carry one. So the statement says which part
// happens by itself and which on request, and the customer's half is named.
func TestNonRepudiationSaysWhatIsAutomaticAndWhatIsOnRequest(t *testing.T) {
	im, ok := Lookup("au-10")
	if !ok {
		t.Fatal("no AU-10")
	}
	s := strings.ToLower(im.Statement)
	for _, claim := range []string{"publications are timestamped", "content and media carry signed"} {
		if strings.Contains(s, claim) {
			t.Errorf("AU-10 says %q, which nothing in the program does by itself", claim)
		}
	}
	if !strings.Contains(s, "on request") {
		t.Errorf("AU-10 does not say timestamping and anchoring happen on request: %s", im.Statement)
	}
	if im.Responsibility == Quilzo {
		t.Error("AU-10 is Quilzo's alone, and a publication nobody stamps is not stamped")
	}
	for _, cmd := range []string{"quilzo timestamp stamp", "quilzo anchor submit"} {
		found := false
		for _, w := range im.Where {
			found = found || w == cmd
		}
		if !found {
			t.Errorf("AU-10 does not name %q, the command that does it", cmd)
		}
	}
}

// Goal 4 said every running copy checks itself hourly. The check is one of
// the admin server's jobs: the public site server runs only retention, so a
// copy serving the site without the admin never checks itself.
func TestThePatchGoalSaysWhichServerChecksItself(t *testing.T) {
	g := Pledge[3]
	if g.N != 4 {
		t.Fatalf("goal %d where 4 was expected", g.N)
	}
	p := strings.ToLower(g.Position)
	if strings.Contains(p, "every running copy") {
		t.Errorf("goal 4 says every running copy checks itself: %s", g.Position)
	}
	if !strings.Contains(g.Position, "quilzo serve") || !strings.Contains(g.Position, "quilzo site") {
		t.Errorf("goal 4 does not say which server checks itself and which does not: %s", g.Position)
	}
}
