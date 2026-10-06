// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package controls

import (
	"regexp"
	"strings"
	"testing"

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
