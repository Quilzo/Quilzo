// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A role reaches only the package's own blocks, as one of the things each
// can be granted as.
func TestARoleReachesOnlyThePackagesOwnBlocks(t *testing.T) {
	for name, mutate := range map[string]func(*Package){
		"another collection":     func(p *Package) { p.Roles[0].Grants[0].Collection = "payroll" },
		"a page it did not make": func(p *Package) { p.Roles[0].Grants[1].Page = "about" },
		"an agent it did not declare": func(p *Package) {
			p.Roles[0].Grants = append(p.Roles[0].Grants, Grant{Agent: "intake", May: "run"})
		},
		"administering":         func(p *Package) { p.Roles[0].Grants[0].May = "admin" },
		"publishing records":    func(p *Package) { p.Roles[0].Grants[0].May = "publish" },
		"two blocks in a grant": func(p *Package) { p.Roles[0].Grants[0].Page = "samples" },
		"no block":              func(p *Package) { p.Roles[0].Grants[0].Collection = "" },
		"nothing granted":       func(p *Package) { p.Roles[0].Grants = nil },
		"no title":              func(p *Package) { p.Roles[0].Title = "" },
		"a bad name":            func(p *Package) { p.Roles[0].Name = "Lab Tech" },
		"declared twice":        func(p *Package) { p.Roles = append(p.Roles, p.Roles[0]) },
		"a grant twice":         func(p *Package) { p.Roles[0].Grants[1] = p.Roles[0].Grants[0] },
	} {
		t.Run(name, func(t *testing.T) {
			p := sample(t)
			mutate(p)
			if err := p.Validate(checks); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// A role is the bindings it stands for, on the resources each block is
// checked against.
func TestARoleIsTheBindingsItStandsFor(t *testing.T) {
	p := sample(t)
	ar := p.AppRole(p.Roles[0])
	want := []auth.Binding{
		{Role: auth.RoleAuthor, Resource: "/@data/samples"},
		{Role: auth.RoleReader, Resource: "/samples"},
	}
	if ar.Name != "lab-samples/technician" || len(ar.Bindings) != len(want) {
		t.Fatalf("%+v", ar)
	}
	for i := range want {
		if ar.Bindings[i] != want[i] {
			t.Errorf("binding %d is %+v, want %+v", i, ar.Bindings[i], want[i])
		}
	}
	if !strings.Contains(ar.Grants[0], "writes the records in \"samples\"") {
		t.Errorf("%q", ar.Grants[0])
	}
}

// The card lists the roles, and declaring one does not by itself ask for a
// second approver: a role holds nobody until it is granted.
func TestTheCardListsRolesWithoutRaisingTheRisk(t *testing.T) {
	p := sample(t)
	with := p.MakeCard()
	if len(with.Roles) != 2 || !strings.Contains(with.Roles[1].Text, "publishes the page \"samples\"") {
		t.Errorf("%+v", with.Roles)
	}
	p.Roles = nil
	without := p.MakeCard()
	if with.Approvers != without.Approvers || with.Risk != without.Risk {
		t.Errorf("roles changed the approvers: %d/%s against %d/%s", with.Approvers, with.Risk, without.Approvers, without.Risk)
	}
}

// A model drafting a feature is not shown roles, and roles in its answer
// are left out and said to be.
func TestADraftHoldsNoRoles(t *testing.T) {
	if strings.Contains(DraftPrompt(nil), "technician") {
		t.Error("the drafting prompt shows the model how to write roles")
	}
	answer := `{"name":"lab","title":"Lab","purpose":"Samples.","roles":[{"name":"boss","title":"Boss","grants":[{"page":"x","may":"publish"}]}]}`
	p, notes, err := ReadDraft(answer, nil, "dana", "a lab", "m", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Roles) != 0 || len(notes) != 1 || !strings.Contains(notes[0], `left out "roles"`) {
		t.Errorf("roles %v, notes %v", p.Roles, notes)
	}
}
