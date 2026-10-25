// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package standing

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

func TestTheRegisterIsWellFormed(t *testing.T) {
	if err := Check(); err != nil {
		t.Fatal(err)
	}
	s := Look()
	if s.Roles < 5 || s.Powers < 12 {
		t.Fatalf("%+v", s)
	}
	// Every role here today acts inside its own situation: the ones that
	// reached outside (an incident's commander, a detection's promoter, a
	// work item's assignee) left with the security team's tools for
	// Vaigil. TestAPowerThatOutlivesItsSituationIsAStandingAct keeps the
	// rule for the next one.
	if s.Contained == 0 {
		t.Fatal("everything reaches outside, which would mean the " +
			"distinction is not being drawn")
	}
}

// TestAPowerThatReachesOutsideMustNameWhatItNeeds.
func TestAPowerThatReachesOutsideMustNameWhatItNeeds(t *testing.T) {
	for _, c := range []struct {
		name string
		p    Power
		says string
	}{
		{"no reason", Power{Name: "x"}, "unexplained judgement"},
		{"outside with no action", Power{Name: "x", Outside: true,
			Why: "because"}, "situational costume"},
		{"inside that needs authority", Power{Name: "x", Why: "because",
			Needs: auth.ActPublish}, "run by whoever has the most access"},
	} {
		if err := c.p.Validate(); err == nil {
			t.Errorf("%s: accepted", c.name)
		} else if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// TestACallHostNeedsNoStandingAuthority.
//
// The rule that is not obvious. Requiring one would mean meetings are run
// by whoever has the most access, which is a permission model shaping the
// organisation.
func TestACallHostNeedsNoStandingAuthority(t *testing.T) {
	host, ok := Find("huddle", "host")
	if !ok {
		t.Fatal("no host role")
	}
	if !host.Contained() {
		t.Fatalf("a call host reaches outside: %+v", host.Reaches())
	}
	for _, p := range []string{"admit", "eject", "mute", "lock"} {
		if err := Allows(host, p, "ada", nil, "/"); err != nil {
			t.Errorf("%s needed standing authority: %v", p, err)
		}
	}
	// Even ejecting, which is cryptographic and irreversible for that
	// call, is contained: they can be invited to the next one.
	if err := Allows(host, "eject", "anybody", nil, "/"); err != nil {
		t.Fatal(err)
	}
}

// A power that outlives its situation is a standing act: refused with no
// standing authority, and with the reason, refused to a reader, allowed to
// somebody who may publish. Built here because no role this program has
// today reaches outside; the rule is what keeps the next one honest.
func TestAPowerThatOutlivesItsSituationIsAStandingAct(t *testing.T) {
	pro := Situational{Package: "example", Name: "promoter", What: "moves a rule to live",
		Held: "by being somebody other than whoever proposed it", Ends: "at the promotion",
		Powers: []Power{{Name: "promote", Outside: true, Needs: auth.ActPublish,
			Why: "a rule reaching live alerts everybody for as long as it runs"},
			{Name: "look", Why: "reading the candidate changes nothing"}}}
	if pro.Contained() {
		t.Fatal("promoting a rule to live was classified as contained")
	}
	if err := Allows(pro, "look", "grace", nil, "/"); err != nil {
		t.Fatalf("a contained power needed authority: %v", err)
	}
	// With no policy at all, it is refused and says why.
	err := Allows(pro, "promote", "grace", nil, "/")
	if err == nil {
		t.Fatal("a power reaching outside was allowed with no standing authority anywhere")
	}
	if !strings.Contains(err.Error(), "alerts everybody") {
		t.Fatalf("%v", err)
	}
	// A reader who happens to hold the role is still refused.
	p := &auth.Policy{}
	if err := p.Grant(auth.Binding{Principal: "grace",
		Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := Allows(pro, "promote", "grace", p, "/"); err == nil {
		t.Fatal("a reader used a power that reaches outside")
	}
	// Somebody who may publish is not.
	if err := p.Grant(auth.Binding{Principal: "ada",
		Role: auth.RolePublisher, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := Allows(pro, "promote", "ada", p, "/"); err != nil {
		t.Fatalf("a publisher was refused: %v", err)
	}
}

// TestWithdrawingConsentHasNoFloorAtAll, deliberately.
func TestWithdrawingConsentHasNoFloorAtAll(t *testing.T) {
	sc, ok := Find("scribe", "participant")
	if !ok {
		t.Fatal("no participant role")
	}
	if !sc.Contained() {
		t.Fatal("a participant's powers reach outside the call")
	}
	if err := Allows(sc, "withdraw-consent", "anybody", nil, "/"); err != nil {
		t.Fatalf("withdrawing consent required authority: %v", err)
	}
	p, _ := sc.Power("withdraw-consent")
	if !strings.Contains(p.Why, "nobody's to refuse") {
		t.Fatalf("why = %q", p.Why)
	}
}

func TestAnUnknownPowerSaysWhatExists(t *testing.T) {
	host, _ := Find("huddle", "host")
	err := Allows(host, "delete-everything", "ada", nil, "/")
	if err == nil {
		t.Fatal("an invented power was allowed")
	}
	for _, want := range []string{"admit", "eject", "lock", "mute"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not list %q: %v", want, err)
		}
	}
}

// TestEveryPackageWithASituationalRoleIsRegistered.
//
// The guard this package exists for. The failure is not a wrong entry, it
// is a ninth model appearing quietly in the tenth package — so the check is
// that nothing under internal/ defines a role-shaped vocabulary without
// appearing in the register.
func TestEveryPackageWithASituationalRoleIsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, p := range Packages() {
		registered[p] = true
	}
	// Packages whose roles are standing rather than situational, or which
	// have none, with the reason each is exempt.
	exempt := map[string]string{
		"auth": "it is the standing model itself",
		"agent": "an agent's authority is a manifest bounded by the " +
			"person who ran it, which is a narrowing rather than a role",
		"workforce": "it reads roles from an identity provider and " +
			"reconciles them; it confers nothing",
		"review": "it reads access somebody else granted",
		"collab": "a proposal's author is a fact about the proposal " +
			"rather than authority over anything",
		"vendor":  "a tier is a classification, not a power",
		"posture": "a severity is not a role",
		"oscal": "a role in an OSCAL document names who is responsible " +
			"for a control in that document; it confers nothing here",
		"feature": "a role a feature declares is standing: it is granted " +
			"as auth bindings, held until revoked, and confers nothing " +
			"those bindings do not",
	}
	var missing []string
	err := filepath.WalkDir("..", func(path string, d os.DirEntry,
		err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		pkg := filepath.Base(path)
		if pkg == "standing" || registered[pkg] || exempt[pkg] != "" {
			return nil
		}
		if !defines(t, path) {
			return nil
		}
		missing = append(missing, pkg)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) > 0 {
		t.Fatalf(
			"these package(s) define a role-shaped vocabulary and are not "+
				"in the register: %s. Either register what the role "+
				"confers and whether each power survives its situation, or "+
				"add it to the exemptions with the reason",
			strings.Join(missing, ", "))
	}
}

// defines reports whether a package declares a type called Role.
//
// The common shape and not the only one: internal/errand's owner and
// internal/proving's promoter are situational roles with no type called
// Role, and both are registered anyway. So the register is deliberately
// wider than this catches, and what this catches is the case where
// somebody reaches for the obvious name — which is the case most likely to
// be written without thinking about whether its powers survive.
func defines(t *testing.T, dir string) bool {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return false
	}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, decl := range f.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.TYPE {
					continue
				}
				for _, spec := range gen.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if ok && ts.Name.Name == "Role" {
						return true
					}
				}
			}
		}
	}
	return false
}
