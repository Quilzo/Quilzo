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
	if s.Roles < 4 || s.Powers < 7 {
		t.Fatalf("%+v", s)
	}
	// Most roles here act inside their own situation. One reaches outside:
	// an enrolment link, whose passkey outlives it.
	// TestAPowerThatOutlivesItsSituationIsAStandingAct keeps the rule.
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

// A visitor handed to a person needs no standing authority.
//
// The rule that is not obvious. Requiring one would mean only the people
// with the most access could be helped, which is a permission model shaping
// the organisation.
func TestAHandoffVisitorNeedsNoStandingAuthority(t *testing.T) {
	v, ok := Find("handoff", "visitor")
	if !ok {
		t.Fatal("no handoff visitor")
	}
	if !v.Contained() {
		t.Fatalf("a handoff visitor reaches outside: %+v", v.Reaches())
	}
	for _, p := range []string{"read", "say", "end"} {
		if err := Allows(v, p, "anybody", nil, "/"); err != nil {
			t.Errorf("%s needed standing authority: %v", p, err)
		}
	}
}

// A power that outlives its situation is a standing act: refused with no
// standing authority, and with the reason, refused to a reader, allowed to
// somebody who may publish. Built here rather than read from the register,
// so the rule is tested whatever the register holds.
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

func TestAnUnknownPowerSaysWhatExists(t *testing.T) {
	v, _ := Find("handoff", "visitor")
	err := Allows(v, "delete-everything", "ada", nil, "/")
	if err == nil {
		t.Fatal("an invented power was allowed")
	}
	for _, want := range []string{"end", "read", "say"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not list %q: %v", want, err)
		}
	}
}

// exemptions are the packages whose roles are standing rather than
// situational, or which have none, with the reason each is exempt.
//
// Each names a package that is here and not registered
// (TestEveryExemptionNamesAPackageThatIsHere): workforce, review and vendor
// were listed after they left with the security team's tools, and agent
// after its run starter was registered.
var exemptions = map[string]string{
	"auth": "it is the standing model itself",
	"collab": "a proposal's author is a fact about the proposal " +
		"rather than authority over anything",
	"posture": "a severity is not a role",
	"oscal": "a role in an OSCAL document names who is responsible " +
		"for a control in that document; it confers nothing here",
	"feature": "a role a feature declares is standing: it is granted " +
		"as auth bindings, held until revoked, and confers nothing " +
		"those bindings do not",
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
	var missing []string
	err := filepath.WalkDir("..", func(path string, d os.DirEntry,
		err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		pkg := filepath.Base(path)
		if pkg == "standing" || registered[pkg] || exemptions[pkg] != "" {
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
// The common shape and not the only one: a share link's holder and a
// handoff's visitor are situational roles with no type called Role, and
// both are registered anyway. So the register is deliberately
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

// The register called itself every situational role in this program and
// left out the ones a deployment hands out every day: a share link, a
// handoff conversation's secret, an enrolment link and an agent run's
// starter. Each is authority a situation hands somebody that no grant did.
func TestTheRolesADeploymentHandsOutAreRegistered(t *testing.T) {
	for _, r := range []struct{ pkg, name string }{
		{"share", "link holder"},
		{"handoff", "visitor"},
		{"enrol", "link holder"},
		{"agent", "run starter"},
	} {
		if _, ok := Find(r.pkg, r.name); !ok {
			t.Errorf("%s/%s is handed out by a deployment and is not in the register", r.pkg, r.name)
		}
	}
	// An enrolment link adds a passkey that outlives it: a standing act,
	// resting on the grant of whoever made the link.
	if l, ok := Find("enrol", "link holder"); ok && l.Contained() {
		t.Error("a passkey added through an enrolment link outlives the link, and the register says it does not")
	}
}

// The exemptions named packages that are not in this repository — they
// left with the security team's tools — so the guard was excusing nothing
// and reading as if it covered them. An exemption names a package that
// exists and is not already registered.
func TestEveryExemptionNamesAPackageThatIsHere(t *testing.T) {
	registered := map[string]bool{}
	for _, p := range Packages() {
		registered[p] = true
	}
	for pkg := range exemptions {
		if info, err := os.Stat(filepath.Join("..", pkg)); err != nil || !info.IsDir() {
			t.Errorf("internal/%s is exempt and does not exist", pkg)
		}
		if registered[pkg] {
			t.Errorf("internal/%s is exempt and registered", pkg)
		}
	}
}

// The sentence about the register agrees with its numbers.
//
// It was written when two roles reached outside their situation, and read
// "7 are contained and 2 confer something". With the call demonstrations
// and the room gone one role does, and `quilzo standing list` printed "3 are
// contained and 1 confer something": a sentence that is wrong about its own
// count reads as a count nobody checked.
func TestTheRegistersSentenceAgreesWithItsNumbers(t *testing.T) {
	for _, c := range []struct {
		shape Shape
		want  string
	}{
		{Shape{Roles: 4, Packages: 4, Powers: 7, Contained: 3, Reaching: 1},
			"3 are contained and 1 confers something"},
		{Shape{Roles: 3, Packages: 3, Powers: 5, Contained: 1, Reaching: 2},
			"1 is contained and 2 confer something"},
		{Shape{Roles: 9, Packages: 8, Powers: 19, Contained: 7, Reaching: 2},
			"7 are contained and 2 confer something"},
		{Shape{Roles: 2, Packages: 2, Powers: 3, Contained: 2, Reaching: 0},
			"2 are contained and 0 confer something"},
	} {
		if got := c.shape.Why(); !strings.Contains(got, c.want) {
			t.Errorf("%+v is described as %q, which does not say %q", c.shape, got, c.want)
		}
	}
	// And the register as it stands is described in a sentence that agrees.
	if s := Look(); s.Reaching == 1 && !strings.Contains(s.Why(), "1 confers something") {
		t.Errorf("the register is described as %q", s.Why())
	}
}
