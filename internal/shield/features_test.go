// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A feature the site asks the shield about is one the shield can turn down.
//
// # What this found
//
// The public site asked about "fediverse", "bookings" and "newsletter" —
// the inbox that makes this server fetch from hosts a stranger names, the
// booking form and the newsletter sign-up — and none of the three was in
// Features. Validate refuses a target that is not there, so `quilzo shield
// feature fediverse`, the Shield screen and every playbook were told it was
// "not a feature the shield can turn down", and the check in the handler
// could never come true. Three public surfaces had a switch wired to
// nothing, and nothing said so until somebody needed it in an incident.
//
// # Why a source walk
//
// Because the two halves are a string in one package and a map key in
// another, and nothing joins them: the handler compiles and runs whether or
// not the name is a key. What is wrong is visible only in the call, so the
// call is what this reads — every place a feature is asked about by a
// literal name, in every package, held against Features.
func TestEveryFeatureAskedAboutCanBeTurnedDown(t *testing.T) {
	asked := map[string]string{}
	for _, dir := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if name, ok := featureNamed(call); ok {
					asked[name] = fset.Position(call.Pos()).String()
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Some of each kind of caller, or the walk is reading nothing and a test
	// that sees nothing passes.
	for _, want := range []string{"signup", "mcp", "scim", "chatbot", "upload"} {
		if _, ok := asked[want]; !ok {
			t.Fatalf("the walk did not find the site asking about %q, so it "+
				"is not reading the callers it means to; found %v", want, asked)
		}
	}
	for name, where := range asked {
		if _, ok := Features[name]; !ok {
			t.Errorf("%s asks the shield whether %q is turned down, and %q "+
				"is not in Features, so nobody can ever turn it down: the "+
				"command line, the Shield screen and every playbook are told "+
				"it is not a feature", where, name, name)
		}
	}
}

// And turning each of the three down is accepted and seen, end to end
// through the store the enforcement point reads.
func TestThePublicSurfacesThatWereMissingCanBeTurnedDown(t *testing.T) {
	g := guard(t)
	for _, name := range []string{"fediverse", "bookings", "newsletter"} {
		p := ok(Feature, name)
		if err := p.Validate(t0); err != nil {
			t.Fatalf("%s cannot be turned down: %v", name, err)
		}
		put(t, g, p)
		if _, on := g.Feature(name, t0); !on {
			t.Errorf("%s was turned down and the guard does not see it", name)
		}
	}
	if _, on := g.Feature("fediverse", t0.Add(2*time.Hour)); on {
		t.Error("a feature shield did not end when it said it would")
	}
}

// featureNamed is the feature a call asks the shield about by a literal
// name: the public site's shielded, the admin's shieldedOff and
// shieldable, the command line's shield host (off, feature), and a
// shield.Find for a Feature. A name with a part after a colon (chatbot:help)
// is the feature before it.
func featureNamed(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	arg := -1
	switch sel.Sel.Name {
	case "shielded", "shieldable", "off", "feature":
		arg = 0
	case "shieldedOff":
		arg = 1
	case "Find":
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "shield" && len(call.Args) > 2 {
			if kind, ok := call.Args[1].(*ast.SelectorExpr); ok && kind.Sel.Name == "Feature" {
				arg = 2
			}
		}
	}
	if arg < 0 || arg >= len(call.Args) {
		return "", false
	}
	lit := call.Args[arg]
	if bin, ok := lit.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		lit = bin.X // "chatbot:" + a.Name
	}
	s, ok := lit.(*ast.BasicLit)
	if !ok || s.Kind != token.STRING {
		return "", false
	}
	name, err := strconv.Unquote(s.Value)
	if err != nil {
		return "", false
	}
	name, _, _ = strings.Cut(name, ":")
	return name, name != ""
}

// A flood of spam turns off what was flooded.
//
// # What this found
//
// The booking form and the newsletter sign-up refuse spam as a form does,
// and say so with the same signal, so that the shipped form-flood playbook
// can close them for a while. The engine made every such signal's subject
// a form's name: the newsletter's became form:newsletter, which closes a
// form called newsletter if there is one and leaves the sign-up open, and a
// booking's became form:booking:NAME, which the shield refuses as not a
// name, so nothing was turned off. Switches for bookings and the
// newsletter could be turned on by hand; the shield's own answer to the
// attack that most calls for them still could not reach them.
//
// # How
//
// Every place that raises a form-spam signal, in every package, with the
// subject it raises it with; the engine acting on that signal, as the
// shipped playbook does; and the feature it turned off held against what
// the same function asks the shield about. A subject that is not written
// out — a form's own name — stands in as a name.
func TestAFloodOfSpamTurnsOffWhatWasFlooded(t *testing.T) {
	type raised struct {
		subject, where string
		asks           map[string]bool
	}
	var found []raised
	for _, dir := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				asks := map[string]bool{}
				var here []raised
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if name, ok := featureNamed(call); ok {
						asks[name] = true
					}
					if subject, ok := spamSubject(call); ok {
						here = append(here, raised{subject: subject, where: fset.Position(call.Pos()).String()})
					}
					return true
				})
				for _, r := range here {
					r.asks = asks
					found = append(found, r)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// A form, the newsletter and a booking, or the walk is reading nothing
	// and a test that sees nothing passes.
	for _, want := range []string{"name", "newsletter", "booking"} {
		seen := false
		for _, r := range found {
			seen = seen || strings.HasPrefix(r.subject, want)
		}
		if !seen {
			t.Fatalf("the walk found nothing raising form-spam about %q; found %+v", want, found)
		}
	}

	var flood Playbook
	for _, pb := range Builtins() {
		if pb.Name == "form-flood" {
			flood = pb
		}
	}
	if flood.Name == "" {
		t.Fatal("no form-flood playbook is shipped")
	}
	flood.Mode, flood.On.Count = "act", 1

	for _, r := range found {
		rig := newRig(t, flood)
		rig.see("form-spam", "198.51.100.1", r.subject)
		var off []string
		for _, p := range rig.state(t).Protections {
			if p.Kind == Feature {
				off = append(off, p.Target)
			}
		}
		if len(off) != 1 {
			t.Errorf("%s: a flood of spam about %q turned off %v, not the one thing that was flooded", r.where, r.subject, off)
			continue
		}
		if name, _, _ := strings.Cut(off[0], ":"); !r.asks[name] {
			t.Errorf("%s: a flood of spam about %q turned off %s, and what was flooded asks the shield only about %v",
				r.where, r.subject, off[0], r.asks)
		}
	}

	// And a form that happens to be called newsletter is still a form.
	rig := newRig(t, flood)
	rig.see("form-spam", "198.51.100.1", "newsletter")
	if _, on := rig.Guard.Feature("form:newsletter", rig.clock); !on {
		t.Error("a flood at the form called newsletter did not close that form")
	}
	if _, on := rig.Guard.Feature("newsletter", rig.clock); on {
		t.Error("a flood at the form called newsletter closed the newsletter sign-up instead")
	}
}

// spamSubject is the subject a call raises a form-spam signal with: the
// site's signal(FormSpam, subject, r). What is added to a written-out
// prefix, and a subject not written out at all, stand in as a name.
func spamSubject(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "signal" || len(call.Args) < 2 {
		return "", false
	}
	switch kind := call.Args[0].(type) {
	case *ast.Ident:
		if kind.Name != "FormSpam" {
			return "", false
		}
	case *ast.SelectorExpr:
		if kind.Sel.Name != "FormSpam" {
			return "", false
		}
	default:
		return "", false
	}
	subject, rest := call.Args[1], ""
	if bin, ok := subject.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		subject, rest = bin.X, "name"
	}
	if s, ok := subject.(*ast.BasicLit); ok && s.Kind == token.STRING {
		v, err := strconv.Unquote(s.Value)
		return v + rest, err == nil
	}
	return "name", true
}
