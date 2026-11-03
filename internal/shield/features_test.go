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
