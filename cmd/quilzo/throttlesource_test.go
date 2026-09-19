// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every limiter this program builds must take the configured policy.
//
// # What this found
//
// throttlePolicy's own comment says it exists so "the CLI, the admin interface
// and the API cannot end up with three different ideas of how many attempts
// are free". `quilzo studio` was the fourth surface, built after that sentence
// was written, and it held throttle.New(throttle.Default()).
//
// So every auth.throttle.* and auth.lockout.* setting was silently ignored on
// that port. The studio does authenticate tokens and does use its limiter, so
// an operator who set auth.lockout.hard or raised auth.throttle.max got the
// compiled-in numbers there and their own everywhere else — and nothing said
// so on either side.
//
// # Why a source walk
//
// Because the failure is the argument somebody passed, and both arguments
// produce a working limiter. There is no behaviour to drive that distinguishes
// them without knowing the configured numbers in advance, and a test that knew
// them would be a test of the fixture. What is wrong is visible only in the
// call, so the call is what this reads.
//
// One exemption, named: internal/throttle's own Default is what a package with
// no configuration should use, and cmd/quilzo has configuration.
func TestEveryThrottleTakesTheConfiguredPolicy(t *testing.T) {
	built := 0
	for _, file := range commandFiles(t) {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, file, src, 0)
		if err != nil {
			continue
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isCall(call, "throttle", "New") || len(call.Args) != 1 {
				return true
			}
			built++
			if inner, ok := call.Args[0].(*ast.CallExpr); ok {
				if isCall(inner, "throttle", "Default") {
					t.Errorf("%s:%d builds a limiter from throttle.Default(), "+
						"so every auth.throttle and auth.lockout setting is "+
						"ignored on that surface",
						file, fset.Position(call.Pos()).Line)
				}
			}
			return true
		})
	}
	if built == 0 {
		t.Fatal("found no throttle.New anywhere; the walk is wrong and a " +
			"test that sees nothing passes")
	}
}

// isCall reports whether a call is pkg.Name(...).
func isCall(c *ast.CallExpr, pkg, name string) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// commandFiles lists this package's non-test source.
func commandFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") ||
			strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, filepath.Clean(n))
	}
	return out
}
