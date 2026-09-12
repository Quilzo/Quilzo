// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every package is reached by something other than its own tests.
//
// internal/slack and internal/discord were complete, correct and reachable by
// nobody. A signature verifier with a real test suite, no CLI command, no
// route, and nothing importing it: about six hundred lines that had never run
// outside a test. internal/chat was built as the layer beneath them and only
// Telegram ever arrived there.
//
// Nothing failed. Both packages compile, both are covered, and `go vet` has no
// opinion about a package nobody imports — which is why this survived. It is
// the same shape as the federation loops, whose comment records the same
// discovery: "Both were built and neither was reachable — a followed site that
// confirmed nothing and posted nothing — until this started them."
//
// A package nobody imports is worse than a missing feature. It is maintained,
// it is tested, it appears in the inventory, and it answers nobody — so the
// project believes it has a capability it does not have.
//
// Reached means imported by a non-test file in another package. That is
// deliberately loose: it says nothing about whether the code is any good, only
// that something outside it has a reason to mention it.
func TestEveryPackageIsReachedBySomething(t *testing.T) {
	imported, pkgs := importGraph(t)

	if len(pkgs) < 50 {
		t.Fatalf("found %d packages; the walk is wrong and a test that "+
			"inspects nothing passes", len(pkgs))
	}

	var orphans []string
	for p := range pkgs {
		if imported[p] || p == "cmd/quilzo" {
			continue
		}
		if reason, ok := notImported[p]; ok {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is excused with an empty reason", p)
			}
			continue
		}
		orphans = append(orphans, p)
	}
	sort.Strings(orphans)
	for _, p := range orphans {
		t.Errorf("%s is imported by nothing outside itself, so it is "+
			"maintained and tested and answers nobody. Wire it up, delete it, "+
			"or add a row to notImported saying which of those it is waiting "+
			"for", p)
	}
}

// notImported is for packages that exist without being imported, with a
// written reason each.
//
// A registry rather than a rule, the same shape as cmd/quilzo's coverage
// table: a pattern that excuses one package excuses the next one of that
// shape, including the one that was an oversight.
var notImported = map[string]string{}

// importGraph returns which packages are imported from outside themselves, and
// every package in the tree.
func importGraph(t *testing.T) (imported map[string]bool, pkgs map[string]bool) {
	t.Helper()
	const mod = "github.com/quilzo/quilzo/"
	imported = map[string]bool{}
	pkgs = map[string]bool{}

	for _, root := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			dir := filepath.ToSlash(filepath.Dir(path))
			pkgs[dir] = true
			// Test files are excluded on purpose. A package imported only by
			// its own tests, or only by another package's tests, is exactly
			// the state this test exists to find: covered and unreachable.
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), path, nil,
				parser.ImportsOnly)
			if perr != nil {
				return nil
			}
			for _, spec := range f.Imports {
				p := strings.Trim(spec.Path.Value, `"`)
				if !strings.HasPrefix(p, mod) {
					continue
				}
				target := strings.TrimPrefix(p, mod)
				if target != dir {
					imported[target] = true
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return imported, pkgs
}
