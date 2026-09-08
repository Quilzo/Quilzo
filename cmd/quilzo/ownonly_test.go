// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --own-only is refused rather than accepted and ignored.
//
// It was offered on the command line and in the admin, both confirmed in
// writing that the restriction had taken effect, and nothing enforced it. A
// principal granted `author --own-only` could edit every page in the store
// while the operator had been told they could not.
//
// Refusing is louder than removing: a script that passes it stops with a
// reason rather than silently granting something wider than it asked for.
func TestOwnOnlyIsRefused(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	err := cmdAuth(root, []string{"grant", "frank", "author", "--own-only"})
	if err == nil {
		t.Fatal("--own-only was accepted, so a grant still looks narrower " +
			"than it is")
	}
	if !strings.Contains(err.Error(), "never enforced") {
		t.Errorf("refused without saying why: %v", err)
	}
	// And the ordinary shapes still work, including the scope that is real.
	if err := cmdAuth(root, []string{"grant", "frank", "author"}); err != nil {
		t.Fatalf("an ordinary grant was refused: %v", err)
	}
	if err := cmdAuth(root, []string{"grant", "gina", "author",
		"--on", "/products"}); err != nil {
		t.Fatalf("a scoped grant was refused: %v", err)
	}
}

// If anything starts setting OwnOnly again, something has to enforce it.
//
// The defect was not that the field existed. It was that two surfaces wrote it
// from user input while no enforcement path read it: auth.EvaluateOwned, the
// only function that resolves an own-only binding, had zero production callers
// and every check called plain Evaluate instead.
//
// So this walks the source for the shape of the bug rather than for the flag,
// which is what makes it survive the feature coming back in a different form.
// Bring OwnOnly back and this test asks, once, for the other half.
func TestNothingSetsOwnOnlyWithoutEnforcingIt(t *testing.T) {
	root := repoRoot(t)
	var writes []string
	enforced := false

	err := filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		src := string(b)
		rel, _ := filepath.Rel(root, path)
		// The declaration and the resolver live in internal/auth; this is
		// about the callers.
		if !strings.HasPrefix(rel, "internal/auth/") {
			if strings.Contains(src, "OwnOnly:") {
				writes = append(writes, rel)
			}
		}
		if strings.Contains(src, "EvaluateOwned(") &&
			!strings.HasPrefix(rel, "internal/auth/") {
			enforced = true
		}
		return nil
	})
	if err != nil {
		t.Skipf("walk: %v", err)
	}
	if len(writes) > 0 && !enforced {
		t.Errorf("these set an own-only binding and nothing calls "+
			"auth.EvaluateOwned, so the restriction is stored, shown, and "+
			"not applied — which is exactly the defect that withdrew the "+
			"flag: %s", strings.Join(writes, ", "))
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Skip("no working directory")
	}
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("could not find the repository root")
	return ""
}
