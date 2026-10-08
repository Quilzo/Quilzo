// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rejected token is named by where it came from, and an old token file
// shadowing QUILZO_TOKEN says so: the file is read first on purpose, and
// the refusal is where a person learns it.
func TestARejectedTokenSaysWhereItCameFrom(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".quilzo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".quilzo", "token"),
		[]byte("qz_"+strings.Repeat("a", 52)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "qz_"+strings.Repeat("b", 52))
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	c := resolveCaller(root, "")
	if c.Verified {
		t.Fatal("an unknown token verified")
	}
	if !strings.Contains(c.Why, filepath.Join(home, ".quilzo", "token")) || !strings.Contains(c.Why, "QUILZO_TOKEN is set too") {
		t.Fatalf("the refusal does not say which token was tried: %q", c.Why)
	}
	if c := resolveCaller(root, "qz_"+strings.Repeat("c", 52)); !strings.Contains(c.Why, "from --token") {
		t.Fatalf("an explicit token is not named as one: %q", c.Why)
	}
}
