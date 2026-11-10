// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/user"
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

// A risk accepted on a store nobody has been granted anything in names the
// operating-system account that accepted it, said to be not verified, as
// nothing checked it.
//
// `quilzo config set mcp.remote true --accept-risk ...` run where $USER,
// $USERNAME and $LOGNAME are empty, as under a service manager or in a
// container, was accepted by "unknown-operator": the posture scan and
// `config show` named nobody, though the program knew whose account it ran
// as. And a name taken from $USER was shown as plainly as one a token
// proved.
func TestAnAcceptanceNamesWhoAcceptedIt(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Username == "" {
		t.Skipf("this system does not say whose account this is: %v", err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	flagToken = ""
	for _, tc := range []struct{ user, want string }{
		{"", me.Username + " (not verified)"},
		{"kit", "kit (not verified)"},
	} {
		for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
			t.Setenv(k, "")
		}
		t.Setenv("USER", tc.user)
		root := t.TempDir()
		if err := cmdInit(root); err != nil {
			t.Fatal(err)
		}
		if err := cmdConfig(root, []string{"set", "mcp.remote", "true", "--accept-risk", "agents reach it"}); err != nil {
			t.Fatal(err)
		}
		w := mustConfig(root).Weakened()
		if len(w) != 1 || w[0].Accepted == nil {
			t.Fatalf("USER=%q: mcp.remote is not reported as accepted: %d weakened", tc.user, len(w))
		}
		if by := w[0].Accepted.By; by != tc.want {
			t.Errorf("USER=%q: accepted by %q, not %q", tc.user, by, tc.want)
		}
		got, err := humanOutput(t, func() error { return cmdConfig(root, []string{"show"}) })
		if err != nil || !strings.Contains(got, "accepted by "+tc.want) {
			t.Errorf("USER=%q: config show does not name %q: %v\n%s", tc.user, tc.want, err, got)
		}
	}
}
