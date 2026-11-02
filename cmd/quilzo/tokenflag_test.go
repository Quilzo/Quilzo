// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A --token on the command line is who the command acts as, for every
// command, and not only for the check in front of it: with sam's token in
// QUILZO_TOKEN and dana's given as --token, the command is dana's.
func TestTheTokenGivenIsWhoTheCommandIs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"sam", "admin"})
	ts, _ := loadTokens(root)
	danas, _, err := ts.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	sams, _, err := ts.Issue("sam", "sam", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", sams)
	old := flagToken
	t.Cleanup(func() { flagToken = old })

	flagToken = ""
	if c := resolveCaller(root, ""); c.Name != "sam" || !c.Verified {
		t.Fatalf("with no --token: %+v", c)
	}
	flagToken = danas
	if c := resolveCaller(root, ""); c.Name != "dana" || !c.Verified {
		t.Fatalf("--token was dana's and the command is %+v", c)
	}
	// A token passed explicitly is still that one.
	if c := resolveCaller(root, sams); c.Name != "sam" {
		t.Fatalf("%+v", c)
	}
}
