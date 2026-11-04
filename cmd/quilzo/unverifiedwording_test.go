// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// A command run with no token on a store with access control is refused,
// and the refusal names the command. It named the action instead: oidc
// status, saml list, scim status and auth roles each said "grant needs a
// verified identity", though none of them grants anything, and saml
// presets, a list of identity providers' consoles built into the program,
// needed an administrator's token to print.
func TestARefusalForWantOfATokenNamesTheCommand(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	isolateToken(t)
	t.Setenv("QUILZO_TOKEN", "")

	for _, c := range [][]string{{"oidc", "status"}, {"saml", "list"}, {"scim", "status"}, {"auth", "roles"}} {
		err := authoriseCommand(root, c[0], c[1:])
		if err == nil {
			t.Errorf("%s ran with no token", strings.Join(c, " "))
			continue
		}
		if strings.Contains(err.Error(), "so grant needs") || !strings.Contains(err.Error(), strings.Join(c, " ")) {
			t.Errorf("%s: the refusal does not name the command: %v", strings.Join(c, " "), err)
		}
	}
	if err := authoriseCommand(root, "saml", []string{"presets"}); err != nil {
		t.Errorf("saml presets, a list built into the program, was refused: %v", err)
	}
	// A command that grants is still asked for the authority to.
	if err := authoriseCommand(root, "saml", []string{"add", "kc"}); err == nil {
		t.Error("saml add ran with no token")
	}
}
