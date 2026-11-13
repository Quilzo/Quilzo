// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/out"
)

func onlyOwner(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	// What the commands say goes nowhere: a token issued here is printed
	// under --json, and a credential is not written to the test's output.
	w.Out = &bytes.Buffer{}
	seedPolicy(t, root, [2]string{"owner", "admin"})
	asOnly(t, root, "owner")
	if err := cmdAuth(root, []string{"grant", "dana", "author"}); err != nil {
		t.Fatal(err)
	}
	return root
}

func administers(t *testing.T, root, who string) bool {
	t.Helper()
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	return pol.Evaluate(who, auth.ActGrant, "/").Allowed
}

func TestTheLastAdministratorIsNeverRevokedOrDeniedFromTheCommandLine(t *testing.T) {
	root := onlyOwner(t)
	if err := cmdAuth(root, []string{"revoke", "owner", "admin"}); err == nil {
		t.Error("the only administrator's admin binding was revoked")
	}
	if !administers(t, root, "owner") {
		t.Fatal("nobody administers the store after a revoke")
	}
	if err := cmdAuth(root, []string{"deny", "owner", "admin"}); err == nil {
		t.Error("the only administrator was denied admin")
	}
	if !administers(t, root, "owner") {
		t.Fatal("nobody administers the store after a deny")
	}

	// With nothing else in the policy, revoking it would have emptied it.
	bare := t.TempDir() + "/st"
	if err := cmdInit(bare); err != nil {
		t.Fatal(err)
	}
	seedPolicy(t, bare, [2]string{"owner", "admin"})
	asOnly(t, bare, "owner")
	if err := cmdAuth(bare, []string{"revoke", "owner", "admin"}); err == nil {
		t.Error("the only binding of the only administrator was revoked")
	}
	if pol, _ := loadPolicy(bare); len(pol.Bindings) == 0 {
		t.Fatal("the policy was emptied, which turns access control off")
	}

	// A second administrator may be removed, and either may then not be.
	seedPolicy(t, root, [2]string{"lee", "admin"})
	if err := cmdAuth(root, []string{"revoke", "lee", "admin"}); err != nil {
		t.Fatalf("one of two administrators could not be removed: %v", err)
	}
}

func TestARecoveryIsNotRefusedOverATokenThatCanNoLongerAdminister(t *testing.T) {
	root := onlyOwner(t)
	// Written by hand, as a store would be left by anything that took the
	// last administrator away before the guard did.
	pol, _ := loadPolicy(root)
	pol.Bindings = []auth.Binding{{Principal: "owner", Role: auth.RoleAuthor, Resource: "/"},
		{Principal: "dana", Role: auth.RoleAuthor, Resource: "/"}}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")
	_, printed := captureStdout(t)
	err := cmdRecover(root, []string{"--principal", "owner", "--reason", "locked out", "--i-have-filesystem-access"})
	_ = printed()
	if err != nil && strings.Contains(err.Error(), "still usable") {
		t.Fatalf("the recovery counted a token that administers nothing: %v", err)
	}
	if !administers(t, root, "owner") {
		t.Fatalf("the recovery did not give the store an administrator back: %v", err)
	}
}

func TestAStoreNobodyHasEnteredGetsTwoFactorsFromInit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(false)
	w.Out = &bytes.Buffer{}

	root := demoStore(t)
	w.Out = &bytes.Buffer{}
	if err := runInit(root, []string{"--admin", "owner"}); err != nil {
		t.Fatal(err)
	}
	if from, ok := mfaFromIfSet(root); !ok || time.Until(from) > time.Minute {
		t.Errorf("a store made by demo gets two factors from %v (%v), not now", from, ok)
	}

	typo := t.TempDir() + "/st"
	if err := runInit(typo, []string{"--admni", "owner"}); err == nil {
		t.Fatal("a mistyped flag was accepted")
	}
	if isStore(typo) {
		t.Error("a mistyped flag made a store before it was refused")
	}
	if err := runInit(typo, []string{"--admin", "owner"}); err != nil {
		t.Fatal(err)
	}
	if from, ok := mfaFromIfSet(typo); !ok || time.Until(from) > time.Minute {
		t.Errorf("after a mistyped init, two factors start at %v (%v), not now", from, ok)
	}

	// A store somebody already signs in to keeps whatever it was given.
	used := onlyOwner(t)
	if err := runInit(used, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := mfaFromIfSet(used); ok {
		t.Error("init wrote a date for a store people already sign in to")
	}
}
