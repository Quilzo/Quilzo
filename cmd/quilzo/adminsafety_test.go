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

func TestAnyNameTypedAfterByIsCreditedNotRecorded(t *testing.T) {
	root := onlyOwner(t)
	granted := auditFor(t, root, "auth.granted")
	if len(granted) == 0 {
		t.Fatal("no grant on the record to compare with")
	}
	owner := granted[0].Principal

	if err := postureSuppress(root, []string{"mfa.no-second-factor", "--reason", "accepted by the board",
		"--by", "Dana (CISO)", "--days", "90"}); err != nil {
		t.Fatal(err)
	}
	got := auditFor(t, root, "posture.suppress")
	if len(got) != 1 || got[0].Principal != owner || !got[0].Verified {
		t.Errorf("the suppression is recorded as %+v, not as the administrator who made it", got)
	}
	f := &suppressionFile{}
	_ = loadJSON(suppressPath(root), f)
	if len(f.Suppressions) != 1 || !strings.HasPrefix(f.Suppressions[0].By, "owner") ||
		!strings.Contains(f.Suppressions[0].By, "Dana (CISO)") {
		t.Errorf("the suppression is by %+v", f.Suppressions)
	}

	if err := cmdAuth(root, []string{"grant", "mallory", "reader", "--by", "Dana (CISO)"}); err != nil {
		t.Fatal(err)
	}
	pol, _ := loadPolicy(root)
	for _, b := range pol.Snapshot() {
		if b.Principal == "mallory" && (b.GrantedBy != "owner" || !strings.Contains(b.Note, "Dana (CISO)")) {
			t.Errorf("mallory's grant is by %q, noted %q", b.GrantedBy, b.Note)
		}
	}

	pages, _ := draftPageIDs(root)
	if len(pages) == 0 {
		// The store has no draft pages; a demonstration gives it some.
		if err := cmdDemo(root, []string{"-publish=false", "-templates", t.TempDir() + "/tpl"}); err != nil {
			t.Fatal(err)
		}
		pages, _ = draftPageIDs(root)
	}
	ts, _ := loadTokens(root)
	dana, _, err := ts.Issue("dana", "dana", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_ = saveJSON(tokensPath(root), ts)
	t.Setenv("QUILZO_TOKEN", dana)
	if err := checkedSet(root, []string{pages[0], "--by", "Priya (Compliance)", "--note", "legal reviewed"}); err != nil {
		t.Fatal(err)
	}
	st, _ := openChecked(root)
	r, err := st.Get(pages[0])
	if err != nil || r.By != "dana" || !strings.Contains(r.Note, "Priya (Compliance)") {
		t.Errorf("the check is recorded as %+v %v", r, err)
	}
}
