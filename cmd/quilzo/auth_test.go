// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// A job is granted, works on its area's commands only, and is revoked whole.
func TestAJobIsGrantedFromTheCommandLineAndKeepsToItsArea(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "boss")
	if err := cmdAuth(root, []string{"grant", "sam", "analyst", "--for", "30d"}); err != nil {
		t.Fatal(err)
	}
	p, _ := loadPolicy(root)
	if !p.Evaluate("sam", auth.ActGrant, auth.AreaSecurity).Allowed ||
		p.Evaluate("sam", auth.ActView, "/").Allowed {
		t.Fatalf("the analyst job did not grant its area alone: %+v", p.Bindings)
	}
	for _, b := range p.Bindings {
		if b.Principal == "sam" && (b.Expires == 0 || b.Expires > time.Now().Add(31*24*time.Hour).Unix()) {
			t.Errorf("--for 30d gave %+v", b)
		}
	}
	if err := cmdAuth(root, []string{"grant", "sam", "analyst", "--on", "/blog"}); err == nil {
		t.Error("a job was granted on a part of the site")
	}

	// As sam: the area's commands run, and nothing outside them.
	issueFor := func(who string) string {
		ts, _ := loadTokens(root)
		secret, _, err := ts.Issue("t", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		_ = saveJSON(tokensPath(root), ts)
		return secret
	}
	t.Setenv("QUILZO_TOKEN", issueFor("sam"))
	if err := authoriseCommand(root, "shield", []string{"status"}); err != nil {
		t.Errorf("an analyst cannot read the shield: %v", err)
	}
	for _, c := range [][]string{{"publish"}, {"auth", "grant", "x", "admin"}, {"add", "x=y.json"}, {"inbox"}} {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("an analyst may run %v", c)
		}
	}

	t.Setenv("QUILZO_TOKEN", "")
	if err := cmdAuth(root, []string{"revoke", "sam", "analyst"}); err != nil {
		t.Fatal(err)
	}
	p, _ = loadPolicy(root)
	if p.Evaluate("sam", auth.ActView, auth.AreaSecurity).Allowed {
		t.Error("revoking the job left part of it")
	}
}

// The auditor job is only granted with an end, and its holder reads the log
// and the posture from a terminal and runs nothing that changes them.
func TestAnAuditorReadsFromTheCommandLineAndChangesNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "kim", "auditor"}); err == nil {
		t.Fatal("an auditor was granted with no end")
	}
	if err := cmdAuth(root, []string{"grant", "kim", "auditor", "--for", "30d"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "rae", "reader"}); err != nil {
		t.Fatal(err)
	}
	issueFor := func(who string) string {
		ts, _ := loadTokens(root)
		secret, _, err := ts.Issue("t", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		_ = saveJSON(tokensPath(root), ts)
		return secret
	}
	reads := [][]string{{"auditlog", "show"}, {"auditlog", "verify"}, {"posture", "rules"}, {"posture", "frameworks"}, {"compliance", "summary"}}
	t.Setenv("QUILZO_TOKEN", issueFor("kim"))
	for _, c := range reads {
		if err := authoriseCommand(root, c[0], c[1:]); err != nil {
			t.Errorf("an auditor cannot run %v: %v", c, err)
		}
	}
	for _, c := range [][]string{{"auditlog", "anchor"}, {"posture", "suppress", "x"}, {"finding", "list"}, {"publish"}, {"auth", "grant", "x", "reader"}} {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("an auditor may run %v", c)
		}
	}
	// A reader over the site used to run these: the admin would not show
	// them the log, and the terminal did.
	t.Setenv("QUILZO_TOKEN", issueFor("rae"))
	for _, c := range reads {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("a reader over the site may run %v", c)
		}
	}
}

// What a grant lets somebody do is said from the policy as it is written,
// not from the copy read before the change: it said "nothing" for every
// grant, an administrator's included.
func TestAGrantSaysWhatItLetsThemDo(t *testing.T) {
	root := connectStore(t)
	_, read := captureStdout(t)
	err := cmdAuth(root, []string{"grant", "dana", "author", "--on", "/blog"})
	out := read()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "can now: nothing") || !strings.Contains(out, "edit-draft") {
		t.Fatalf("the consequence is not what was granted:\n%s", out)
	}
}

// A fresh install's first credential: the first token, for the
// administrator the policy names alone, is issued without a second
// administrator nobody could be; the next one is not issued without a
// token at all.
func TestTheOnlyAdministratorGetsTheirFirstToken(t *testing.T) {
	root := connectStore(t)
	t.Setenv("QUILZO_TOKEN", "")
	t.Setenv("HOME", t.TempDir())
	if err := cmdAuth(root, []string{"grant", "dana", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := authoriseCommand(root, "token", []string{"issue", "laptop", "--principal", "dana"}); err != nil {
		t.Fatalf("the first token was refused: %v", err)
	}
	if err := tokenIssue(root, []string{"laptop", "--principal", "dana"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	if len(ts.Tokens) != 1 || ts.Tokens[0].Role != auth.RoleAdmin {
		t.Fatalf("no administrator's token was issued: %+v", ts.Tokens)
	}
	if pend, _ := dualStore(root).Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("it waits for a second administrator: %+v", pend)
	}
	if err := authoriseCommand(root, "token", []string{"issue", "again", "--principal", "dana"}); err == nil {
		t.Fatal("a second token was issued with no token presented")
	}
	evs, _ := audit.Read(auditPath(root))
	boot := false
	for _, e := range evs {
		if e.Action == "dual.approved" && e.Detail["bootstrap"] == "true" {
			boot = true
		}
	}
	if !boot {
		t.Error("the record does not say the first token was the bootstrap")
	}
}
