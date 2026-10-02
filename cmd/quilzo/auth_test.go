// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A job is granted, works on its area's commands only, and is revoked whole.
func TestAJobIsGrantedFromTheCommandLineAndKeepsToItsArea(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
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
	if err := authoriseCommand(root, "finding", []string{"list"}); err != nil {
		t.Errorf("an analyst cannot list findings: %v", err)
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
