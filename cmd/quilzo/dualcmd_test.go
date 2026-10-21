// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/shield"
)

func waiting(t *testing.T, root string) dual.Request {
	t.Helper()
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil || len(pend) != 1 {
		t.Fatalf("waiting: %+v %v", pend, err)
	}
	return pend[0]
}

// Making somebody an administrator, weakening a setting and moving the
// audit log each wait for a second administrator, who makes the change on
// approving it; nobody approves their own.
func TestAPrivilegedChangeWaitsForASecondAdministrator(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, boss, lee := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdAuth(root, []string{"grant", "pat", "admin"}); err != nil {
		t.Fatal(err)
	}
	isAdmin := func() bool {
		pol, _ := loadPolicy(root)
		return pol.Evaluate("pat", auth.ActGrant, "/").Allowed
	}
	if isAdmin() {
		t.Fatal("pat became an administrator on one administrator's word")
	}
	r := waiting(t, root)
	if err := cmdPending(root, []string{"approve", r.ID}); err == nil {
		t.Fatal("dana approved her own request")
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Fatal(err)
	}
	if !isAdmin() {
		t.Fatal("approved, and pat is not an administrator")
	}

	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdConfig(root, []string{"set", "publish.require_a11y", "false", "--accept-risk", "a migration"}); err != nil {
		t.Fatal(err)
	}
	if !mustConfig(root).Bool("publish.require_a11y") {
		t.Fatal("a weaker setting took effect on one administrator's word")
	}
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", waiting(t, root).ID}); err != nil {
		t.Fatal(err)
	}
	if mustConfig(root).Bool("publish.require_a11y") {
		t.Fatal("approved, and the setting did not change")
	}

	// Raising how many approve a change is one administrator's; lowering
	// it, or putting it back to a lower default, is two.
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdConfig(root, []string{"set", "review.required_approvals", "2"}); err != nil {
		t.Fatal(err)
	}
	if mustConfig(root).Int("review.required_approvals") != 2 {
		t.Fatal("raising the approvals waited")
	}
	for _, args := range [][]string{{"set", "review.required_approvals", "1"}, {"unset", "review.required_approvals"}} {
		if err := cmdConfig(root, args); err != nil {
			t.Fatal(err)
		}
		if mustConfig(root).Int("review.required_approvals") != 2 {
			t.Fatalf("%v took effect on one administrator's word", args)
		}
		t.Setenv("QUILZO_TOKEN", lee)
		_ = cmdPending(root, []string{"decline", waiting(t, root).ID})
		t.Setenv("QUILZO_TOKEN", boss)
	}

	dir := t.TempDir()
	if err := cmdAuditDir(root, []string{dir}); err != nil {
		t.Fatal(err)
	}
	if auditDir(root) == dir {
		t.Fatal("the audit log moved on one administrator's word")
	}
	t.Setenv("QUILZO_TOKEN", lee)
	r = waiting(t, root)
	if err := cmdPending(root, []string{"decline", r.ID}); err != nil {
		t.Fatal(err)
	}
	if auditDir(root) == dir {
		t.Fatal("a declined move happened")
	}
	body, _ := os.ReadFile(auditPath(root))
	for _, want := range []string{"dual.proposed", "dual.approved", "dual.declined"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("%s was not recorded", want)
		}
	}
}

// An administrator's token is issued to whoever asked, once another
// administrator agrees, and to nobody else.
func TestAnAdministratorsTokenWaitsAndGoesToWhoeverAsked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, boss, lee := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", boss)
	count := func() int { ts, _ := loadTokens(root); return len(ts.Tokens) }
	before := count()
	if err := cmdToken(root, []string{"issue", "deploy", "--principal", "dana", "--role", "admin"}); err != nil {
		t.Fatal(err)
	}
	if count() != before {
		t.Fatal("an administrator's token was issued on one administrator's word")
	}
	r := waiting(t, root)
	t.Setenv("QUILZO_TOKEN", lee)
	if err := cmdPending(root, []string{"approve", r.ID}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Fatal("the approver received the token")
	}
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdPending(root, []string{"redeem", r.ID}); err != nil {
		t.Fatal(err)
	}
	if count() != before+1 {
		t.Fatal("redeemed, and no token was issued")
	}
	if err := cmdPending(root, []string{"redeem", r.ID}); err == nil {
		t.Error("a token was redeemed twice")
	}
}

// A store with one administrator is not left unable to change anything:
// their change is made as they make it, and the record says alone.
func TestTheOnlyAdministratorChangesAlone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	boss, _, _ := ts.Issue("b", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	_ = saveJSON(tokensPath(root), ts)
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdAuth(root, []string{"grant", "pat", "admin"}); err != nil {
		t.Fatal(err)
	}
	pol, _ := loadPolicy(root)
	if !pol.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("the only administrator could not make another")
	}
	body, _ := os.ReadFile(auditPath(root))
	if !strings.Contains(string(body), `"alone":"true"`) {
		t.Error("the record does not say it was approved alone")
	}
}

// A shield playbook change waits for a second administrator, and the only
// administrator's is approved as they make it.
func TestAPlaybookChangeTakesTwoOrSaysAlone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, dana, _ := twoAdmins(t)
	t.Setenv("QUILZO_TOKEN", dana)
	if err := cmdShield(root, []string{"playbook", "mode", "admin-hunting", "watch", "--why", "a test"}); err != nil {
		t.Fatal(err)
	}
	bk, _ := shield.LoadBook(root)
	if len(bk.Pending) != 1 || len(bk.Playbooks) != 0 {
		t.Fatalf("with two administrators: %d waiting, %d changed", len(bk.Pending), len(bk.Playbooks))
	}

	solo := demoStore(t)
	if err := cmdAuth(solo, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(solo)
	boss, _, _ := ts.Issue("b", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	_ = saveJSON(tokensPath(solo), ts)
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdShield(solo, []string{"playbook", "mode", "admin-hunting", "watch", "--why", "a test"}); err != nil {
		t.Fatal(err)
	}
	bk, _ = shield.LoadBook(solo)
	if len(bk.Pending) != 0 || len(bk.Decided) != 1 || !bk.Decided[0].Alone {
		t.Fatalf("alone: %d waiting, %+v", len(bk.Pending), bk.Decided)
	}
}

// seedPolicy grants straight into the policy, as a test's setup does: a
// second administrator granted by a command waits for a third.
func seedPolicy(t *testing.T, root string, grants ...[2]string) {
	t.Helper()
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		for _, g := range grants {
			if err := p.Grant(auth.Binding{Principal: g[0], Role: auth.Role(g[1]), Resource: "/"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// asOnly acts as who, with a token of their own, for a test whose store
// they alone administer.
func asOnly(t *testing.T, root, who string) {
	t.Helper()
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue(who, who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
}
