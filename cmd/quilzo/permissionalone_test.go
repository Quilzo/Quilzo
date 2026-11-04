// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A permission granted alone reaches the commands its own work needs, and
// nothing besides.
//
// It did not. The commands that read what the work is about (the runs
// waiting for a decision, the features there are to install, the agents
// there are to run or change) asked to view, which a permission granted
// alone does not include, so on the reference stack somebody given approve
// was refused `agent approve` ("no binding gives role-approve any role on
// /@agents") and `approvals`, and somebody given install-features could
// install a feature and not list, check or show one, nor see the installs
// waiting on them. The commands check the exact agent or run themselves;
// the table only asked the wrong question.
func TestAPermissionGrantedAloneReachesItsOwnCommands(t *testing.T) {
	isolateToken(t)
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	for _, b := range []auth.Binding{
		{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"},
		{Principal: "ap", Permission: auth.ActApprove, Resource: "/"},
		{Principal: "nl", Permission: auth.ActApprove, Resource: auth.AgentResource("newsletter")},
		{Principal: "inst", Permission: auth.ActInstall, Resource: "/"},
		{Principal: "mg", Permission: auth.ActManageAgents, Resource: "/"},
		{Principal: "rn", Permission: auth.ActRunAgents, Resource: "/"},
	} {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	as := func(who string) {
		ts, _ := loadTokens(root)
		secret, _, err := ts.Issue(who, who, auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveJSON(tokensPath(root), ts); err != nil {
			t.Fatal(err)
		}
		t.Setenv("QUILZO_TOKEN", secret)
	}

	for _, c := range []struct {
		who     string
		allowed [][]string
		refused [][]string
	}{
		{"ap", [][]string{{"agent", "approve", "run-0000", "1"}, {"agent", "decline", "run-0000", "1"},
			{"agent", "answer", "run-0000", "1"}, {"approvals"}},
			[][]string{{"publish"}, {"feature", "list"}, {"agent", "resume", "run-0000"}, {"log"}}},
		{"nl", [][]string{{"agent", "approve", "run-0000", "1"}, {"approvals"}},
			[][]string{{"agent", "resume", "run-0000"}, {"diff"}}},
		// approvals lists the features waiting to be installed to whoever
		// may install them.
		{"inst", [][]string{{"feature", "list"}, {"feature", "check", "x.json"}, {"feature", "show", "x"},
			{"approvals"}},
			[][]string{{"agent", "approve", "run-0000", "1"}, {"agent", "list"}, {"export"}}},
		{"mg", [][]string{{"agent", "list"}, {"agent", "show", "tidy"}, {"agent", "could", "tidy", "publish"},
			{"agent", "backends"}},
			[][]string{{"approvals"}, {"feature", "list"}}},
		{"rn", [][]string{{"agent", "resume", "run-0000"}, {"agent", "list"}, {"agent", "could", "tidy", "publish"}},
			[][]string{{"agent", "approve", "run-0000", "1"}, {"feature", "list"}}},
	} {
		as(c.who)
		for _, a := range c.allowed {
			if err := authoriseCommand(root, a[0], a[1:]); err != nil {
				t.Errorf("%s, granted only that, was refused %v: %v", c.who, a, err)
			}
		}
		for _, a := range c.refused {
			if err := authoriseCommand(root, a[0], a[1:]); err == nil {
				t.Errorf("%s may run %v, which its permission does not reach", c.who, a)
			}
		}
	}
}

// Approve granted on part of the site alone reaches the commands that
// decide what a run waits to change there.
//
// A run waiting to change a page is decided by whoever holds approve on that
// page (mayApprove), and `approvals` listed it to them. But the table asked
// about the agents, and took approve only on them or under them, so somebody
// given approve on /blog was refused `agent approve` ("no binding gives bl
// any role on /@agents") for the run `approvals` had just shown them. They
// are still refused what approve does not reach.
func TestApproveOnAPartOfTheSiteDecidesItsRuns(t *testing.T) {
	isolateToken(t)
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	for _, b := range []auth.Binding{
		{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"},
		{Principal: "bl", Permission: auth.ActApprove, Resource: "/blog"},
	} {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("bl", "bl", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
	for _, a := range [][]string{{"approvals"}, {"agent", "approve", "run-0000", "1"},
		{"agent", "decline", "run-0000", "1"}, {"agent", "answer", "run-0000", "1", "a=b"}} {
		if err := authoriseCommand(root, a[0], a[1:]); err != nil {
			t.Errorf("approve on /blog alone was refused %v: %v", a, err)
		}
	}
	for _, a := range [][]string{{"agent", "resume", "run-0000"}, {"agent", "list"}, {"publish"}, {"diff"}} {
		if err := authoriseCommand(root, a[0], a[1:]); err == nil {
			t.Errorf("approve on /blog alone may run %v", a)
		}
	}
}
