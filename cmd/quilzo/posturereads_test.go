// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// The posture and assurance reads on the command line are asked where the
// admin shows them, the compliance area, as `posture` and `compliance` are.
//
// They asked for view on "/". The compliance job and the auditor are granted
// areas and nothing else, so each was refused the code scan, agent activity,
// the frameworks, the assurance report, the engagements and the group's
// controls, which Security shows them; and any reader of the site's content
// read every one of them from a terminal, which the admin, guarding the
// area, shows only an administrator of the whole site. The store's
// integrity and its content policy stay a reader's as well, as verify_store
// says of the first and the live site's headers say the second.
func TestThePostureReadsAreAskedInTheComplianceArea(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "boss")
	for _, g := range [][]string{
		{"grant", "sam", "analyst", "--for", "30d"},
		{"grant", "cal", "compliance", "--for", "30d"},
		{"grant", "kim", "auditor", "--for", "30d"},
		{"grant", "rae", "reader"},
	} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatalf("%v: %v", g, err)
		}
	}
	as := func(who string) {
		ts, _ := loadTokens(root)
		secret, _, err := ts.Issue("t", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		if err := saveJSON(tokensPath(root), ts); err != nil {
			t.Fatal(err)
		}
		t.Setenv("QUILZO_TOKEN", secret)
	}

	// What Security shows the compliance area, and nobody else below an
	// administrator of the whole site.
	guarded := [][]string{{"scan"}, {"scan", "--rules"}, {"agents"},
		{"framework"}, {"framework", "list"}, {"framework", "status", "x"}, {"framework", "adopt", "x"},
		{"framework", "relations"},
		{"assurance"}, {"assurance", "report"}, {"assurance", "show", "x"}, {"assurance", "controls"},
		{"engagement"}, {"engagement", "list"}, {"engagement", "check", "x"},
		{"entity"}, {"entity", "tree"}, {"entity", "report", "x"}}
	// What a reader of the content read before, and still does.
	open := [][]string{{"verify"}, {"csp"}}

	for who, may := range map[string][][]string{
		"boss": append(append([][]string{}, guarded...), open...),
		"cal":  append(append([][]string{}, guarded...), open...),
		"kim":  append(append([][]string{}, guarded...), open...),
		"rae":  open,
	} {
		as(who)
		for _, c := range may {
			if err := authoriseCommand(root, c[0], c[1:]); err != nil {
				t.Errorf("%s may not run %v: %v", who, c, err)
			}
		}
	}
	for who, mayNot := range map[string][][]string{
		"rae": guarded,
		"sam": append(append([][]string{}, guarded...), open...),
	} {
		as(who)
		for _, c := range mayNot {
			if err := authoriseCommand(root, c[0], c[1:]); err == nil {
				t.Errorf("%s may run %v", who, c)
			}
		}
	}
}
