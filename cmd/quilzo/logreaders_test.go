// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// The people whose job is the audit log may ask from a terminal how it is
// protected and see its proofs, as the admin shows them on /logs and on
// Integrity: the analyst, compliance and the auditor run `logd status`,
// `anchor status` and `anchor export` (and bare `anchor`), and those with
// the compliance area the timestamps and stamps. Everybody who ran them
// before still does, and none of them may send a digest out.
//
// The rows asked for view on "/", which these jobs never hold: they are
// granted areas and nothing else, so the auditor was told "no binding gives
// kim any role on /" for the commands that read what the job exists to
// read, while any reader of the site's content ran them.
func TestTheLogsReadersMayAskHowItIsProtected(t *testing.T) {
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

	// The log's protection and its anchors, read where the log is read.
	logReads := [][]string{{"logd", "status"}, {"anchor", "status"}, {"anchor", "export"}, {"anchor"}}
	// The publication's timestamps, read where Integrity shows them.
	stampReads := [][]string{{"timestamp", "list"}, {"timestamp", "export"}, {"timestamp"},
		{"stamp", "list"}, {"stamp", "export"}, {"stamp"}}
	// Sending a digest out stays an administrator's of the whole site.
	sends := [][]string{{"anchor", "submit"}, {"anchor", "upgrade"}, {"timestamp", "stamp"}, {"stamp", "stamp"}}

	for who, may := range map[string][][]string{
		"sam": logReads,
		"cal": append(append([][]string{}, logReads...), stampReads...),
		"kim": append(append([][]string{}, logReads...), stampReads...),
		"rae": append(append([][]string{}, logReads...), stampReads...),
	} {
		as(who)
		for _, c := range may {
			if err := authoriseCommand(root, c[0], c[1:]); err != nil {
				t.Errorf("%s may not run %v: %v", who, c, err)
			}
		}
		for _, c := range sends {
			if err := authoriseCommand(root, c[0], c[1:]); err == nil {
				t.Errorf("%s may run %v", who, c)
			}
		}
	}
	// The analyst's job is the shield and the log, not the compliance area,
	// and Integrity is not shown to it either.
	as("sam")
	for _, c := range stampReads {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("the analyst may run %v", c)
		}
	}
}
