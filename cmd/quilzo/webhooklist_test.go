// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// The webhook endpoints are listed to whoever the Integrations screen shows
// them to: an administrator of the whole site.
//
// `webhook list` asked for view, so any reader of the content was listed
// every endpoint this store posts to, each by its whole address, which is
// often the receiver's credential itself (a Slack or Teams incoming hook is
// nothing else), and the first characters of its signing key. The admin
// gates the same list on grant, as a map of where this system sends data.
func TestOnlyAnAdministratorListsTheWebhooks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "boss")
	if err := cmdAuth(root, []string{"grant", "rae", "reader"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "pat", "publisher"}); err != nil {
		t.Fatal(err)
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
	lists := [][]string{{"webhook", "list"}, {"webhooks", "list"}, {"webhook"}, {"webhooks"}}
	for _, who := range []string{"rae", "pat"} {
		as(who)
		for _, c := range lists {
			if err := authoriseCommand(root, c[0], c[1:]); err == nil {
				t.Errorf("%s, who may not open Integrations, may run %v", who, c)
			}
		}
	}
	as("boss")
	for _, c := range lists {
		if err := authoriseCommand(root, c[0], c[1:]); err != nil {
			t.Errorf("an administrator may not run %v: %v", c, err)
		}
	}
}
