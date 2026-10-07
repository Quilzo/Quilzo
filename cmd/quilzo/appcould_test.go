// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/shield"
)

// Could this app do that? The answer is the interface's own gate, asked
// for the connection: its scopes, the shield, the person's standing and
// access.
func TestCouldAnAppDoItIsAskedOfWhatAdmitsItsCalls(t *testing.T) {
	root, pol := identityStore(t)
	if err := pol.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	const res = "https://admin.example.org/mcp"
	reader := oauthas.Grant{ID: "gr_00000000000000a1", Principal: "dana", Client: "https://app.example.com/meta",
		ClientName: "Notes app", Scopes: []string{"mcp:read"}, Resource: res, Created: now, Expires: now.Add(24 * time.Hour)}
	raes := oauthas.Grant{ID: "gr_00000000000000a2", Principal: "rae", Client: "https://app.example.com/meta",
		ClientName: "Notes app", Scopes: []string{"mcp:publish"}, Resource: res, Created: now, Expires: now.Add(24 * time.Hour)}
	ended := reader
	ended.ID, ended.Ended, ended.EndedWhy = "gr_00000000000000a3", now.Add(-time.Minute), "disconnected by dana"
	writeGrants(t, root, reader, raes, ended)

	ask := func(conn, op, page string) appCouldAnswer {
		t.Helper()
		a, err := appCould(root, conn, op, page, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if a := ask(reader.ID, "list_pages", ""); a.Could || !strings.Contains(a.Why, "interface is off") {
		t.Fatalf("with the interface off: %+v", a)
	}
	if err := cmdConfig(root, []string{"set", "mcp.remote", "true", "--accept-risk", "apps are asked about here"}); err != nil {
		t.Fatal(err)
	}
	if a := ask(reader.ID, "list_pages", ""); !a.Could || a.App != "Notes app" || a.For != "dana" || len(a.Then) == 0 {
		t.Fatalf("a reader's app reading: %+v", a)
	}
	// Given read only, it cannot write, and is told the scope that would.
	if a := ask(reader.ID, "write_page", ""); a.Could || !strings.Contains(a.Why, "reader access") {
		t.Fatalf("a reader's app writing: %+v", a)
	}
	// Given publish by somebody who may only author, it still cannot.
	if a := ask(raes.ID, "publish", ""); a.Could {
		t.Fatalf("an author's app published: %+v", a)
	}
	if a := ask(raes.ID, "write_page", "/blog/x"); !a.Could {
		t.Fatalf("an author's app writing: %+v", a)
	}
	if a := ask(ended.ID, "list_pages", ""); a.Could || !strings.Contains(a.Why, "disconnected by dana") {
		t.Fatalf("an ended connection: %+v", a)
	}
	// Suspended by the shield, nothing.
	if _, _, err := shield.Apply(root, shield.Protection{Kind: shield.Token, Target: reader.ID, Reason: "kept trying",
		By: "dana", Until: time.Now().Add(time.Hour)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if a := ask(reader.ID, "list_pages", ""); a.Could || !strings.Contains(a.Why, "suspended") {
		t.Fatalf("a suspended connection: %+v", a)
	}
	if _, err := appCould(root, raes.ID, "no_such_thing", "", time.Now()); err == nil {
		t.Fatal("an unknown operation was answered")
	}
	if _, err := appCould(root, "gr_00000000000000ff", "list_pages", "", time.Now()); err == nil {
		t.Fatal("an unknown connection was answered")
	}
}
