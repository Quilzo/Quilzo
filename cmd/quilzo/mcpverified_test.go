// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agentwatch"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/store"
)

// mcpWrites makes every write over the machine interface that records an
// act of its own, as caller, and answers the records they left. A store
// served to another machine has an access policy, which a caller nobody
// proved may not write to at all, so only that store is given one.
func mcpWrites(t *testing.T, caller *Caller) []audit.Event {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := storeFolder(t)
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if caller.Remote {
		seedPolicy(t, root, [2]string{"dana", "admin"})
	}
	if _, err := putCheckedRecords(root, "samples", []map[string]any{{"name": "first"}}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, caller, bundleTemplates(t))
	for _, c := range []struct {
		tool, op string
		args     map[string]any
	}{
		{"quilzo_write", "write_page", map[string]any{"page": "mcp-audit-test",
			"fields": map[string]any{"title": "Audit test", "body": "Written over the interface."}}},
		{"quilzo_write", "write_record", map[string]any{"collection": "samples", "fields": map[string]any{"name": "second"}}},
		{"quilzo_write", "declare_assistant", map[string]any{"name": "help", "title": "Help"}},
	} {
		if _, rerr := callTool(t, srv, c.tool, c.op, c.args); rerr != nil {
			t.Fatalf("%s: %s", c.op, rerr.Message)
		}
	}
	out := ownRecords(t, root, "mcp.write_page", "mcp.write_record", "assistant.declare")

	// A publish of a draft a person wrote, in a store of its own: a draft a
	// model wrote waits for a person's approval, as it should.
	root, tpl, s := approvalDemo(t)
	if caller.Remote {
		seedPolicy(t, root, [2]string{"dana", "admin"})
	}
	if _, rerr := callTool(t, buildMCP(root, s, caller, tpl), "quilzo_publish", "publish", map[string]any{}); rerr != nil {
		t.Fatalf("publish: %s", rerr.Message)
	}
	return append(out, ownRecords(t, root, "mcp.publish")...)
}

// ownRecords are the log's records of these acts, one of each.
func ownRecords(t *testing.T, root string, actions ...string) []audit.Event {
	t.Helper()
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range events {
		if slices.Contains(actions, e.Action) {
			out = append(out, e)
		}
	}
	if len(out) != len(actions) {
		t.Fatalf("%v left %d records", actions, len(out))
	}
	return out
}

// A write over the machine interface by a caller a token proved is recorded
// as verified, as the interface's own record of the call is.
//
// write_page, write_record, publish and declare_assistant recorded
// Verified false whoever called, so every write an app made with a token
// was in the log twice, once verified (mcp.call) and once not, and the
// agent watch counted the second as an act with nobody verified behind it.
// A caller nobody proved, as over standard input, is still recorded as not
// verified.
func TestAWriteOverTheInterfaceIsVerifiedWhenItsCallerWas(t *testing.T) {
	now := time.Now()
	tok := auth.Token{Principal: "dana", Role: auth.RoleAdmin, Resource: "/",
		CreatedAt: now.Unix(), ExpiresAt: now.Add(30 * time.Minute).Unix()}
	remote := mcpWrites(t, remoteCaller(tok))
	for _, e := range remote {
		if !e.Verified {
			t.Errorf("%s by a token's caller was recorded as not verified", e.Action)
		}
	}
	for _, r := range agentwatch.Look(remote, now) {
		if n := r.Counts[agentwatch.Unattributed]; n > 0 {
			t.Errorf("the agent watch counted %d unattributed act(s) for %s", n, r.Principal)
		}
	}

	local := mcpWrites(t, &Caller{Name: "dana", Role: auth.RoleAdmin, Kind: audit.KindHuman})
	for _, e := range local {
		if e.Verified {
			t.Errorf("%s by a caller nobody proved was recorded as verified", e.Action)
		}
	}
}
