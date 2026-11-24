// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Saying where a page's bytes came from is a write, on the command line as
// on the provenance screen, which asks to edit the page. The table asked
// provenance only to view, set and backfill included, so a token issued
// --read-only, and a reader with their own token, recorded a page as a
// person's work and wrote what readers are told about it. Checking and a
// dry run still read with either; whoever may edit still writes.
func TestOnlyAnEditorRecordsProvenance(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := runCmd(t, root, "init"); err != nil {
		t.Fatal(err)
	}
	// Written by an agent, so a backfill has a record to write: committed
	// as an agent's run commits, since a person's `quilzo add` cannot say a
	// machine wrote it (collab.PersonsMessage).
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{"index": map[string]any{"title": "T", "body": "b"}},
		collab.AgentMessage("drafter", "index", ""), "agent/drafter"); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	for who, role := range map[string]auth.Role{"dana": auth.RoleAdmin, "rita": auth.RoleReader} {
		if err := pol.Grant(auth.Binding{Principal: who, Role: role, Resource: "/"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	toks := &auth.TokenStore{}
	readOnly, _, err := toks.IssueScoped("dana-ro", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin,
		auth.Scope{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := toks.Issue("rita", "rita", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	full, _, err := toks.Issue("dana", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), toks); err != nil {
		t.Fatal(err)
	}
	defer func(old string) { flagToken = old }(flagToken)

	// Each command as main runs it: the table first, then the command.
	run := func(args ...string) error {
		if err := authoriseCommand(root, args[0], args[1:]); err != nil {
			return err
		}
		return cmdProvenance(root, args[1:])
	}
	recorded := func() bool {
		idx, err := loadProvenance(root)
		if err != nil {
			t.Fatal(err)
		}
		_, ok := idx.Get("index")
		return ok
	}
	for name, tok := range map[string]string{"a read-only token": readOnly, "a reader": reader} {
		flagToken = tok
		for _, cmd := range []string{"provenance", "prov"} {
			if err := run(cmd, "set", "index", "--source", "humanEdits", "--author", "dana"); err == nil {
				t.Errorf("%s ran %s set", name, cmd)
			}
			if err := run(cmd, "backfill"); err == nil {
				t.Errorf("%s ran %s backfill", name, cmd)
			}
		}
		if recorded() {
			t.Fatalf("%s recorded where the home page came from", name)
		}
		for _, cmd := range []string{"provenance", "prov"} {
			// The check reports the unmarked page; it is not refused.
			for _, args := range [][]string{{cmd}, {cmd, "check"}, {cmd, "status"}} {
				if err := run(args...); err != nil && !strings.Contains(err.Error(), "without provenance") {
					t.Errorf("%s could not run %v: %v", name, args, err)
				}
			}
			if err := run(cmd, "backfill", "--dry-run"); err != nil {
				t.Errorf("%s could not dry-run a %s backfill: %v", name, cmd, err)
			}
		}
		if recorded() {
			t.Fatalf("a dry run by %s wrote a record", name)
		}
	}

	flagToken = full
	if err := run("provenance", "backfill"); err != nil {
		t.Fatalf("dana's own token could not backfill: %v", err)
	}
	if !recorded() {
		t.Fatal("backfilled, the home page has no record")
	}
	if err := run("provenance", "set", "index", "--source", "humanEdits", "--author", "dana"); err != nil {
		t.Fatalf("dana's own token could not set provenance: %v", err)
	}
}
