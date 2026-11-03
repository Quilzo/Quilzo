// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// The policy a server was started with follows the file, as its tokens do: a
// grant and a revocation made on the command line both apply at the next
// request, and a server that cannot read the file keeps what it knew.
//
// The content API in `quilzo serve` and `quilzo site --api` decided against
// the policy loaded at startup, so a reader granted while it ran was refused
// there and a revoked one kept reading pages there until a restart.
func TestThePolicyAServerHoldsFollowsTheFile(t *testing.T) {
	root := t.TempDir()
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	reload := policyReloader(root, pol)
	reload()
	if pol.Evaluate("late", auth.ActView, "/").Allowed {
		t.Fatal("somebody granted nothing may read")
	}

	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "late", Role: auth.RoleReader, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	reload()
	if !pol.Evaluate("late", auth.ActView, "/").Allowed {
		t.Fatal("a reader granted while the server ran is not seen")
	}

	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("late", auth.RoleReader, "/")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reload()
	if pol.Evaluate("late", auth.ActView, "/").Allowed {
		t.Fatal("a reader revoked while the server ran may still read")
	}
}

// A token's use at a server that does not save the store is written down, at
// most once an hour, and nothing else about the token is touched.
func TestATokensUseIsWrittenDown(t *testing.T) {
	root := t.TempDir()
	ts := &auth.TokenStore{}
	_, tok, err := ts.Issue("integration", "ada", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	record := useRecorder(root)
	record(tok)
	stored, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	first := stored.Snapshot()[0]
	if first.LastUsed == 0 {
		t.Fatal("a use was not written down: `token list` says never")
	}
	if first.Name != tok.Name || first.Hash != tok.Hash || first.Role != tok.Role {
		t.Fatalf("writing the use changed the token: %+v", first)
	}

	// Revoked elsewhere since: a use written down does not bring it back.
	if _, err := stored.Revoke(tok.ID); err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, stored); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(tokensPath(root))
	if err != nil {
		t.Fatal(err)
	}
	record(tok)
	if after, err := os.Stat(tokensPath(root)); err != nil || !after.ModTime().Equal(fi.ModTime()) || after.Size() != fi.Size() {
		t.Error("a second use within the hour rewrote the file every other process reloads on change")
	}
	again, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Snapshot()[0].Revoked {
		t.Error("the revocation was undone")
	}
}
