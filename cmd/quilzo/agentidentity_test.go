// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
)

// identityStore is a store where dana and sam administer and tidy is
// declared by dana.
func identityStore(t *testing.T) (root string, pol *auth.Policy) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root = demoStore(t)
	pol = &auth.Policy{}
	for _, who := range []string{"dana", "sam"} {
		if err := pol.Grant(auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: "/"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	if err := declareAgent(root, asker("tidy"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	return root, pol
}

func runTidy(root string) (agentOutcome, error) {
	return executeAgentFrom(context.Background(), root, "tidy", "", false, asAdmin("dana"), nil)
}

func TestWhoeverDeclaresAnAgentAnswersForIt(t *testing.T) {
	root, _ := identityStore(t)
	set, _ := loadAgents(root)
	id := set.identityOf("tidy")
	if id == nil || id.Sponsor != "dana" || id.Expires.Before(time.Now().Add(80*24*time.Hour)) {
		t.Fatalf("%+v", id)
	}
	if _, err := runTidy(root); err != nil {
		t.Fatalf("a sponsored agent did not run: %v", err)
	}
	// Withdrawn, its identity goes with it.
	if err := withdrawAgent(root, "tidy", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	set, _ = loadAgents(root)
	if set.identityOf("tidy") != nil {
		t.Fatal("a withdrawn agent kept its identity")
	}
}

func TestAnExpiredAgentDoesNotRun(t *testing.T) {
	root, _ := identityStore(t)
	set, _ := loadAgents(root)
	id := set.Identities["tidy"]
	id.Expires = time.Now().Add(-time.Minute)
	set.Identities["tidy"] = id
	saveJSON(agentsPath(root), set)
	if _, err := runTidy(root); err == nil || !strings.Contains(err.Error(), "renew") {
		t.Fatalf("an expired agent ran: %v", err)
	}
	// An evaluation still runs it: it changes nothing.
	if _, err := executeAgentFrom(context.Background(), root, "tidy", "", false, asAdmin("dana"),
		&agentResume{Eval: &evalMode{}}); err != nil && strings.Contains(err.Error(), "renew") {
		t.Fatalf("an evaluation was refused: %v", err)
	}
}

func TestAnAgentStopsWhenItsSponsorCannotActHere(t *testing.T) {
	root, pol := identityStore(t)
	pol.Revoke("dana", auth.RoleAdmin, "/")
	saveJSON(policyPath(root), pol)
	if _, err := runTidy(root); err == nil || !strings.Contains(err.Error(), "dana") {
		t.Fatalf("an orphaned agent ran: %v", err)
	}
	// A suspension by the identity provider is a deny, and counts the same.
	pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"})
	pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleReader, Resource: "/", Deny: true})
	saveJSON(policyPath(root), pol)
	if sponsorActive(root, "dana") {
		t.Fatal("a suspended sponsor counted as active")
	}
}

func TestAnAgentsOwnGrantBoundsEveryRun(t *testing.T) {
	root, pol := identityStore(t)
	pol.Grant(auth.Binding{Principal: agent.Principal("tidy"), Role: auth.RoleReader, Resource: "/"})
	saveJSON(policyPath(root), pol)
	out, err := runTidy(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range out.Manifest.Capabilities {
		if c == "write_page" {
			t.Fatal("an agent granted reader kept write_page under an administrator")
		}
	}
	// Refused everywhere: it does not run at all.
	pol.Grant(auth.Binding{Principal: agent.Principal("tidy"), Role: auth.RoleReader, Resource: "/", Deny: true})
	saveJSON(policyPath(root), pol)
	if _, err := runTidy(root); err == nil || !strings.Contains(err.Error(), "refuses") {
		t.Fatalf("a denied agent ran: %v", err)
	}
}

func TestAnAgentGrantedOneSubtreeReadsOnlyThere(t *testing.T) {
	root, pol := identityStore(t)
	pol.Grant(auth.Binding{Principal: agent.Principal("tidy"), Role: auth.RoleAuthor, Resource: "/docs"})
	saveJSON(policyPath(root), pol)
	c, err := agentGrants(root, "tidy")
	if err != nil || c == nil || c.Role != auth.RoleAuthor || c.Scope != "/docs" {
		t.Fatalf("%+v %v", c, err)
	}
	if b := boundOf(asker("tidy"), c); b.Retrieval.Path != "/docs" {
		t.Fatalf("the subtree did not bound what it reads: %q", b.Retrieval.Path)
	}
	pol.Grant(auth.Binding{Principal: agent.Principal("tidy"), Role: auth.RoleAuthor, Resource: "/blog"})
	saveJSON(policyPath(root), pol)
	if _, err := agentGrants(root, "tidy"); err == nil {
		t.Fatal("two subtrees were treated as one")
	}
	if c, err := agentGrants(root, "nobody"); c != nil || err != nil {
		t.Fatal("an agent the policy does not name was bounded")
	}
}

func TestRenewingAndNamingASponsor(t *testing.T) {
	root, pol := identityStore(t)
	pol.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"})
	saveJSON(policyPath(root), pol)
	toks := &auth.TokenStore{}
	issue := func(who string, role auth.Role) string {
		s, _, err := toks.Issue(who, who, role, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	sam, rae := issue("sam", auth.RoleAdmin), issue("rae", auth.RoleAuthor)
	saveJSON(tokensPath(root), toks)
	defer func(old string) { flagToken = old }(flagToken)

	flagToken = rae
	if err := agentIdentityCmd(root, "renew", []string{"tidy"}); err == nil {
		t.Fatal("somebody who is neither sponsor nor administrator renewed it")
	}
	if err := agentIdentityCmd(root, "sponsor", []string{"tidy", "rae"}); err == nil {
		t.Fatal("an author named themselves sponsor")
	}
	flagToken = sam
	if err := agentIdentityCmd(root, "sponsor", []string{"tidy", "nobody"}); err == nil {
		t.Fatal("somebody with no access was made sponsor")
	}
	if err := agentIdentityCmd(root, "sponsor", []string{"tidy", "rae", "--for", "720h"}); err != nil {
		t.Fatal(err)
	}
	set, _ := loadAgents(root)
	if id := set.Identities["tidy"]; id.Sponsor != "rae" || id.CreatedBy != "dana" || id.RenewedBy != "sam" {
		t.Fatalf("%+v", id)
	}
	// Now rae answers for it, rae may renew it.
	flagToken = rae
	if err := agentIdentityCmd(root, "renew", []string{"tidy"}); err != nil {
		t.Fatalf("its sponsor could not renew it: %v", err)
	}
	if err := agentIdentityCmd(root, "renew", []string{"tidy", "--for", "9000h"}); err == nil {
		t.Fatal("renewed beyond a year")
	}
}
