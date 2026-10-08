// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/shield"
)

// The answer to "could it?" is the one the run enforces, with its reasons.
func TestCouldAnswersAsTheRunEnforces(t *testing.T) {
	root, pol := identityStore(t)
	if err := pol.Grant(auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	set, _ := loadAgents(root)
	m := set.Agents["tidy"]
	m.Tools = []agent.Tool{{Name: "file_issue", Host: "tracker.example", Purpose: "file what it finds"}}
	m.Retrieval = agent.Retrieval{Ref: "draft"}
	if err := declareAgent(root, m, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	ask := func(what, page string, model bool, as *Caller) couldAnswer {
		t.Helper()
		a, err := could(root, "tidy", what, page, model, false, as)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	// Dana may: write_page asks first, and a person decides before it is live.
	a := ask("write_page", "about", false, asAdmin("dana"))
	if !a.Could || !strings.Contains(strings.Join(a.Then, ";"), "approves the exact call") {
		t.Fatalf("dana: %+v", a)
	}
	// Rae is a reader: the run she starts loses write_page, and says why.
	rae, err := callerFor(root, "rae")
	if err != nil {
		t.Fatal(err)
	}
	a = ask("write_page", "about", false, rae)
	if a.Could || len(a.Bounded) == 0 || a.Bounded[0].By != "caller" || !strings.Contains(strings.Join(a.Bounded[0].Lost, ","), "write_page") {
		t.Fatalf("rae: %+v", a)
	}
	// Something it does not hold at all.
	if a := ask("publish", "", false, asAdmin("dana")); a.Could || a.Why == "" {
		t.Fatalf("publish: %+v", a)
	}
	// A model with no evaluation proposes only.
	if a := ask("write_page", "", true, asAdmin("dana")); a.Could {
		t.Fatalf("an unevaluated model may write: %+v", a)
	}
	// No integration offers the tool: no, and why.
	if a := ask("tool:file_issue", "", false, asAdmin("dana")); a.Could || !strings.Contains(a.Why, "integration") {
		t.Fatalf("an uninstalled tool: %+v", a)
	}
	// Installed and unpinned: yes, with the breaker and the pin said in advance.
	inst := agent.Integrations{Declared: []agent.Integration{{Name: "tracker", Kind: agent.IntegrationMCP, Enabled: true,
		Purpose: "file issues", Endpoint: "tracker.example", Uses: []string{"file_issue"}}}}
	if err := saveJSON(integrationsPath(root), inst); err != nil {
		t.Fatal(err)
	}
	a = ask("tool:file_issue", "", false, asAdmin("dana"))
	then := strings.Join(a.Then, ";")
	if !a.Could || !strings.Contains(then, "exfiltration breaker") || !strings.Contains(then, "nobody pinned") {
		t.Fatalf("tool: %+v", a)
	}
	if a := ask("host:evil.example", "", false, asAdmin("dana")); a.Could {
		t.Fatalf("an undeclared host: %+v", a)
	}
	// Paused by the shield, nothing.
	if _, _, err := shield.Apply(root, shield.Protection{Kind: shield.Agent, Target: "tidy", Reason: "steered",
		By: "dana", Until: time.Now().Add(time.Hour)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if a := ask("list_pages", "", false, asAdmin("dana")); a.Could || !strings.Contains(a.Why, "paused") {
		t.Fatalf("paused: %+v", a)
	}
}

// A write is asked of the draft, where a run writes, whatever the agent reads:
// an agent reading the live site may still draft the page its runs draft.
func TestCouldAsksAWriteOfTheDraft(t *testing.T) {
	root, _ := identityStore(t)
	set, _ := loadAgents(root)
	m := set.Agents["tidy"]
	m.Retrieval = agent.Retrieval{Ref: "live"}
	if err := declareAgent(root, m, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	a, err := could(root, "tidy", "write_page", "about", false, false, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Could || !strings.Contains(strings.Join(a.Then, ";"), "approves the exact call") {
		t.Fatalf("an agent reading live was told it could not draft: %+v", a)
	}
}
