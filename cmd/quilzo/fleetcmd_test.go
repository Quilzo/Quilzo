// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/fleet"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// The fleet is who called what as the log recorded it, the things that
// were declared, and the AI used without going through Quilzo.
func TestTheFleetIsWhatHappenedNotOnlyWhatWasDeclared(t *testing.T) {
	root, _ := identityStore(t) // dana declared tidy
	if err := saveJSON(integrationsPath(root), agent.Integrations{Declared: []agent.Integration{{Name: "tracker",
		Kind: agent.IntegrationMCP, Enabled: true, Purpose: "file issues", Endpoint: "tracker.example",
		Uses: []string{"create_issue"}, Gateway: &agent.GatewayPolicy{Role: "reader"}}}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ai := func(action string, d map[string]string, model string) {
		record(root, audit.Record{Action: action, Resource: "/", Outcome: audit.Success, Principal: "agent/tidy",
			Kind: audit.KindAI, Model: model, Verified: true, Detail: d})
	}
	ai("agent.run", map[string]string{"agent": "tidy", "on_behalf_of": "dana"}, "m")
	ai("agent.action", map[string]string{"agent": "tidy", "tool": "create_issue", "on_behalf_of": "dana"}, "m")
	ai("agent.egress", map[string]string{"agent": "tidy", "host": "api.openai.com", "on_behalf_of": "dana"}, "m")
	ai("mcp.call", map[string]string{"tool": "quilzo_read", "on_behalf_of": "sam"}, "https://app.example.com/meta")
	if err := os.WriteFile(usagePath(root), []byte(`{"at":"`+now.UTC().Format(time.RFC3339)+`","consumer":"chatbot:help","route":"hosted","in":10,"outcome":"ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Append(telemetry.Event{Time: now, Received: now, Class: telemetry.ClassHTTPActivity, Source: "zscaler/web",
		Actor:       telemetry.ID{Issuer: "okta", Value: "rae@shop.example"},
		Observables: []telemetry.Observable{{Kind: telemetry.ObservableURL, Value: "https://claude.ai/new"}}}); err != nil {
		t.Fatal(err)
	}
	sp.Close()

	v, err := buildFleet(root, 30, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	nodes := map[string]fleet.Node{}
	for _, n := range v.Nodes {
		nodes[n.ID] = n
	}
	if n := nodes["agent:tidy"]; n.Owner != "dana" || !strings.HasPrefix(n.Standing, "until") {
		t.Fatalf("tidy: %+v", n)
	}
	if n := nodes["tool:tracker"]; n.Standing != "enabled" || len(n.Flags) != 2 {
		t.Fatalf("tracker: %+v", n)
	}
	edges := map[string]int{}
	for _, e := range v.Edges {
		edges[e.From+" > "+e.To] = e.Calls
	}
	for _, want := range []string{"person:dana > agent:tidy", "agent:tidy > tool:tracker", "agent:tidy > host:api.openai.com",
		"app:https://app.example.com/meta > quilzo", "person:sam > app:https://app.example.com/meta", "chatbot:help > route:hosted"} {
		if edges[want] != 1 {
			t.Errorf("no edge %s in %v", want, edges)
		}
	}
	shadow := map[string]bool{}
	for _, s := range v.Shadow {
		shadow[s.Service+" "+s.Who] = true
	}
	if !shadow["OpenAI agent:tidy"] || !shadow["Anthropic okta:rae@shop.example"] || len(v.Shadow) != 2 {
		t.Fatalf("%+v", v.Shadow)
	}
	// Outside the window, nothing called anything.
	if old, _ := buildFleet(root, 7, now.Add(8*24*time.Hour)); len(old.Edges) != 0 || len(old.Shadow) != 0 {
		t.Fatalf("%+v", old.Edges)
	}
}

// Another vendor's agent is registered by its card, answered for by whoever
// registered it, and noticed when its card changes.
func TestAnotherVendorsAgentIsRegisteredByItsCard(t *testing.T) {
	root, _ := identityStore(t)
	card := `{"name":"Help Desk","description":"Answers tickets","version":"1","provider":{"organization":"Zendesk"},
		"supportedInterfaces":[{"url":"https://agents.example.com/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"skills":[]}`
	was := cardFetch
	cardFetch = func(_ context.Context, u string) ([]byte, error) {
		if u != "https://agents.example.com/.well-known/agent-card.json" {
			return nil, errors.New("no such card")
		}
		return []byte(card), nil
	}
	defer func() { cardFetch = was }()
	if _, err := fleetRegister(root, "https://agents.example.com/.well-known/agent-card.json", "", human("rae"), time.Now()); err == nil {
		t.Fatal("somebody who may not grant registered an agent")
	}
	e, err := fleetRegister(root, "https://agents.example.com/.well-known/agent-card.json", "", asAdmin("dana"), time.Now())
	if err != nil || e.Name != "help-desk" || e.Sponsor != "dana" || e.Provider != "Zendesk" {
		t.Fatalf("%+v %v", e, err)
	}
	if _, err := fleetRegister(root, "https://agents.example.com/.well-known/agent-card.json", "other", asAdmin("dana"), time.Now()); err == nil {
		t.Fatal("the same card was registered twice")
	}
	if changed, err := fleetCheck(root, time.Now()); err != nil || len(changed) != 0 {
		t.Fatalf("%v %v", changed, err)
	}
	card = strings.Replace(card, "Answers tickets", "Answers tickets and exports the customer list", 1)
	if changed, err := fleetCheck(root, time.Now()); err != nil || len(changed) != 1 || changed[0] != "help-desk" {
		t.Fatalf("%v %v", changed, err)
	}
	v, _ := buildFleet(root, 30, time.Now())
	for _, n := range v.Nodes {
		if n.ID == "external:help-desk" && (len(n.Flags) != 1 || n.Owner != "dana") {
			t.Fatalf("%+v", n)
		}
	}
	if err := fleetUnregister(root, "help-desk", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if err := fleetUnregister(root, "help-desk", asAdmin("dana")); err == nil {
		t.Fatal("removed twice")
	}
	if _, err := cardFetch(context.Background(), "http://agents.example.com/card"); err == nil {
		t.Fatal("the stub let anything through")
	}
	cardFetch = was
	for _, u := range []string{"http://agents.example.com/card", "https://user:pw@agents.example.com/card", "file:///etc/passwd"} {
		if _, err := cardFetch(context.Background(), u); err == nil {
			t.Errorf("%s was fetched", u)
		}
	}
}
