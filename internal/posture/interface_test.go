// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package posture

import (
	"testing"
	"time"
)

func TestTheAgentInterfaceChecks(t *testing.T) {
	base := func() State {
		return State{Now: time.Now(), Interface: InterfaceFacts{Checked: true, On: true, Hosts: []string{"claude.ai"}}}
	}
	if f := has(Scan(base(), nil), "mcp.any-app"); f != nil {
		t.Fatal("named hosts flagged")
	}
	s := base()
	s.Interface.Hosts = append(s.Interface.Hosts, "*")
	if f := has(Scan(s, nil), "mcp.any-app"); f == nil {
		t.Fatal("any host not flagged")
	}
	s.Interface.On = false
	if f := has(Scan(s, nil), "mcp.any-app"); f != nil {
		t.Fatal("flagged while the interface is off")
	}
	s = base()
	if f := has(Scan(s, nil), "mcp.admin-app"); f != nil {
		t.Fatal("no admin connection, yet flagged")
	}
	s.Interface.Admin = []string{"gr_1 (Assistant for dana)"}
	if f := has(Scan(s, nil), "mcp.admin-app"); f == nil || f.Resource != "mcp/gr_1 (Assistant for dana)" {
		t.Fatalf("admin connection not flagged: %+v", f)
	}
}

func TestTheAgentIdentityChecks(t *testing.T) {
	now := time.Now()
	s := State{Now: now, AI: AIFacts{Checked: true, Identities: []AgentIdentityFact{
		{Name: "fine", Sponsor: "dana", SponsorActive: true, Expires: now.Add(60 * 24 * time.Hour)},
		{Name: "orphan"},
		{Name: "left", Sponsor: "sam", Expires: now.Add(60 * 24 * time.Hour)},
		{Name: "ending", Sponsor: "dana", SponsorActive: true, Expires: now.Add(3 * 24 * time.Hour)},
		{Name: "ended", Sponsor: "dana", SponsorActive: true, Expires: now.Add(-time.Hour)},
	}}}
	got := map[string][]string{}
	for _, f := range Scan(s, nil).Findings {
		got[f.Rule] = append(got[f.Rule], f.Resource)
	}
	want := map[string]string{"agent.no-sponsor": "agent/orphan", "agent.sponsor-gone": "agent/left"}
	for rule, res := range want {
		if len(got[rule]) != 1 || got[rule][0] != res {
			t.Errorf("%s: %v", rule, got[rule])
		}
	}
	if e := got["agent.identity-ending"]; len(e) != 2 {
		t.Errorf("identity-ending: %v", e)
	}
	for _, rule := range []string{"agent.no-sponsor", "agent.sponsor-gone", "agent.identity-ending"} {
		for _, r := range got[rule] {
			if r == "agent/fine" {
				t.Errorf("%s flagged a fine agent", rule)
			}
		}
	}
}
