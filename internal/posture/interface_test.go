// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package posture

import (
	"strings"
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

func TestTheToolApprovalChecks(t *testing.T) {
	s := State{Now: time.Now(), AI: AIFacts{Checked: true, Tools: []AgentToolFact{
		{Agent: "fine", Integration: "crm", Tool: "lookup", Pinned: true},
		{Agent: "loose", Integration: "crm", Tool: "export"},
		{Agent: "a", Integration: "files", Tool: "read", Pinned: true, Changed: "abcdef0123456789"},
		{Agent: "b", Integration: "files", Tool: "read", Pinned: true, Changed: "abcdef0123456789"},
	}}}
	got := map[string][]Finding{}
	for _, f := range Scan(s, nil).Findings {
		got[f.Rule] = append(got[f.Rule], f)
	}
	if u := got["integration.unpinned"]; len(u) != 1 || u[0].Resource != "agent/loose" {
		t.Errorf("unpinned: %+v", u)
	}
	// One server's change is one finding, however many agents use the tool.
	c := got["integration.tool-changed"]
	if len(c) != 1 || c[0].Resource != "/integrations/files" || c[0].Detail != "files changed read since it was approved (now abcdef012345)" {
		t.Errorf("changed: %+v", c)
	}
	for _, rule := range []string{"integration.unpinned", "integration.tool-changed"} {
		for _, f := range got[rule] {
			if f.Resource == "agent/fine" || f.Resource == "/integrations/crm" {
				t.Errorf("%s flagged a pinned, unchanged tool", rule)
			}
		}
	}
}

func TestAProgramWithNoBoxIsAFinding(t *testing.T) {
	s := State{Now: time.Now(), AI: AIFacts{Checked: true, Programs: []AgentProgramFact{
		{Agent: "fine", Backend: "native", Available: true},
		{Agent: "stuck", Backend: "openshell", Why: "the openshell command is not installed here"},
	}}}
	var got []Finding
	for _, f := range Scan(s, nil).Findings {
		if f.Rule == "agent.program-cannot-run" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Resource != "agent/stuck" || !strings.Contains(got[0].Detail, "not installed") {
		t.Fatalf("%+v", got)
	}
}

func TestPersonalDataSentOutsideIsAFinding(t *testing.T) {
	s := State{Now: time.Now(), AI: AIFacts{Checked: true, PersonalRoutes: []string{"hosted"}}}
	var got []Finding
	for _, f := range Scan(s, nil).Findings {
		if f.Rule == "model.personal-data-leaves" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0].Detail, "hosted") {
		t.Fatalf("%+v", got)
	}
	s.AI.PersonalRoutes = nil
	for _, f := range Scan(s, nil).Findings {
		if f.Rule == "model.personal-data-leaves" {
			t.Fatal("flagged with no such route")
		}
	}
}

func TestHeldMemoriesAreAFindingUntilSomebodyLooks(t *testing.T) {
	s := State{Now: time.Now(), AI: AIFacts{Checked: true, HeldMemories: map[string]int{"helper": 3}}}
	var got []Finding
	for _, f := range Scan(s, nil).Findings {
		if f.Rule == "agent.memory-held" {
			got = append(got, f)
		}
	}
	if len(got) != 1 || got[0].Resource != "agent/helper" || !strings.Contains(got[0].Detail, "3 memories") {
		t.Fatalf("%+v", got)
	}
}
