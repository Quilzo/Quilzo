// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package aievidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/fleet"
	"github.com/quilzo/quilzo/internal/posture"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func ev(action string, at time.Time, kind audit.Kind, outcome audit.Outcome, d map[string]string) audit.Event {
	return audit.Event{Action: action, At: at.Format(time.RFC3339), Kind: kind, Outcome: outcome, Detail: d}
}

func inputs() Inputs {
	day := func(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }
	return Inputs{Name: "Northwind", Version: "1.2", From: day(30), Now: now,
		State: posture.State{Audit: []audit.Event{
			ev("agent.run", day(400), audit.KindAI, audit.Success, nil), // before the period
			ev("agent.run", day(2), audit.KindAI, audit.Success, nil),
			ev("agent.run", day(2), audit.KindHuman, audit.Success, nil),
			ev("agent.action", day(2), audit.KindAI, audit.Denied, nil),
			ev("agent.action", day(2), audit.KindAI, audit.Success, nil),
			ev("agent.approve", day(1), audit.KindHuman, audit.Success, nil),
			ev("shield.responded", day(1), audit.KindService, audit.Success, map[string]string{"did": "paused tidy for 24h"}),
			ev("model.masked", day(1), audit.KindService, audit.Success, nil),
		}, AI: posture.AIFacts{Evals: []posture.AgentEvalFact{{Name: "tidy", At: day(3), Cases: 3}},
			HeldMemories: map[string]int{"tidy": 2}}},
		Agents: map[string]agent.Manifest{
			"tidy":   {Name: "tidy", Kind: agent.KindTask, Purpose: "keep pages tidy", Autonomy: agent.AutonomyDraft, Capabilities: []string{"read_page", "write_page", "remember"}, Memory: agent.Memory{Semantic: true, Retain: agent.Duration(30 * 24 * time.Hour)}, Tools: []agent.Tool{{Name: "create_issue"}}},
			"orphan": {Name: "orphan", Kind: agent.KindRetrieval, Purpose: "answer"},
			"gone":   {Name: "gone", Kind: agent.KindRetrieval, Purpose: "answer"},
		},
		Sponsors: map[string]string{"tidy": "dana", "gone": "sam"}, Standing: map[string]bool{"tidy": true},
		Routes:   []Route{{Name: "hosted", Model: "gpt-x", Host: "api.example.com"}},
		Chatbots: []Chatbot{{Name: "help", Public: true, Disclosed: true, UseModel: true, Documents: 2}, {Name: "sales", Public: true}},
		Tools:    []agent.Integration{{Name: "tracker", Endpoint: "tracker.example", Uses: []string{"create_issue"}, Pins: map[string]string{"create_issue": "x"}, Enabled: true}},
		External: []fleet.External{{Name: "help-desk", CardURL: "https://agents.example.com/card", Sponsor: "dana"}},
		Uses:     map[string][]string{"agent:tidy": {"hosted"}, "chatbot:help": {"hosted"}},
		Findings: []posture.Finding{{Rule: "ai.chatbot-undisclosed", Detail: "sales does not say it is automated"}},
	}
}

func byRef(items []Item) map[string]Item {
	m := map[string]Item{}
	for _, it := range items {
		m[it.Ref] = it
	}
	return m
}

func TestTheDeployersDutiesAreReadFromWhatHappened(t *testing.T) {
	d := byRef(Deployer(inputs()))
	if len(d) != 12 {
		t.Fatalf("%d duties", len(d))
	}
	if it := d["Art. 26(1)"]; it.Status != Shown || !strings.Contains(strings.Join(it.Evidence, " "), "2 runs, 2 actions, 1 of them refused") {
		t.Fatalf("%+v", it)
	}
	if it := d["Art. 26(2)"]; it.Status != Partly || !strings.Contains(strings.Join(it.Evidence, " "), "nobody with standing answers for: gone, orphan") ||
		!strings.Contains(strings.Join(it.Evidence, " "), "approved 1 actions") {
		t.Fatalf("%+v", it)
	}
	if it := d["Art. 26(5)"]; it.Status != Partly || !strings.Contains(strings.Join(it.Evidence, " "), "paused agents 1 times") ||
		!strings.Contains(strings.Join(it.Evidence, " "), "never evaluated: gone, orphan") {
		t.Fatalf("%+v", it)
	}
	if it := d["Art. 26(6)"]; it.Status != Shown || !strings.Contains(strings.Join(it.Evidence, " "), "begins on") ||
		strings.Contains(strings.Join(it.Evidence, " "), "younger than six months") {
		t.Fatalf("%+v", it)
	}
	if it := d["Art. 50(1)"]; it.Status != Partly || len(it.Findings) != 1 || !strings.Contains(strings.Join(it.Evidence, " "), "not disclosed: sales") {
		t.Fatalf("%+v", it)
	}
	if it := d["Art. 26(7)"]; it.Status != Yours || it.Yours == "" {
		t.Fatalf("%+v", it)
	}
	// A young log says to keep it.
	in := inputs()
	in.State.Audit = in.State.Audit[1:]
	if it := byRef(Deployer(in))["Art. 26(6)"]; !strings.Contains(strings.Join(it.Evidence, " "), "younger than six months") {
		t.Fatalf("%+v", it)
	}
}

func TestEveryAnnexAControlIsStated(t *testing.T) {
	a := Annex(inputs())
	if len(a) != 38 {
		t.Fatalf("%d controls", len(a))
	}
	m := byRef(a)
	if m["A.8.2"].Status != Partly || len(m["A.8.2"].Findings) != 1 {
		t.Fatalf("%+v", m["A.8.2"])
	}
	if m["A.6.2.4"].Status != Partly || m["A.6.2.8"].Status != Shown || m["A.2.2"].Status != Yours {
		t.Fatalf("%+v %+v %+v", m["A.6.2.4"], m["A.6.2.8"], m["A.2.2"])
	}
	for _, it := range a {
		if it.Status == Yours && it.Yours == "" {
			t.Errorf("%s is the organisation's and says nothing of what", it.Ref)
		}
	}
}

func TestTheAIBillOfMaterialsSaysWhatUsesWhat(t *testing.T) {
	b := AIBOM(inputs())
	if b.Format != "CycloneDX" || b.SpecVersion != "1.6" || !strings.HasPrefix(b.SerialNumber, "urn:uuid:") {
		t.Fatalf("%+v", b)
	}
	types := map[string]string{}
	for _, c := range b.Components {
		types[c.BOMRef] = c.Type
	}
	for ref, want := range map[string]string{"model:hosted": "machine-learning-model", "agent:tidy": "application",
		"data:memory:tidy": "data", "chatbot:help": "application", "data:knowledge:help": "data"} {
		if types[ref] != want {
			t.Errorf("%s is %q", ref, types[ref])
		}
	}
	deps := map[string][]string{}
	for _, d := range b.Dependencies {
		deps[d.Ref] = d.DependsOn
	}
	if strings.Join(deps["agent:tidy"], ",") != "data:memory:tidy,model:hosted,service:tracker" ||
		strings.Join(deps["chatbot:help"], ",") != "data:knowledge:help,model:hosted" {
		t.Fatalf("%v", deps)
	}
	if len(b.Services) != 2 || !b.Services[0].TrustBoundary {
		t.Fatalf("%+v", b.Services)
	}
	if _, err := json.Marshal(b); err != nil {
		t.Fatal(err)
	}
}
