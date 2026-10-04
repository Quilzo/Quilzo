// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package posture

import (
	"strings"
	"testing"
	"time"
)

func findingFor(rep Report, id string) (Finding, bool) {
	for _, f := range rep.Findings {
		if f.ID() == id {
			return f, true
		}
	}
	return Finding{}, false
}

func TestAPublicChatbotThatDoesNotSayItIsAutomatedIsFound(t *testing.T) {
	s := clean(t)
	s.AI.Chatbots[0].Disclosed = false
	f, ok := findingFor(Scan(s, nil), "ai.chatbot-undisclosed:help")
	if !ok {
		t.Fatal("an undisclosed public chatbot was not found")
	}
	var art50 bool
	for _, r := range f.Refs {
		art50 = art50 || (r.Framework == "eu-ai-act" && r.ID == "Art. 50(1)")
	}
	if !art50 {
		t.Errorf("the finding does not cite the AI Act article it is about: %v", f.Refs)
	}
	// Not public: nobody is talking to it.
	s.AI.Chatbots[0].Public = false
	if _, ok := findingFor(Scan(s, nil), "ai.chatbot-undisclosed:help"); ok {
		t.Error("a chatbot nobody can reach was reported")
	}
}

func TestAChatbotNobodyHasMeasuredIsFound(t *testing.T) {
	s := clean(t)
	s.AI.Chatbots[0].LastEval = time.Time{}
	if _, ok := findingFor(Scan(s, nil), "ai.chatbot-unevaluated:help"); !ok {
		t.Error("a never-evaluated public chatbot was not found")
	}
	s.AI.Chatbots[0].LastEval = s.Now.Add(-100 * 24 * time.Hour)
	f, ok := findingFor(Scan(s, nil), "ai.chatbot-unevaluated:help")
	if !ok || !strings.Contains(f.Detail, "ago") {
		t.Errorf("one evaluated a hundred days ago was not found: %+v", f)
	}
}

func TestAFlaggedAgentIsFound(t *testing.T) {
	s := clean(t)
	s.AI.Flagged = []string{"agent/support"}
	if _, ok := findingFor(Scan(s, nil), "ai.agent-flagged:agent/support"); !ok {
		t.Error("a flagged agent was not found")
	}
}

func TestSendingToAnOutsideModelIsADecisionToRecord(t *testing.T) {
	s := clean(t)
	s.AI.ModelHost, s.AI.ModelLocal = "api.provider.example", false
	f, ok := findingFor(Scan(s, nil), "privacy.model-egress:api.provider.example")
	if !ok || !strings.Contains(f.Detail, "1 chatbot(s) and 1 agent(s)") {
		t.Fatalf("an outside model was not reported: %+v", f)
	}
	// Once the agreement is recorded, it is suppressed like any accepted risk.
	sup := []Suppression{{ID: f.ID(), Reason: "DPA signed", By: "dana",
		Until: s.Now.Add(24 * time.Hour).Unix()}}
	if _, ok := findingFor(Scan(s, sup), f.ID()); ok {
		t.Error("a recorded agreement did not quiet the finding")
	}
	// Nothing is sent when nothing uses it.
	s.AI.Agents, s.AI.Chatbots[0].UseModel = 0, false
	if _, ok := findingFor(Scan(s, nil), f.ID()); ok {
		t.Error("an outside model nobody uses was reported")
	}
}

// Not run is said, not scored as fine.
func TestAScanWithoutTheAIFactsSaysSo(t *testing.T) {
	s := clean(t)
	s.AI = AIFacts{}
	rep := Scan(s, nil)
	said := false
	for _, n := range rep.NotChecked {
		said = said || strings.Contains(n, "AI and privacy checks")
	}
	if !said || rep.Score == 100 {
		t.Errorf("a scan that never looked at the AI facts reads %d with %v",
			rep.Score, rep.NotChecked)
	}
}

// Every finding carries where it bears, so a framework view is not built
// from a second list that can drift from the checks.
func TestEveryFindingSaysWhichFrameworksItBearsOn(t *testing.T) {
	s := clean(t)
	s.Server.AdminAddr = "0.0.0.0:8080"
	s.AI.Flagged = []string{"agent/x"}
	rep := Scan(s, nil)
	if len(rep.Findings) < 2 {
		t.Fatal("the scan found too little to test this")
	}
	for _, f := range rep.Findings {
		if len(f.Refs) == 0 {
			t.Errorf("%s carries no framework reference", f.ID())
		}
	}
}

func TestAFrameworkViewSaysFailingPassingOrNotChecked(t *testing.T) {
	s := clean(t)
	s.AI.Chatbots[0].Disclosed = false
	rep := Scan(s, nil)
	view := ByFramework(rep, "eu-ai-act")
	var art50 RefStatus
	for _, st := range view {
		if st.Ref.ID == "Art. 50(1)" {
			art50 = st
		}
	}
	if art50.State != "failing" || len(art50.Findings) != 1 {
		t.Fatalf("Article 50(1) reads %+v", art50)
	}
	if view[0].State != "failing" {
		t.Error("failing requirements are not listed first")
	}

	// The same requirement, with the inputs never gathered, is not checked
	// rather than passing: silence from a rule that did not run is not a pass.
	s.AI = AIFacts{}
	for _, st := range ByFramework(Scan(s, nil), "eu-ai-act") {
		if st.Ref.ID == "Art. 50(1)" && st.State != "not checked" {
			t.Errorf("an unchecked requirement reads %q", st.State)
		}
	}
	s = clean(t)
	for _, st := range ByFramework(Scan(s, nil), "eu-ai-act") {
		if st.Ref.ID == "Art. 50(1)" && st.State != "passing" {
			t.Errorf("a disclosed chatbot leaves Article 50(1) %q", st.State)
		}
	}
	if len(ByFramework(rep, "no-such-framework")) != 0 {
		t.Error("an unknown framework has requirements")
	}
}

func TestAnAgentThatFollowedAPlantIsFoundAndAnUnmeasuredOneToo(t *testing.T) {
	s := clean(t)
	s.AI.Evals = []AgentEvalFact{
		{Name: "steered", At: s.Now.Add(-time.Hour), Cases: 4, Hijacked: 1},
		{Name: "never", Cases: 0},
		{Name: "fine", At: s.Now.Add(-time.Hour), Cases: 4},
	}
	rep := Scan(s, nil)
	if f := has(rep, "ai.agent-followed-plant"); f == nil || f.Resource != "agent/steered" {
		t.Errorf("followed a plant: %+v", f)
	}
	if f := has(rep, "ai.agent-unevaluated"); f == nil || f.Resource != "agent/never" {
		t.Errorf("never evaluated: %+v", f)
	}
	for _, f := range rep.Findings {
		if f.Resource == "agent/fine" {
			t.Errorf("a passing, recent agent was flagged: %s", f.Rule)
		}
	}
}
