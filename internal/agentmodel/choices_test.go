// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentmodel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

func supervisor(t *testing.T) *agent.Session {
	t.Helper()
	return agent.NewSession(agent.Manifest{
		Name: "lead", Kind: agent.KindSupervisor, Purpose: "coordinate",
		Capabilities: []string{"list_pages"}, Autonomy: agent.AutonomyPropose,
		Tools:     []agent.Tool{{Name: "create_issue", Host: "tracker.example", Purpose: "file issues"}},
		Delegates: []string{"writer"},
		Budget:    agent.Budget{Steps: 10, Tools: 2, Duration: agent.Duration(time.Minute)},
	}, nil)
}

func choose(t *testing.T, reply string, d Decider) (agent.Action, error, string) {
	t.Helper()
	m := &fakeModel{reply: reply}
	d.Model = m
	a, err := d.Decide()(context.Background(), "goal", nil)
	return a, err, m.system
}

func TestAModelChoosesOnlyOfferedToolsAndDelegates(t *testing.T) {
	d := Decider{Session: supervisor(t),
		Tools: []ToolChoice{
			{Name: "create_issue", Purpose: "File an issue\nin the tracker", Args: []string{"title", "body"}},
			// Offered by the host and not declared by the manifest: not
			// in the vocabulary.
			{Name: "delete_project", Purpose: "remove", Args: []string{"id"}},
		},
		Delegates: []DelegateChoice{{Name: "writer", Purpose: "drafts pages"}, {Name: "stranger", Purpose: "x"}},
	}
	a, err, system := choose(t, `{"op":"tool:create_issue","input":{"title":"T","body":"B","api_key":"leak","nested":{"a":1}}}`, d)
	if err != nil || a.Tool != "create_issue" || len(a.Input) != 2 || a.Input["api_key"] != nil {
		t.Fatalf("%+v %v", a, err)
	}
	if !strings.Contains(system, "tool:create_issue — File an issue in the tracker (arguments: title, body)") ||
		strings.Contains(system, "delete_project") || strings.Contains(system, "stranger") ||
		!strings.Contains(system, "delegate:writer — drafts pages") {
		t.Fatalf("prompt:\n%s", system)
	}
	if _, err, _ := choose(t, `{"op":"tool:delete_project","input":{"id":"1"}}`, d); err == nil {
		t.Fatal("a tool the manifest does not declare was chosen")
	}
	a, err, _ = choose(t, `{"op":"delegate:writer","say":"draft the about page"}`, d)
	if err != nil || a.Delegate != "writer" || a.Say != "draft the about page" {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err, _ := choose(t, `{"op":"delegate:writer"}`, d); err == nil {
		t.Fatal("work handed on with no task")
	}
	if _, err, _ := choose(t, `{"op":"delegate:stranger","say":"x"}`, d); err == nil {
		t.Fatal("handed work to an agent the manifest does not name")
	}
	// Capabilities still work, and nothing else does.
	if a, err, _ := choose(t, `{"op":"list_pages"}`, d); err != nil || a.Op != "list_pages" {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err, _ := choose(t, `{"op":"tool:"}`, d); err == nil {
		t.Fatal("an empty tool name was taken")
	}
}

func TestWithoutChoicesTheVocabularyIsTheCapabilities(t *testing.T) {
	d := Decider{Session: supervisor(t)}
	_, err, system := choose(t, `{"op":"tool:create_issue","input":{}}`, d)
	if err == nil || strings.Contains(system, "tool:") || strings.Contains(system, "delegate:") {
		t.Fatalf("a tool nobody offered: %v\n%s", err, system)
	}
}
