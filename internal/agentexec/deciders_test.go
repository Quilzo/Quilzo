// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentexec

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/decide"
)

// A deciding model: the same answer every sample, so the confidence holds.
type steadyModel struct{ answer string }

func (m steadyModel) Name() string { return "steady" }
func (m steadyModel) Complete(_ context.Context, _, _ string) (string, error) {
	return m.answer, nil
}

// A model that changes its mind: overconfident and inconsistent, which is
// the case the confidence measurement exists to catch.
type flipModel struct {
	n     int
	along int
}

func (m *flipModel) Name() string { return "flip" }
func (m *flipModel) Complete(_ context.Context, _, _ string) (string, error) {
	m.n++
	if m.n%2 == 0 {
		return `{"answers":{"queue":{"value":"billing","confidence":0.95}}}`, nil
	}
	return `{"answers":{"queue":{"value":"support","confidence":0.95}}}`, nil
}

func triageDecider() decide.Decider {
	return decide.Decider{Name: "triage", Title: "Where a ticket goes",
		MinConfidence: 0.8, Samples: 3,
		Questions: []decide.Question{{Name: "queue", Ask: "which queue", Kind: decide.Choice,
			Options: []string{"billing", "support", "abuse"}}}}
}

// deciderAgent holds the decide capabilities, as a manifest may declare
// them against the MCP registry.
func deciderAgent() agent.Manifest {
	return agent.Manifest{Name: "router", Kind: agent.KindTask, Purpose: "route tickets",
		Capabilities: []string{"decide", "list_deciders"}, Autonomy: agent.AutonomyDraft,
		Budget: agent.Budget{Steps: 10, Tools: 2, Duration: agent.Duration(time.Minute)}}
}

func decidersFor(t *testing.T, m decide.Model) (func(context.Context, agent.Action) (string, error), *agent.Session) {
	t.Helper()
	set := &decide.Set{}
	if err := set.Put(triageDecider()); err != nil {
		t.Fatal(err)
	}
	s := agent.NewSession(deciderAgent(), nil)
	st := searchStore(t)
	perform := Dispatch(Reader{Store: st}, Writer{Store: st, Author: "agent/router"},
		Tools{}, Delegates{}, Deciders{
			Load:  func() (*decide.Set, error) { return set, nil },
			Model: func(string) decide.Model { return m },
		}, s)
	return perform, s
}

// The reason the executor grew this branch: an agent that holds the decide
// capability asks a typed question and gets a typed answer, not "not
// implemented here".
func TestAnAgentAsksATypedQuestionAndGetsATypedAnswer(t *testing.T) {
	perform, s := decidersFor(t, steadyModel{`{"answers":{"queue":{"value":"billing","confidence":0.95}}}`})
	out, err := perform(context.Background(), agent.Action{Op: "decide",
		Input: map[string]any{"name": "triage", "state": "my card was charged twice"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "queue: billing") || !strings.Contains(out, "confidence") {
		t.Fatalf("the answer did not come back typed:\n%s", out)
	}
	// The state is somebody's words: the run is marked as having read them.
	if s.Reads() == 0 {
		t.Error("asking about somebody's words did not mark the run as having read them")
	}
	out, err = perform(context.Background(), agent.Action{Op: "decide",
		Input: map[string]any{"name": "nope", "state": "x"}})
	if err == nil || !strings.Contains(err.Error(), "no decider called") {
		t.Fatalf("an unknown decider was not refused as one: %v", err)
	}
}

// An escalated answer says so in words the model is told to obey, and it
// is not dressed up as an answer.
func TestAnEscalatedAnswerSaysAPersonDecides(t *testing.T) {
	perform, _ := decidersFor(t, &flipModel{})
	out, err := perform(context.Background(), agent.Action{Op: "decide",
		Input: map[string]any{"name": "triage", "state": "something ambiguous"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "a person decides") || !strings.Contains(out, "do not act on this answer") {
		t.Fatalf("the escalation did not say what it is:\n%s", out)
	}
	if strings.Contains(out, "queue: billing") || strings.Contains(out, "queue: support") {
		t.Fatalf("an escalated answer leaked a value to act on:\n%s", out)
	}
}

// No model configured: every question escalates, which is the package's
// own failure mode, and the executor does not paper over it.
func TestWithNoModelEveryQuestionEscalates(t *testing.T) {
	perform, _ := decidersFor(t, nil)
	out, err := perform(context.Background(), agent.Action{Op: "decide",
		Input: map[string]any{"name": "triage", "state": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "a person decides") {
		t.Fatalf("without a model nothing should be decided:\n%s", out)
	}
}

// The listing, for a model that must first discover what it may ask.
func TestTheAgentSeesWhichDecidersExist(t *testing.T) {
	perform, _ := decidersFor(t, nil)
	out, err := perform(context.Background(), agent.Action{Op: "list_deciders"})
	if err != nil || !strings.Contains(out, "triage") || !strings.Contains(out, "choice") {
		t.Fatalf("the listing: %v\n%s", err, out)
	}
}
