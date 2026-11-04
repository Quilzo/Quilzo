// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentexec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assist"
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

// An escalated answer is the run's question for a person, typed as the
// decider asked it, and nothing of it reaches the model as an answer.
func TestAnEscalatedAnswerIsAQuestionForAPerson(t *testing.T) {
	perform, _ := decidersFor(t, &flipModel{})
	out, err := perform(context.Background(), agent.Action{Op: "decide",
		Input: map[string]any{"name": "triage", "state": "something ambiguous"}})
	var esc *agent.Escalation
	if !errors.As(err, &esc) {
		t.Fatalf("the escalation was not a question: %v %q", err, out)
	}
	if out != "" || strings.Contains(esc.Why, "billing") || strings.Contains(esc.Why, "support") {
		t.Fatalf("an escalated answer leaked a value to act on: %q %q", out, esc.Why)
	}
	q := esc.Questions[0]
	if q.Name != "queue" || q.Kind != "choice" || len(q.Options) == 0 || q.Threshold == 0 {
		t.Fatalf("the question is not the decider's, typed: %+v", q)
	}
}

// No model configured: every question escalates, which is the package's
// own failure mode, and the executor does not paper over it.
func TestWithNoModelEveryQuestionEscalates(t *testing.T) {
	perform, _ := decidersFor(t, nil)
	out, err := perform(context.Background(), agent.Action{Op: "decide",
		Input: map[string]any{"name": "triage", "state": "x"}})
	var esc *agent.Escalation
	if !errors.As(err, &esc) || out != "" {
		t.Fatalf("without a model nothing should be decided: %v %q", err, out)
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

// pricedModel answers as steadyModel does and says what each call used and
// cost, as the gateway's models do.
type pricedModel struct {
	steadyModel
	calls int
}

func (m *pricedModel) Complete(ctx context.Context, system, user string) (string, error) {
	m.calls++
	return m.steadyModel.Complete(ctx, system, user)
}

func (m *pricedModel) CompleteCosted(ctx context.Context, system, user string) (string, assist.Usage, int64, error) {
	out, err := m.Complete(ctx, system, user)
	return out, assist.Usage{In: 600, Out: 400}, 100_000, err
}

// A decider's model calls are the run's, and were charged to nothing: each
// decide step could be up to five calls the run's money and token budgets
// never saw, and its receipt priced the agent's own calls alone.
func TestADecidersModelCallsAreChargedToTheRun(t *testing.T) {
	m := &pricedModel{steadyModel: steadyModel{`{"answers":{"queue":{"value":"billing","confidence":0.95}}}`}}
	perform, s := decidersFor(t, m)
	if _, err := perform(context.Background(), agent.Action{Op: "decide",
		Input: map[string]any{"name": "triage", "state": "my card was charged twice"}}); err != nil {
		t.Fatal(err)
	}
	if m.calls != 3 {
		t.Fatalf("the decider asked its model %d times; it samples 3", m.calls)
	}
	if s.Cost() != 300_000 || s.TokensUsed() != 3000 {
		t.Errorf("three calls at 0.10 and 1000 tokens each left the run charged %d micros and %d tokens",
			s.Cost(), s.TokensUsed())
	}
}

// Without a model every question escalates, as the package's own failure
// mode, and charging cannot be what turns that into a model call.
func TestADeciderWithNoModelStillEscalates(t *testing.T) {
	perform, _ := decidersFor(t, nil)
	_, err := perform(context.Background(), agent.Action{Op: "decide",
		Input: map[string]any{"name": "triage", "state": "my card was charged twice"}})
	var esc *agent.Escalation
	if !errors.As(err, &esc) {
		t.Fatalf("with no model the question came back %v", err)
	}
}

// After a person answers what a decider was not sure of, the run goes on
// with every answer the step had, not only theirs.
//
// Found by running one: support-triage settled desk and urgency and was
// not sure of refund_due; the person answered refund_due, and the next
// prompt said only "ada answered what the decider was not sure of:
// refund_due: yes". What the decider had settled was thrown away with the
// escalation, so nothing after the step could use it. Both ways a person
// answers: the run paused and continued from its record, and the run
// waiting in its own process.
func TestAnAnsweredEscalationKeepsWhatTheDeciderSettled(t *testing.T) {
	d := decide.Decider{Name: "support-triage", Title: "Where a message goes",
		MinConfidence: 0.8, Samples: 3, Questions: []decide.Question{
			{Name: "desk", Ask: "which desk", Kind: decide.Choice, Options: []string{"refunds", "events"}},
			{Name: "refund_due", Ask: "is a refund due", Kind: decide.YesNo},
			{Name: "urgency", Ask: "how urgent", Kind: decide.Score},
		}}
	model := steadyModel{`{"answers":{"desk":{"value":"refunds","confidence":0.96},` +
		`"refund_due":{"value":"yes","confidence":0.69},"urgency":{"value":0.22,"confidence":0.83}}}`}
	set := &decide.Set{}
	if err := set.Put(d); err != nil {
		t.Fatal(err)
	}
	st := searchStore(t)
	performFor := func(s *agent.Session) func(context.Context, agent.Action) (string, error) {
		return Dispatch(Reader{Store: st}, Writer{Store: st, Author: "agent/router"}, Tools{}, Delegates{},
			Deciders{Load: func() (*decide.Set, error) { return set, nil },
				Model: func(string) decide.Model { return model }}, s)
	}
	// The model decides once, then finishes; what it was shown before
	// finishing is what the run went on with.
	var shown string
	decideNext := func(_ context.Context, _ string, seen []agent.Observation) (agent.Action, error) {
		if len(seen) == 0 {
			return agent.Action{Op: "decide", Input: map[string]any{"name": "support-triage",
				"state": "I bought Nightglass on Saturday and it will not start"}}, nil
		}
		shown = seen[len(seen)-1].Body
		return agent.Action{Say: "routed"}, nil
	}
	check := func(how string) {
		t.Helper()
		for _, want := range []string{"ada answered", "refund_due: yes", "desk: refunds", "urgency: 0.22"} {
			if !strings.Contains(shown, want) {
				t.Errorf("%s: the run went on without %q:\n%s", how, want, shown)
			}
		}
	}

	s := agent.NewSession(deciderAgent(), nil)
	r := agent.Runner{Decide: decideNext, Perform: performFor(s), Pause: true}
	first, err := r.Run(context.Background(), s, "route the message")
	if err != nil {
		t.Fatal(err)
	}
	if first.Waiting == nil || len(first.Waiting.Questions) != 1 || first.Waiting.Questions[0].Name != "refund_due" {
		t.Fatalf("the run did not stop at refund_due alone: %+v", first.Waiting)
	}
	s = agent.NewSession(deciderAgent(), nil)
	r.Perform = performFor(s)
	if _, err := r.Continue(context.Background(), s, first, &agent.Verdict{N: first.Waiting.N, Approve: true,
		By: "ada", Answers: map[string]string{"refund_due": "yes"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	check("continued from its record")

	shown = ""
	s = agent.NewSession(deciderAgent(), nil)
	r = agent.Runner{Decide: decideNext, Perform: performFor(s),
		Hold: func(_ context.Context, w agent.Pending, _ func()) (agent.Verdict, error) {
			return agent.Verdict{N: w.N, Approve: true, By: "ada", Answers: map[string]string{"refund_due": "yes"}}, nil
		}}
	if _, err := r.Run(context.Background(), s, "route the message"); err != nil {
		t.Fatal(err)
	}
	check("answered while it waited")
}
