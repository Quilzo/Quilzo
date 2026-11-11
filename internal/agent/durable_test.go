// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// drafter may read and may write a draft, and asks a person before it
// writes.
func drafter() Manifest {
	return Manifest{Name: "drafter", Kind: KindTask, Purpose: "draft pages",
		Capabilities: []string{"read_page", "write_page"},
		Autonomy:     AutonomyDraft, AskFirst: []string{"write_page"},
		Budget: Budget{Steps: 4, Tools: 1, Duration: Duration(time.Minute)}}
}

// scripted proposes a fixed list and records what it was shown each time.
type scripted struct {
	plan  []Action
	asked int
	shown [][]Observation
}

func (p *scripted) decide(_ context.Context, _ string, seen []Observation) (Action, error) {
	p.shown = append(p.shown, append([]Observation(nil), seen...))
	if p.asked >= len(p.plan) {
		return Action{Say: "done"}, nil
	}
	a := p.plan[p.asked]
	p.asked++
	return a, nil
}

// doer performs anything and records it.
type doer struct{ did []string }

func (d *doer) perform(_ context.Context, a Action) (string, error) {
	d.did = append(d.did, fmt.Sprintf("%s %v", a.Op, a.Input["page"]))
	return "did " + a.Op, nil
}

var write = Action{Op: "write_page", Input: map[string]any{"page": "about"}}

func TestARunStopsBeforeAnActionThatAsksFirstAndDoesNothing(t *testing.T) {
	p := &scripted{plan: []Action{{Op: "read_page"}, write}}
	d := &doer{}
	var kept []Trace
	r := Runner{Decide: p.decide, Perform: d.perform, Pause: true,
		Checkpoint: func(t Trace) { kept = append(kept, t) }}
	s := NewSession(drafter(), nil)
	tr, err := r.Run(context.Background(), s, "tidy the about page")
	if err != nil {
		t.Fatal(err)
	}
	if tr.Waiting == nil || tr.Waiting.N != 2 || tr.Waiting.Action.Op != "write_page" ||
		tr.Complete {
		t.Fatalf("the run did not stop to ask: %+v", tr)
	}
	if strings.Join(d.did, ",") != "read_page <nil>" {
		t.Errorf("before anybody was asked it did %v", d.did)
	}
	// Asking is not charged: the question may be answered no.
	if steps, _, _ := s.Spent(); steps != 1 {
		t.Errorf("%d steps were charged", steps)
	}
	if len(kept) != 1 || len(kept[0].Steps) != 1 {
		t.Errorf("the trace was handed over %d times", len(kept))
	}
}

func TestApprovingPerformsExactlyWhatWasAskedAndDoesNotAskTheModelAgain(t *testing.T) {
	p := &scripted{plan: []Action{{Op: "read_page"}, write}}
	d := &doer{}
	r := Runner{Decide: p.decide, Perform: d.perform, Pause: true}
	first, _ := r.Run(context.Background(), NewSession(drafter(), nil), "g")
	asked := p.asked

	// A different model, which would choose something else given the chance.
	other := &scripted{plan: []Action{{Op: "write_page",
		Input: map[string]any{"page": "pricing"}}}}
	r.Decide = other.decide
	s := NewSession(drafter(), nil)
	tr, err := r.Continue(context.Background(), s, first,
		&Verdict{N: 2, Approve: true, By: "dana"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.did) != 2 || d.did[1] != "write_page about" {
		t.Fatalf("after approval it did %v", d.did)
	}
	if p.asked != asked {
		t.Error("the first model was asked again")
	}
	// The continued run then asked what comes next, showing what came before
	// with the trust each had: content stays content.
	if len(other.shown) == 0 || len(other.shown[0]) != 2 ||
		other.shown[0][0].Trusted || other.shown[0][0].Body != "did read_page" {
		t.Fatalf("the model was shown %+v", other.shown)
	}
	// And the next write is a new question, not covered by the last answer.
	if tr.Waiting == nil || tr.Waiting.N != 3 ||
		tr.Waiting.Action.Input["page"] != "pricing" || len(d.did) != 2 {
		t.Errorf("a second write went through on the first approval: %+v %v",
			tr.Waiting, d.did)
	}
	// What the first stretch spent is still spent.
	if steps, _, _ := s.Spent(); steps != 2 {
		t.Errorf("the continued run has spent %d steps", steps)
	}
}

func TestDecliningIsToldToTheModelAndNothingIsDone(t *testing.T) {
	p := &scripted{plan: []Action{write}}
	d := &doer{}
	r := Runner{Decide: p.decide, Perform: d.perform, Pause: true}
	first, _ := r.Run(context.Background(), NewSession(drafter(), nil), "g")

	tr, err := r.Continue(context.Background(), NewSession(drafter(), nil), first,
		&Verdict{N: 1, By: "dana"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.did) != 0 {
		t.Fatalf("a declined action was done: %v", d.did)
	}
	if !tr.Complete || len(tr.Steps) != 2 || tr.Steps[0].Allowed ||
		tr.Steps[0].Why != "dana declined this" {
		t.Errorf("the declined run is %+v", tr)
	}
	last := p.shown[len(p.shown)-1]
	if len(last) != 1 || !last[0].Trusted ||
		last[0].Body != "refused: dana declined this" {
		t.Errorf("the model was told %+v", last)
	}
}

func TestAnAnswerOnlyFitsTheQuestionThatWasAsked(t *testing.T) {
	p := &scripted{plan: []Action{{Op: "read_page"}, write}}
	d := &doer{}
	r := Runner{Decide: p.decide, Perform: d.perform, Pause: true}
	ctx := context.Background()
	first, _ := r.Run(ctx, NewSession(drafter(), nil), "g")
	now := time.Now()
	yes := func(n int) *Verdict { return &Verdict{N: n, Approve: true, By: "dana"} }

	// For another step.
	if _, err := r.Continue(ctx, NewSession(drafter(), nil), first, yes(1), now); err == nil {
		t.Error("an answer to step 1 approved step 2")
	}
	// Too late.
	if _, err := r.Continue(ctx, NewSession(drafter(), nil), first, yes(2),
		now.Add(PendingTTL+time.Hour)); err == nil {
		t.Error("a question four days old was approved")
	}
	// With no answer at all.
	if _, err := r.Continue(ctx, NewSession(drafter(), nil), first, nil, now); err == nil {
		t.Error("a waiting run was continued without an answer")
	}
	// For another agent's session.
	m := drafter()
	m.Name = "other"
	if _, err := r.Continue(ctx, NewSession(m, nil), first, yes(2), now); err == nil {
		t.Error("one agent's run was continued as another")
	}
	// On a run that is not waiting.
	done := Trace{Agent: "drafter", Goal: "g", Complete: true}
	if _, err := r.Continue(ctx, NewSession(drafter(), nil), done, yes(1), now); err != ErrNotWaiting {
		t.Errorf("a finished run took an approval: %v", err)
	}
	if _, err := r.Continue(ctx, NewSession(drafter(), nil), done, nil, now); err == nil {
		t.Error("a finished run was continued")
	}
	if len(d.did) != 1 {
		t.Fatalf("a refused answer did something: %v", d.did)
	}
}

// Approval is not a way around the gate. The declaration as it stands when
// the run is continued decides.
func TestAnApprovedActionStillGoesThroughTheGate(t *testing.T) {
	p := &scripted{plan: []Action{write}}
	d := &doer{}
	r := Runner{Decide: p.decide, Perform: d.perform, Pause: true}
	ctx := context.Background()
	first, _ := r.Run(ctx, NewSession(drafter(), nil), "g")
	yes := &Verdict{N: 1, Approve: true, By: "dana"}

	// The capability was withdrawn while the run waited.
	narrowed := drafter()
	narrowed.Capabilities, narrowed.AskFirst = []string{"read_page"}, nil
	tr, err := r.Continue(ctx, NewSession(narrowed, nil), first, yes, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.did) != 0 || tr.Steps[0].Allowed {
		t.Fatalf("an approved action outside the declaration was done: %v", d.did)
	}

	// The budget was already spent before it stopped.
	spent := first
	spent.Steps = []Step{
		{N: 1, Action: Action{Op: "read_page"}, Allowed: true, Result: "a"},
		{N: 2, Action: Action{Op: "read_page"}, Allowed: true, Result: "b"},
		{N: 3, Action: Action{Op: "read_page"}, Allowed: true, Result: "c"},
		{N: 4, Action: Action{Op: "read_page"}, Allowed: true, Result: "d"}}
	spent.Waiting = &Pending{N: 5, Action: write, Since: time.Now()}
	tr, err = r.Continue(ctx, NewSession(drafter(), nil), spent,
		&Verdict{N: 5, Approve: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.did) != 0 || !strings.Contains(tr.Stopped, "budget") {
		t.Errorf("stopping a run gave it a fresh budget: %v, %q", d.did, tr.Stopped)
	}
}

func TestStoppingARunDoesNotCleanItsRecord(t *testing.T) {
	p := &scripted{plan: []Action{write}}
	r := Runner{Decide: p.decide, Perform: (&doer{}).perform, Pause: true}
	first, _ := r.Run(context.Background(), NewSession(drafter(), nil), "g")
	first.Tainted = true
	first.Spent.Tokens = 900

	s := NewSession(drafter(), nil)
	s.Recall([]Source{{Kind: FromPage, Name: "about"}}, 2)
	tr, err := r.Continue(context.Background(), s, first,
		&Verdict{N: 1, Approve: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !tr.Tainted || tr.Spent.Tokens != 900 {
		t.Errorf("the continued run is tainted=%v with %d tokens",
			tr.Tainted, tr.Spent.Tokens)
	}
	rc := tr.Receipt(s)
	if len(rc.Sources) != 1 || rc.Omitted != 2 {
		t.Errorf("what it read before stopping is gone: %+v", rc)
	}
}

// A run with nobody to ask does not do the thing instead.
func TestWithNobodyToAskAnActionThatAsksFirstIsRefused(t *testing.T) {
	p := &scripted{plan: []Action{write}}
	d := &doer{}
	r := Runner{Decide: p.decide, Perform: d.perform}
	tr, err := r.Run(context.Background(), NewSession(drafter(), nil), "g")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.did) != 0 || tr.Waiting != nil || tr.Steps[0].Allowed ||
		!strings.Contains(tr.Steps[0].Why, "nobody to ask") {
		t.Errorf("with nobody to ask: did %v, %+v", d.did, tr.Steps[0])
	}
}

// An action the declaration refuses anyway is refused, not asked about.
// Asking would teach people to approve without reading.
func TestARefusedActionIsNotPutToAPerson(t *testing.T) {
	m := drafter()
	// Not a declaration Validate would accept; a session does not assume
	// it was handed one that is.
	m.AskFirst = append(m.AskFirst, "publish")
	p := &scripted{plan: []Action{{Op: "publish"}, {Op: "read_page"}}}
	d := &doer{}
	r := Runner{Decide: p.decide, Perform: d.perform, Pause: true}
	tr, _ := r.Run(context.Background(), NewSession(m, nil), "g")
	if tr.Waiting != nil || tr.Steps[0].Allowed || len(d.did) != 1 {
		t.Errorf("an action outside the declaration was asked about: %+v", tr)
	}
	// And an action that does not ask first is simply done.
	if !tr.Complete {
		t.Errorf("an ordinary read stopped the run: %q", tr.Stopped)
	}
}

func TestRunningAgainFromAnEarlierStep(t *testing.T) {
	tr := Trace{Agent: "drafter", Goal: "g", Complete: true, Tainted: true,
		Steps: []Step{
			{N: 1, Action: Action{Op: "read_page"}, Allowed: true, Result: "a"},
			{N: 2, Action: Action{Op: "publish"}, Why: "not held"},
			{N: 3, Action: Action{Say: "done"}, Allowed: true, Result: "done"}}}
	cut, err := tr.Upto(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(cut.Steps) != 2 || cut.Complete || !cut.Tainted {
		t.Fatalf("cut to %+v", cut)
	}
	for _, n := range []int{-1, 3, 4} {
		if _, err := tr.Upto(n); err == nil {
			t.Errorf("a run of three steps was cut to %d", n)
		}
	}
	p := &scripted{plan: []Action{{Op: "read_page"}}}
	d := &doer{}
	r := Runner{Decide: p.decide, Perform: d.perform, Pause: true}
	s := NewSession(drafter(), nil)
	out, err := r.Continue(context.Background(), s, cut, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !out.Complete || len(out.Steps) != 4 || out.Steps[2].N != 3 || len(d.did) != 1 {
		t.Errorf("run again from step 2: %+v", out)
	}
	// The model was shown both earlier steps, the refusal as ours.
	if len(p.shown[0]) != 2 || p.shown[0][0].Trusted || !p.shown[0][1].Trusted {
		t.Errorf("it was shown %+v", p.shown[0])
	}
	if !out.Tainted {
		t.Error("running again from a step cleaned the run")
	}
}

func TestAskingFirstIsOnlyDeclaredAboutWhatIsHeldAndNarrowingKeepsIt(t *testing.T) {
	m := drafter()
	if err := m.Validate(nil); err != nil {
		t.Fatal(err)
	}
	m.AskFirst = []string{"publish"}
	if err := m.Validate(nil); err == nil {
		t.Error("asking first about something not held was accepted")
	}
	// Either side may add it; neither takes it away.
	parent, child := drafter(), drafter()
	child.AskFirst = nil
	if got := parent.Narrow(child).AskFirst; len(got) != 1 || got[0] != "write_page" {
		t.Errorf("narrowing dropped the parent's ask-first: %v", got)
	}
	parent.AskFirst, child.AskFirst = nil, []string{"write_page"}
	if got := parent.Narrow(child).AskFirst; len(got) != 1 {
		t.Errorf("narrowing dropped the child's ask-first: %v", got)
	}
	// And it does not survive for a capability narrowed away.
	parent.Capabilities = []string{"read_page"}
	if got := parent.Narrow(child).AskFirst; len(got) != 0 {
		t.Errorf("ask-first names something no longer held: %v", got)
	}
}

// pricedDecider charges a fixed price for each choice it makes, as a
// metered model does.
type pricedDecider struct {
	scripted
	s      **Session
	tokens int
	micros int64
}

func (p *pricedDecider) decide(ctx context.Context, goal string, seen []Observation) (Action, error) {
	(*p.s).Tokens(p.tokens)
	(*p.s).Charge(p.micros)
	return p.scripted.decide(ctx, goal, seen)
}

// Each step carries what it cost, and the step a person approved after a
// pause carries what choosing it cost before the pause.
func TestEveryStepCarriesItsCostAcrossAPause(t *testing.T) {
	var s *Session
	p := &pricedDecider{scripted: scripted{plan: []Action{{Op: "read_page"}, write}},
		s: &s, tokens: 100, micros: 2_000}
	r := Runner{Decide: p.decide, Perform: (&doer{}).perform, Pause: true}
	s = NewSession(drafter(), nil)
	first, err := r.Run(context.Background(), s, "tidy")
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Steps[0]; got.Tokens != 100 || got.Cost != 2_000 {
		t.Fatalf("the first step cost %d tokens and %d", got.Tokens, got.Cost)
	}
	if first.Waiting == nil || first.Waiting.Cost != 2_000 {
		t.Fatalf("the question did not keep what choosing it cost: %+v", first.Waiting)
	}
	s = NewSession(drafter(), nil)
	tr, err := r.Continue(context.Background(), s, first, &Verdict{N: 2, Approve: true, By: "dana"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := tr.Steps[1]; got.Action.Op != "write_page" || got.Cost != 2_000 || got.Tokens != 100 {
		t.Fatalf("the approved step was priced %d tokens and %d", got.Tokens, got.Cost)
	}
	var sum int64
	for _, st := range tr.Steps {
		sum += st.Cost
	}
	if sum != tr.Spent.Cost {
		t.Errorf("the steps add up to %d and the run spent %d", sum, tr.Spent.Cost)
	}
}

// A run that stops to ask keeps what it spent: its money budget is not
// refilled by the pause.
func TestAPauseDoesNotRefillTheMoneyBudget(t *testing.T) {
	m := drafter()
	m.Budget.Money = "0.003"
	var s *Session
	p := &pricedDecider{scripted: scripted{plan: []Action{{Op: "read_page"}, write, {Op: "read_page"}}},
		s: &s, micros: 2_000}
	r := Runner{Decide: p.decide, Perform: (&doer{}).perform, Pause: true}
	s = NewSession(m, nil)
	first, err := r.Run(context.Background(), s, "tidy")
	if err != nil {
		t.Fatal(err)
	}
	s = NewSession(m, nil)
	tr, err := r.Continue(context.Background(), s, first, &Verdict{N: 2, Approve: true, By: "dana"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tr.Stopped, "budget") {
		t.Fatalf("spending 0.006 against a 0.003 budget went on after the pause: %q", tr.Stopped)
	}
}

// looker may call one tool and write a page, and asks a person before it
// writes.
func looker() Manifest {
	return Manifest{Name: "looker", Kind: KindTask, Purpose: "look things up",
		Capabilities: []string{"write_page"},
		Tools:        []Tool{{Name: "lookup", Host: "api.example", Purpose: "look up"}},
		Autonomy:     AutonomyDraft, AskFirst: []string{"write_page"},
		Budget: Budget{Steps: 3, Tools: 10, Duration: Duration(time.Minute)}}
}

// chargedSteps counts the steps of a run the gate let through, which is what
// its step budget bounds: every allowed action but the answer.
func chargedSteps(tr Trace) int {
	n := 0
	for _, st := range tr.Steps {
		if st.Allowed && !st.Action.Done() {
			n++
		}
	}
	return n
}

// A tool call costs a step as well as a tool use, and pausing for a person
// gave the step back: the spend was recounted from the steps as tool uses
// alone, so a run whose model chose an action that asks first, whenever it
// liked, went on with its step budget refilled.
func TestPausingDoesNotGiveBackTheStepsToolCallsCost(t *testing.T) {
	lookup := Action{Tool: "lookup"}
	p := &scripted{plan: []Action{lookup, lookup, write, lookup, lookup, lookup}}
	r := Runner{Decide: p.decide, Perform: (&doer{}).perform, Pause: true}
	first, err := r.Run(context.Background(), NewSession(looker(), nil), "g")
	if err != nil {
		t.Fatal(err)
	}
	if first.Waiting == nil || first.Spent.Steps != 2 || first.Spent.Tools != 2 {
		t.Fatalf("the run did not stop to ask after two lookups: %+v %+v", first.Waiting, first.Spent)
	}
	s := NewSession(looker(), nil)
	tr, err := r.Continue(context.Background(), s, first,
		&Verdict{N: first.Waiting.N, Approve: true, By: "dana"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n := chargedSteps(tr); n > 3 {
		t.Errorf("%d steps were let through against a step budget of 3, by pausing once", n)
	}
	if steps, tools, _ := s.Spent(); steps != 3 || tools < 2 {
		t.Errorf("after continuing the run has spent steps=%d tools=%d", steps, tools)
	}
}

// What a delegate spent lands on its supervisor's budget, and pausing for a
// person forgot it: a delegation was recounted as one step, so the tool
// calls its delegate made were available again once a person approved
// anything.
func TestPausingDoesNotForgetWhatADelegateSpent(t *testing.T) {
	m := Manifest{Name: "boss", Kind: KindSupervisor, Purpose: "hand work on",
		Capabilities: []string{"write_page"}, Delegates: []string{"helper"},
		Tools:    []Tool{{Name: "lookup", Host: "api.example", Purpose: "look up"}},
		Autonomy: AutonomyDraft, AskFirst: []string{"write_page"},
		Budget: Budget{Steps: 10, Tools: 3, Duration: Duration(time.Minute)}}
	calls := 0
	perform := func(_ context.Context, a Action) (string, error) {
		if a.Tool != "" {
			calls++
		}
		return "did it", nil
	}
	var parent *Session
	delegating := func(ctx context.Context, a Action) (string, error) {
		if a.Delegate == "" {
			return perform(ctx, a)
		}
		// The delegate spends the whole of the tool budget, as Fold
		// brings back to its supervisor.
		child := NewSession(m, nil)
		for child.MayCallTool("lookup", "") == nil {
			calls++
		}
		parent.Fold(child)
		return "handed on", nil
	}
	lookup := Action{Tool: "lookup"}
	p := &scripted{plan: []Action{{Delegate: "helper", Say: "look it up"}, write, lookup, lookup, lookup}}
	r := Runner{Decide: p.decide, Perform: delegating, Pause: true}
	parent = NewSession(m, nil)
	first, err := r.Run(context.Background(), parent, "g")
	if err != nil {
		t.Fatal(err)
	}
	if first.Waiting == nil || first.Spent.Tools != 3 {
		t.Fatalf("the run did not stop to ask with the tools spent: %+v %+v", first.Waiting, first.Spent)
	}
	parent = NewSession(m, nil)
	if _, err := r.Continue(context.Background(), parent, first,
		&Verdict{N: first.Waiting.N, Approve: true, By: "dana"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if calls > 3 {
		t.Errorf("%d tool calls were made against a tool budget of 3, by pausing once", calls)
	}
}

// A decider's question was asked, and its step charged, before the run
// stopped for a person; answering it charges that step once and not twice.
func TestAnsweringAQuestionChargesItsStepOnce(t *testing.T) {
	p := &scripted{plan: []Action{{Op: "read_page"}, {Op: "decide", Input: map[string]any{"name": "refunds"}}}}
	r := Runner{Decide: p.decide, Perform: unsure, Pause: true}
	first, err := r.Run(context.Background(), NewSession(asker2(), nil), "triage ticket 12")
	if err != nil {
		t.Fatal(err)
	}
	if first.Waiting == nil || first.Spent.Steps != 2 {
		t.Fatalf("the run did not stop at the question with two steps spent: %+v %+v", first.Waiting, first.Spent)
	}
	s := NewSession(asker2(), nil)
	tr, err := r.Continue(context.Background(), s, first,
		&Verdict{N: first.Waiting.N, Approve: true, By: "dana", Answers: map[string]string{"eligible": "no"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if steps, _, _ := s.Spent(); steps != chargedSteps(tr) {
		t.Errorf("the run let %d steps through and charged %d", chargedSteps(tr), steps)
	}
}

// A tool that writes is asked about first at propose autonomy, whatever the
// declaration's ask_first says, and is refused where nobody can be asked.
//
// Propose writes nothing: write_page is refused at it. A tool marked as
// changing something on the far side was gated on its host and the budget
// alone, so a propose-only agent called it with nobody asked. A tool that
// only reads still goes ahead, and at draft the writing tool does too, as
// write_page does.
func TestAWritingToolAsksFirstAtProposeAutonomy(t *testing.T) {
	m := Manifest{Name: "filer", Kind: KindTask, Purpose: "file issues",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyPropose,
		Tools: []Tool{{Name: "notes", Host: "notes.example", Purpose: "read notes"},
			{Name: "delete_everything", Host: "notes.example", Purpose: "tidy", Writes: true}},
		Budget: Budget{Steps: 6, Tools: 4, Duration: Duration(time.Minute)}}
	if err := m.Validate(nil); err != nil {
		t.Fatal(err)
	}
	var did []string
	called := func(_ context.Context, a Action) (string, error) { did = append(did, a.Tool); return "ok", nil }
	tools := func() string { return strings.Join(did, ",") }
	plan := []Action{{Tool: "notes"}, {Tool: "delete_everything"}}
	reset := func() { did = nil }

	r := Runner{Decide: (&scripted{plan: plan}).decide, Perform: called, Pause: true}
	tr, err := r.Run(context.Background(), NewSession(m, nil), "g")
	if err != nil {
		t.Fatal(err)
	}
	if tr.Waiting == nil || tr.Waiting.Action.Tool != "delete_everything" || len(did) != 1 {
		t.Fatalf("the writing tool was not asked about first: did %s, %+v", tools(), tr.Waiting)
	}

	// With nobody to ask, as a delegate has, it is refused.
	reset()
	r = Runner{Decide: (&scripted{plan: plan}).decide, Perform: called}
	tr, _ = r.Run(context.Background(), NewSession(m, nil), "g")
	if len(did) != 1 || tr.Steps[1].Allowed || !strings.Contains(tr.Steps[1].Why, "nobody to ask") {
		t.Fatalf("with nobody to ask the writing tool: did %s, %+v", tools(), tr.Steps[1])
	}

	// At draft it goes ahead.
	m.Autonomy = AutonomyDraft
	reset()
	r = Runner{Decide: (&scripted{plan: plan}).decide, Perform: called, Pause: true}
	if tr, _ = r.Run(context.Background(), NewSession(m, nil), "g"); tr.Waiting != nil || len(did) != 2 {
		t.Fatalf("at draft: did %s, %+v", tools(), tr.Waiting)
	}
}
