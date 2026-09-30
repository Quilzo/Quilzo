// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

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
