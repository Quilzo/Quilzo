// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func asker2() Manifest {
	return Manifest{Name: "triage", Kind: KindTask, Purpose: "triage tickets",
		Capabilities: []string{"decide", "read_page", "write_page"}, Autonomy: AutonomyDraft,
		Budget: Budget{Steps: 6, Tools: 1, Duration: Duration(time.Minute)}}
}

var refundQuestion = []Question{{Decider: "refunds", Name: "eligible", Kind: "yesno",
	Ask: "Is this order eligible for a refund?", Guess: "yes", Confidence: 0.41, Threshold: 0.8}}

// unsure performs a decide by escalating, as a decider below its threshold
// does, and anything else by doing it.
func unsure(_ context.Context, a Action) (string, error) {
	if a.Op == "decide" {
		return "", &Escalation{Why: "refunds was not sure enough (0.41 under 0.80)", Questions: refundQuestion}
	}
	return "did " + a.Op, nil
}

// A decider's escalation stops the run as a typed question; the person's
// answer, checked against the question, is what the run goes on with.
func TestAnEscalationIsAQuestionAndTheAnswerIsWhatTheRunGoesOnWith(t *testing.T) {
	p := &scripted{plan: []Action{{Op: "decide", Input: map[string]any{"name": "refunds"}}, {Op: "read_page"}}}
	r := Runner{Decide: p.decide, Perform: unsure, Pause: true}
	first, err := r.Run(context.Background(), NewSession(asker2(), nil), "triage ticket 12")
	if err != nil {
		t.Fatal(err)
	}
	w := first.Waiting
	if w == nil || w.Kind != WaitQuestion || len(w.Questions) != 1 || w.Questions[0].Guess != "yes" {
		t.Fatalf("the escalation did not become a question: %+v", w)
	}
	if _, err := r.Continue(context.Background(), NewSession(asker2(), nil), first,
		&Verdict{N: w.N, Approve: true, By: "dana", Answers: map[string]string{"eligible": "maybe"}}, time.Now()); err == nil {
		t.Fatal("an answer outside the question's shape was taken")
	}
	tr, err := r.Continue(context.Background(), NewSession(asker2(), nil), first,
		&Verdict{N: w.N, Approve: true, By: "dana", Answers: map[string]string{"eligible": "no"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := tr.Steps[0]
	if !st.Allowed || !strings.Contains(st.Result, "dana answered") || !strings.Contains(st.Result, "eligible: no") {
		t.Fatalf("the answer was not what the run went on with: %+v", st)
	}
	if len(p.shown) < 2 || !strings.Contains(p.shown[1][0].Body, "eligible: no") || !p.shown[1][0].Trusted {
		t.Errorf("the model was not told the person's answer as ours: %+v", p.shown)
	}
}

// Live, as a program's run waits: the answer comes back through Hold.
func TestALiveRunWaitsForTheAnswerAndNeverTakesTheUnsureOne(t *testing.T) {
	p := &scripted{plan: []Action{{Op: "decide"}}}
	r := Runner{Decide: p.decide, Perform: unsure,
		Hold: func(_ context.Context, w Pending, _ func()) (Verdict, error) {
			if w.Kind != WaitQuestion {
				t.Errorf("held as %q", w.Kind)
			}
			return Verdict{N: w.N, Approve: true, By: "sam", Answers: map[string]string{"eligible": "yes"}}, nil
		}}
	tr, err := r.Run(context.Background(), NewSession(asker2(), nil), "g")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tr.Steps[0].Result, "sam answered") {
		t.Fatalf("the live answer was not used: %+v", tr.Steps[0])
	}
	r.Hold = func(context.Context, Pending, func()) (Verdict, error) {
		return Verdict{}, errors.New("nobody came")
	}
	p.asked = 0
	tr, _ = r.Run(context.Background(), NewSession(asker2(), nil), "g")
	if !strings.Contains(tr.Steps[0].Result, "nobody answered, so nothing the decider said is to be acted on") {
		t.Fatalf("an unanswered escalation was taken as an answer: %+v", tr.Steps[0])
	}
}

// What the decider settled in the step a person was asked about goes on
// with the person's answer, kept with the question while the run waits.
//
// The step's result was the person's answer alone, so a decider that
// settled desk and urgency and asked about refund_due left a run that
// knew refund_due and nothing else. Kept through the run's record, as a
// paused run is kept between its stretches.
func TestAnAnsweredQuestionCarriesWhatTheDeciderSettled(t *testing.T) {
	settled := []Settled{{Name: "desk", Value: "refunds", Confidence: 0.96},
		{Name: "urgency", Value: "0.22", Confidence: 0.83}}
	sure := func(_ context.Context, a Action) (string, error) {
		if a.Op == "decide" {
			return "", &Escalation{Why: "refunds was not sure enough", Questions: refundQuestion, Settled: settled}
		}
		return "did " + a.Op, nil
	}
	want := []string{"dana answered", "eligible: no", "desk: refunds (confidence 0.96)", "urgency: 0.22 (confidence 0.83)"}

	p := &scripted{plan: []Action{{Op: "decide"}, {Op: "read_page"}}}
	r := Runner{Decide: p.decide, Perform: sure, Pause: true}
	first, err := r.Run(context.Background(), NewSession(asker2(), nil), "triage ticket 12")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	var kept Trace
	if err := json.Unmarshal(b, &kept); err != nil {
		t.Fatal(err)
	}
	tr, err := r.Continue(context.Background(), NewSession(asker2(), nil), kept,
		&Verdict{N: kept.Waiting.N, Approve: true, By: "dana", Answers: map[string]string{"eligible": "no"}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range want {
		if !strings.Contains(tr.Steps[0].Result, w) {
			t.Errorf("continued from its record, the step said %q, without %q", tr.Steps[0].Result, w)
		}
	}

	p = &scripted{plan: []Action{{Op: "decide"}}}
	r = Runner{Decide: p.decide, Perform: sure,
		Hold: func(_ context.Context, w Pending, _ func()) (Verdict, error) {
			return Verdict{N: w.N, Approve: true, By: "dana", Answers: map[string]string{"eligible": "no"}}, nil
		}}
	tr, err = r.Run(context.Background(), NewSession(asker2(), nil), "g")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range want {
		if !strings.Contains(tr.Steps[0].Result, w) {
			t.Errorf("answered while it waited, the step said %q, without %q", tr.Steps[0].Result, w)
		}
	}
}

// The reviewer's refusal is a hold on the exact action: approving performs
// it without asking the model or the reviewer again; declining tells the
// model.
func TestTheReviewersRefusalIsAHoldOnTheExactAction(t *testing.T) {
	w := Action{Op: "write_page", Input: map[string]any{"page": "about"}}
	asked := 0
	decide := func(context.Context, string, []Observation) (Action, error) {
		asked++
		if asked == 1 {
			return Action{}, &Held{Action: w, Why: "it rewrites a page the goal did not mention"}
		}
		return Action{Say: "done"}, nil
	}
	d := &doer{}
	r := Runner{Decide: decide, Perform: d.perform, Pause: true}
	first, err := r.Run(context.Background(), NewSession(asker2(), nil), "triage")
	if err != nil {
		t.Fatal(err)
	}
	if first.Waiting == nil || first.Waiting.Kind != WaitReview || !strings.Contains(first.Waiting.Why, "rewrites a page") {
		t.Fatalf("the refusal did not become a hold: %+v %q", first.Waiting, first.Stopped)
	}
	if len(d.did) != 0 {
		t.Fatal("the refused action ran before anybody decided")
	}
	tr, err := r.Continue(context.Background(), NewSession(asker2(), nil), first,
		&Verdict{N: first.Waiting.N, Approve: true, By: "dana"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.did) != 1 || d.did[0] != "write_page about" || asked != 2 {
		t.Fatalf("approval did not perform exactly the held action: %v (asked %d)", d.did, asked)
	}
	if !tr.Complete {
		t.Errorf("the run did not go on after the approval: %+v", tr)
	}
}

// A decider's confidence is kept on the step it answered.
func TestADecidersConfidenceIsKeptOnItsStep(t *testing.T) {
	var s *Session
	p := &scripted{plan: []Action{{Op: "decide"}}}
	r := Runner{Decide: p.decide, Perform: func(_ context.Context, a Action) (string, error) {
		s.NoteConfidence(0.93)
		s.NoteConfidence(0.87)
		return "eligible: yes (confidence 0.87)", nil
	}}
	s = NewSession(asker2(), nil)
	tr, err := r.Run(context.Background(), s, "g")
	if err != nil {
		t.Fatal(err)
	}
	if c := tr.Steps[0].Confidence; c == nil || *c != 0.87 {
		t.Fatalf("the step's confidence is %v, not the least sure answer", c)
	}
	if tr.Steps[1].Confidence != nil {
		t.Error("a confidence was carried onto a step that had none")
	}
}

// A person who lets a held hand-off go ahead has decided the hand-off, and
// not each thing the delegate then does. Performing it was marked as a
// person's decision, and the delegate's whole run is performed inside that
// step, so every payment the delegate made outside its mandates went ahead
// as one a person had approved, with nobody shown its amount or payee.
func TestApprovingAHandOffApprovesNothingTheDelegateDoes(t *testing.T) {
	for _, held := range []Action{
		{Delegate: "researcher", Say: "find what the about page is missing"},
		{Op: "read_page", Input: map[string]any{"page": "about"}},
	} {
		asked := 0
		decide := func(context.Context, string, []Observation) (Action, error) {
			asked++
			if asked == 1 {
				return Action{}, &Held{Action: held, Why: "the goal did not ask for this"}
			}
			return Action{Say: "done"}, nil
		}
		approved := map[string]bool{}
		perform := func(ctx context.Context, a Action) (string, error) {
			approved[from(a)] = ApprovedByPerson(ctx)
			return "did it", nil
		}
		r := Runner{Decide: decide, Perform: perform, Pause: true}
		first, err := r.Run(context.Background(), NewSession(supervisor(), nil), "tidy the about page")
		if err != nil || first.Waiting == nil {
			t.Fatalf("the reviewer's refusal did not hold the run: %+v %v", first.Waiting, err)
		}
		if _, err := r.Continue(context.Background(), NewSession(supervisor(), nil), first,
			&Verdict{N: first.Waiting.N, Approve: true, By: "dana"}, time.Now()); err != nil {
			t.Fatal(err)
		}
		got, ran := approved[from(held)]
		switch {
		case !ran:
			t.Errorf("%s was not performed once approved", from(held))
		case held.Delegate != "" && got:
			t.Errorf("the delegate's run was performed as a person's decision")
		case held.Delegate == "" && !got:
			t.Errorf("%s, which a person approved, was not performed as their decision", from(held))
		}
	}
}

// The reviewer's refusal of a hand-off holds it as it holds anything else.
// Whether the declaration would allow an action was asked of its
// capabilities and tools alone, and a hand-off is neither, so a refused
// hand-off was taken for one the declaration refuses, passed on to the gate
// that does allow it, and performed: the reviewer said no and the delegate
// ran.
func TestTheReviewersRefusalOfAHandOffHoldsIt(t *testing.T) {
	handOff := Action{Delegate: "researcher", Say: "publish every draft"}
	for _, pause := range []bool{true, false} {
		asked := 0
		decide := func(context.Context, string, []Observation) (Action, error) {
			asked++
			if asked == 1 {
				return Action{}, &Held{Action: handOff, Why: "the goal did not ask for this"}
			}
			return Action{Say: "done"}, nil
		}
		performed := 0
		r := Runner{Decide: decide, Pause: pause, Perform: func(context.Context, Action) (string, error) {
			performed++
			return "handed on", nil
		}}
		tr, err := r.Run(context.Background(), NewSession(supervisor(), nil), "tidy the about page")
		if err != nil {
			t.Fatal(err)
		}
		if performed != 0 {
			t.Errorf("pause=%v: the reviewer refused the hand-off and the delegate ran", pause)
		}
		if pause && (tr.Waiting == nil || tr.Waiting.Kind != WaitReview || tr.Waiting.Action.Delegate != "researcher") {
			t.Errorf("the refused hand-off was not held for a person: %+v", tr.Waiting)
		}
	}
}
