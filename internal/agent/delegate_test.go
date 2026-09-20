// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"strings"
	"testing"
	"time"
)

func supervisor() Manifest {
	return Manifest{
		Name: "lead", Kind: KindSupervisor, Purpose: "decompose",
		Capabilities: []string{"read_page", "list_pages"},
		Autonomy:     AutonomyDraft,
		Delegates:    []string{"researcher", "checker"},
		Budget:       Budget{Steps: 10, Tools: 5, Duration: Duration(time.Hour)},
	}
}

func TestOnlyASupervisorMayDelegateAtRunTime(t *testing.T) {
	// Validation already refuses a non-supervisor that *declares* delegates.
	// This is the other end: a manifest edited after it was validated, or one
	// narrowed into a different kind, still cannot hand work onward.
	//
	// Any agent being able to hand work onward would mean any agent could
	// reach any other agent's capabilities, which is the restriction on all
	// of them made optional.
	m := supervisor()
	m.Kind = KindRetrieval
	s := NewSession(m, nil)
	err := s.MayDelegate("researcher")
	if err == nil {
		t.Fatal("a retrieval agent handed work to another agent")
	}
	if !strings.Contains(err.Error(), "supervisor") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

func TestOnlyANamedDelegateIsAccepted(t *testing.T) {
	// The graph is named in the manifest so that it is reviewable and a
	// supervisor that has been talked into something cannot invent a worker.
	s := NewSession(supervisor(), nil)
	if err := s.MayDelegate("researcher"); err != nil {
		t.Fatalf("a declared delegate was refused: %v", err)
	}
	err := s.MayDelegate("admin")
	if err == nil {
		t.Fatal("a supervisor handed work to an agent it never declared")
	}
	// The refusal names the list, because an operator reading it is trying to
	// find out what the pipeline is.
	if !strings.Contains(err.Error(), "researcher") ||
		!strings.Contains(err.Error(), "checker") {
		t.Errorf("the refusal does not name the list: %v", err)
	}
}

func TestDelegatingSpendsTheSupervisorsBudget(t *testing.T) {
	// A supervisor that could delegate for free would have an unbounded
	// budget with extra steps.
	s := NewSession(supervisor(), nil)
	before, _, _ := s.Spent()
	if err := s.MayDelegate("researcher"); err != nil {
		t.Fatal(err)
	}
	after, _, _ := s.Spent()
	if after != before+1 {
		t.Fatalf("delegating moved the step count from %d to %d", before, after)
	}
}

func TestARefusedDelegationCostsNothing(t *testing.T) {
	s := NewSession(supervisor(), nil)
	_ = s.MayDelegate("admin")
	if steps, _, _ := s.Spent(); steps != 0 {
		t.Fatalf("a refused delegation spent %d step(s); a refusal is not "+
			"work and charging for it makes a budget a thing an attacker "+
			"can exhaust by asking for things", steps)
	}
	if len(s.Refusals()) != 1 {
		t.Fatalf("%d refusal(s) recorded; the attempt is the finding",
			len(s.Refusals()))
	}
}

func TestTheBudgetOfferedToADelegateIsWhatIsLeft(t *testing.T) {
	// Narrow compares two totals, which is the right question about two
	// manifests and the wrong one about a run in progress: a supervisor with
	// ten steps and three delegates declaring ten each would hand out thirty.
	s := NewSession(supervisor(), nil)
	for i := 0; i < 4; i++ {
		if err := s.Authorize("read_page"); err != nil {
			t.Fatal(err)
		}
	}
	left := s.Remaining()
	if left.Steps != 6 {
		t.Fatalf("after four steps of ten, %d are left", left.Steps)
	}
	if left.Duration <= 0 || left.Duration >= Duration(time.Hour) {
		t.Fatalf("the remaining duration is %s, and some of the hour has gone",
			time.Duration(left.Duration))
	}
}

func TestNothingRemainsOnceTheBudgetIsSpent(t *testing.T) {
	m := supervisor()
	m.Budget.Steps = 2
	s := NewSession(m, nil)
	for i := 0; i < 2; i++ {
		_ = s.Authorize("read_page")
	}
	if left := s.Remaining(); left.Steps != 0 {
		t.Fatalf("a spent budget has %d step(s) left", left.Steps)
	}
}

// -- folding a child back ----------------------------------------------------

func delegateSession(t *testing.T) *Session {
	t.Helper()
	return NewSession(Manifest{
		Name: "researcher", Kind: KindRetrieval, Purpose: "find",
		Capabilities: []string{"read_page"}, Autonomy: AutonomyPropose,
		Budget: Budget{Steps: 5, Tools: 2, Duration: Duration(time.Hour)},
	}, nil)
}

func TestADelegatesTaintIsTheSupervisorsTaint(t *testing.T) {
	// The hole this closes. Without it, a supervisor reads untrusted content
	// through a delegate, receives it as an ordinary string, and publishes —
	// the taint rule defeated by one indirection it never looked at.
	parent := NewSession(supervisor(), nil)
	child := delegateSession(t)
	if err := child.Retrieve("live", "about", "", ""); err != nil {
		t.Fatalf("the delegate could not read: %v", err)
	}
	if !child.Tainted() {
		t.Fatal("reading stored content did not taint the delegate")
	}
	if parent.Tainted() {
		t.Fatal("the supervisor was tainted before anything came back")
	}
	parent.Fold(child)
	if !parent.Tainted() {
		t.Fatal("a delegate read untrusted content and the supervisor came " +
			"back clean, which is the taint rule defeated by an indirection")
	}
}

func TestASupervisorThatDelegatedAReadCannotPublish(t *testing.T) {
	m := supervisor()
	m.Autonomy = AutonomyPublish
	m.HumanApproval = false
	parent := NewSession(m, nil)
	if ok, _ := parent.Publishable(); !ok {
		t.Skip("this manifest cannot publish for an unrelated reason")
	}
	child := delegateSession(t)
	_ = child.Retrieve("live", "about", "", "")
	parent.Fold(child)
	ok, why := parent.Publishable()
	if ok {
		t.Fatal("a supervisor published work its delegate produced from " +
			"content somebody else may have written")
	}
	if !strings.Contains(strings.ToLower(why), "read") {
		t.Errorf("the reason does not name the read: %s", why)
	}
}

func TestWhatADelegateSpentIsSpent(t *testing.T) {
	parent := NewSession(supervisor(), nil)
	child := delegateSession(t)
	for i := 0; i < 3; i++ {
		_ = child.Authorize("read_page")
	}
	before, _, _ := parent.Spent()
	parent.Fold(child)
	after, _, _ := parent.Spent()
	if after != before+3 {
		t.Fatalf("the child spent 3 and the parent went from %d to %d. A "+
			"supervisor whose children cost it nothing could spend any "+
			"amount by spreading it", before, after)
	}
}

func TestADelegatesRefusalsComeBack(t *testing.T) {
	// "The agent was refused four times" is what an operator reads
	// afterwards, and a refusal one level down is still a refusal this run
	// caused.
	parent := NewSession(supervisor(), nil)
	child := delegateSession(t)
	_ = child.Authorize("publish")
	if len(child.Refusals()) == 0 {
		t.Fatal("the delegate was not refused an operation it does not hold")
	}
	parent.Fold(child)
	if len(parent.Refusals()) != 1 {
		t.Fatalf("the supervisor holds %d refusal(s) after folding one in",
			len(parent.Refusals()))
	}
}

func TestFoldingNothingIsSafe(t *testing.T) {
	parent := NewSession(supervisor(), nil)
	parent.Fold(nil)
	parent.Fold(parent)
	if steps, _, _ := parent.Spent(); steps != 0 {
		t.Fatalf("folding a session into itself doubled its spend to %d", steps)
	}
}

// -- the run loop ------------------------------------------------------------

func TestADelegationIsNotTheEndOfTheRun(t *testing.T) {
	// Done() is Op == "" && Tool == "", and a delegation names neither. So a
	// supervisor's first hand-off ended the run and the answer was whatever
	// it had said to the delegate — which reads exactly like a supervisor
	// with nothing to do. The same field was missing when tools were added.
	if (Action{Delegate: "researcher", Say: "find the returns page"}).Done() {
		t.Fatal("an action handing work to another agent was treated as the " +
			"model saying it had finished")
	}
	if !(Action{Say: "finished"}).Done() {
		t.Fatal("an action with nothing but an answer is not done")
	}
	if (Action{Tool: "crm"}).Done() {
		t.Fatal("a tool call was treated as finished")
	}
	if (Action{Op: "read_page"}).Done() {
		t.Fatal("an operation was treated as finished")
	}
}

func TestADelegatesAnswerIsLabelled(t *testing.T) {
	// Concatenating Op and Tool worked while one was always empty. A
	// delegate's answer would have come back labelled with the empty string,
	// which is the one label a model cannot use to tell two results apart.
	if got := from(Action{Delegate: "researcher"}); got != "delegate/researcher" {
		t.Errorf("a delegate's answer is labelled %q", got)
	}
	if got := from(Action{Tool: "crm"}); got != "crm" {
		t.Errorf("a tool's answer is labelled %q", got)
	}
	if got := from(Action{Op: "read_page"}); got != "read_page" {
		t.Errorf("an operation's answer is labelled %q", got)
	}
}

// -- narrowing ---------------------------------------------------------------

func TestADelegateCannotHoldMoreThanItsSupervisor(t *testing.T) {
	// Otherwise a supervisor is a way to launder capability: delegate to an
	// agent that holds more, and every restriction on the supervisor was
	// decoration.
	parent := supervisor()
	child := Manifest{
		Name: "researcher", Kind: KindRetrieval, Purpose: "find",
		Capabilities: []string{"read_page", "list_pages", "publish"},
		Autonomy:     AutonomyPublish,
		Budget:       Budget{Steps: 99, Tools: 99, Duration: Duration(time.Hour)},
	}
	got := parent.Narrow(child)
	for _, c := range got.Capabilities {
		if c == "publish" {
			t.Fatal("the delegate kept a capability its supervisor does not hold")
		}
	}
	if !got.Autonomy.AtMost(parent.Autonomy) {
		t.Fatalf("the delegate's autonomy is %s and its supervisor's is %s",
			got.Autonomy, parent.Autonomy)
	}
	if got.Budget.Steps > parent.Budget.Steps {
		t.Fatalf("the delegate declared %d steps and kept them against a "+
			"supervisor holding %d", got.Budget.Steps, parent.Budget.Steps)
	}
}
