// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// runSpy records what the executor asked a delegate to do.
type runSpy struct {
	calls       int
	name        string
	instruction string
	held        agent.Manifest
	read        bool
	answer      string
	err         error
}

func (r *runSpy) Run(_ context.Context, name string, child *agent.Session,
	instruction string) (string, error) {
	r.calls++
	r.name = name
	r.instruction = instruction
	r.held = child.Manifest()
	if r.read {
		// A delegate that reads stored content, which is how the interesting
		// half of this works.
		_ = child.Retrieve("live", "about", "", "")
	}
	if r.err != nil {
		return "", r.err
	}
	if r.answer == "" {
		return "done", nil
	}
	return r.answer, nil
}

func lead() agent.Manifest {
	return agent.Manifest{
		Name: "lead", Kind: agent.KindSupervisor, Purpose: "decompose",
		Capabilities: []string{"read_page", "list_pages"},
		Autonomy:     agent.AutonomyDraft,
		Delegates:    []string{"researcher"},
		Budget: agent.Budget{
			Steps: 10, Tools: 5, Duration: agent.Duration(time.Hour)},
	}
}

func researcher() agent.Manifest {
	return agent.Manifest{
		Name: "researcher", Kind: agent.KindRetrieval, Purpose: "find",
		Capabilities: []string{"read_page", "list_pages", "publish"},
		Autonomy:     agent.AutonomyPublish,
		Budget: agent.Budget{
			Steps: 99, Tools: 99, Duration: agent.Duration(time.Hour)},
	}
}

func delegates(r *runSpy) Delegates {
	return Delegates{
		Manifest: func(name string) (agent.Manifest, error) {
			if name != "researcher" {
				return agent.Manifest{}, fmt.Errorf("no agent called %q", name)
			}
			return researcher(), nil
		},
		Run: r,
	}
}

func TestADelegationReachesTheDelegate(t *testing.T) {
	r := &runSpy{}
	s := agent.NewSession(lead(), nil)
	perform := delegates(r).Perform(s)

	out, err := perform(context.Background(), agent.Action{
		Delegate: "researcher", Say: "find the returns page",
	})
	if err != nil {
		t.Fatalf("a declared delegate was not reached: %v", err)
	}
	if r.calls != 1 {
		t.Fatalf("the delegate ran %d time(s)", r.calls)
	}
	if r.name != "researcher" {
		t.Errorf("the executor ran %q", r.name)
	}
	if r.instruction != "find the returns page" {
		t.Errorf("the delegate was told %q", r.instruction)
	}
	if out != "done" {
		t.Errorf("the answer is %q", out)
	}
}

func TestAnUndeclaredDelegateIsRefusedBeforeAnythingIsLoaded(t *testing.T) {
	r := &runSpy{}
	s := agent.NewSession(lead(), nil)
	perform := delegates(r).Perform(s)

	_, err := perform(context.Background(), agent.Action{Delegate: "admin"})
	if err == nil {
		t.Fatal("a supervisor handed work to an agent it never declared")
	}
	if r.calls != 0 {
		t.Fatal("the manifest was loaded and the delegate was run before the " +
			"gate had answered")
	}
	if len(s.Refusals()) != 1 {
		t.Fatalf("%d refusal(s) recorded; the attempt is the finding",
			len(s.Refusals()))
	}
}

func TestTheDelegateRunsTheIntersectionAndNotItsOwnDeclaration(t *testing.T) {
	// researcher declares publish and publish autonomy; lead holds neither.
	// If the child ran as declared, a supervisor would be a way to launder
	// capability.
	r := &runSpy{}
	s := agent.NewSession(lead(), nil)
	perform := delegates(r).Perform(s)

	if _, err := perform(context.Background(), agent.Action{
		Delegate: "researcher", Say: "go",
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.held.Capabilities {
		if c == "publish" {
			t.Fatal("the delegate ran holding publish, which its supervisor " +
				"does not hold")
		}
	}
	if !r.held.Autonomy.AtMost(lead().Autonomy) {
		t.Fatalf("the delegate ran at %s under a supervisor at %s",
			r.held.Autonomy, lead().Autonomy)
	}
}

func TestTheDelegateGetsWhatIsLeftRatherThanWhatWasDeclared(t *testing.T) {
	r := &runSpy{}
	s := agent.NewSession(lead(), nil)
	perform := delegates(r).Perform(s)
	for i := 0; i < 6; i++ {
		if err := s.Authorize("read_page"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := perform(context.Background(), agent.Action{
		Delegate: "researcher", Say: "go",
	}); err != nil {
		t.Fatal(err)
	}
	// Six spent, one more for the delegation itself, so three remain.
	if r.held.Budget.Steps != 3 {
		t.Fatalf("the delegate was given %d step(s) with 3 left of the "+
			"supervisor's ten. Handing out the declared budget means a "+
			"supervisor with three delegates has three times its ceiling",
			r.held.Budget.Steps)
	}
}

func TestNothingIsHandedOnceTheBudgetIsGone(t *testing.T) {
	m := lead()
	m.Budget.Steps = 1
	r := &runSpy{}
	s := agent.NewSession(m, nil)
	perform := delegates(r).Perform(s)

	// The one step goes on the delegation itself, leaving nothing to give.
	_, err := perform(context.Background(), agent.Action{
		Delegate: "researcher", Say: "go",
	})
	if err == nil {
		t.Fatal("a delegate was started with no budget to spend")
	}
	if r.calls != 0 {
		t.Fatal("the delegate ran on an empty budget")
	}
}

func TestADelegateThatReadTaintsTheSupervisor(t *testing.T) {
	r := &runSpy{read: true}
	s := agent.NewSession(lead(), nil)
	perform := delegates(r).Perform(s)

	if _, err := perform(context.Background(), agent.Action{
		Delegate: "researcher", Say: "go",
	}); err != nil {
		t.Fatal(err)
	}
	if !s.Tainted() {
		t.Fatal("a delegate read stored content and the supervisor came back " +
			"clean. That is the taint rule defeated by one indirection: read " +
			"through a delegate, receive a string, publish")
	}
}

func TestADelegateThatFailedStillCosts(t *testing.T) {
	// A parent that only inherited from successful children would be a parent
	// that can read untrusted content by arranging to fail.
	r := &runSpy{read: true, err: fmt.Errorf("the far side went away")}
	s := agent.NewSession(lead(), nil)
	perform := delegates(r).Perform(s)

	if _, err := perform(context.Background(), agent.Action{
		Delegate: "researcher", Say: "go",
	}); err == nil {
		t.Fatal("a failing delegate reported success")
	}
	if !s.Tainted() {
		t.Fatal("a delegate read stored content, then failed, and the " +
			"supervisor came back clean")
	}
}

func TestAnUnwiredDelegateSurfaceSaysSo(t *testing.T) {
	// The failure this whole change exists to stop: a declared thing whose
	// executor is absent, reported as though the agent behaved correctly.
	s := agent.NewSession(lead(), nil)
	perform := Delegates{}.Perform(s)
	_, err := perform(context.Background(), agent.Action{
		Delegate: "researcher", Say: "go",
	})
	if err == nil {
		t.Fatal("an unwired delegate surface reported success")
	}
	if !strings.Contains(err.Error(), "cannot run one") {
		t.Errorf("the error does not say the surface is missing: %v", err)
	}
}

func TestDispatchRoutesADelegation(t *testing.T) {
	// The bug in one line. Action.Delegate has no Op, so agent.IsWrite said
	// false and the reader answered "is permitted for this agent and not
	// implemented here" — for every delegation this program could authorise.
	r := &runSpy{}
	st := searchStore(t)
	s := agent.NewSession(lead(), nil)
	perform := Dispatch(
		Reader{Store: st}, Writer{Store: st, Author: "agent/lead"},
		Tools{}, delegates(r), s)

	out, err := perform(context.Background(), agent.Action{
		Delegate: "researcher", Say: "go",
	})
	if err != nil {
		t.Fatalf("a delegation did not reach the executor: %v", err)
	}
	if out != "done" || r.calls != 1 {
		t.Errorf("the answer is %q after %d call(s)", out, r.calls)
	}
	// And an ordinary read still goes to the reader.
	if _, err := perform(context.Background(),
		agent.Action{Op: "list_pages"}); err != nil &&
		strings.Contains(err.Error(), "not implemented") {
		t.Errorf("an ordinary read stopped reaching the reader: %v", err)
	}
}

func TestAnInstructionIsBounded(t *testing.T) {
	// The one part of a delegation a model composes freely.
	r := &runSpy{}
	s := agent.NewSession(lead(), nil)
	perform := delegates(r).Perform(s)
	if _, err := perform(context.Background(), agent.Action{
		Delegate: "researcher", Say: strings.Repeat("a", MaxInstruction*4),
	}); err != nil {
		t.Fatal(err)
	}
	if len(r.instruction) > MaxInstruction {
		t.Fatalf("the delegate was handed %d bytes of instruction",
			len(r.instruction))
	}
}

func TestTheExecutorReportsThatItPerformsDelegations(t *testing.T) {
	if !PerformsDelegates() {
		t.Fatal("the surface says it does not exist")
	}
}
