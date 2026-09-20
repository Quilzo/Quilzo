// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentwatch"
	"github.com/quilzo/quilzo/internal/audit"
)

// fakeModel is enough to be one: actorRecord asks only for a name.
type fakeModel struct{}

func (fakeModel) Name() string { return "test-model" }

func (fakeModel) Complete(context.Context, string, string) (string, error) {
	return "", nil
}

func person() *Caller {
	return &Caller{Name: "dana", Kind: audit.KindHuman, Verified: true}
}

func bot() agent.Manifest {
	return agent.Manifest{Name: "support", Kind: agent.KindRetrieval}
}

func TestAModelDrivenRunIsRecordedAsTheAgent(t *testing.T) {
	// cmd/quilzo/assist.go already says why: "The model is the actor, and it
	// is recorded as one. Logging this as the human who typed the command
	// would lose the fact the log exists to preserve." The MCP surface does
	// it that way, the assistant does it that way, and the runner built for
	// agents did not.
	r := actorRecord(person(), "agent.run", audit.Success, bot(),
		fakeModel{}, map[string]string{"goal": "x"})

	if r.Kind != audit.KindAI {
		t.Errorf("a model-driven run is recorded as %s", r.Kind)
	}
	if r.Principal != "agent/support" {
		t.Errorf("the principal is %q; the watchdog buckets by it and would "+
			"merge every agent one person runs into one report", r.Principal)
	}
	if r.Model != "test-model" {
		t.Errorf("the model is %q, and the audit package refuses an AI "+
			"principal that does not name one", r.Model)
	}
	// Accountability does not move to the agent. Somebody chose to run it.
	if r.Detail["on_behalf_of"] != "dana" {
		t.Errorf("the person who ran it is recorded as %q",
			r.Detail["on_behalf_of"])
	}
}

func TestAWalkIsAPersonCheckingAManifest(t *testing.T) {
	// A run without --model is not a model acting: the plan is the manifest,
	// every capability tried once in a fixed order, and nothing chose
	// anything. Recording it as a model would also need a model name this
	// program would have to invent, and the audit package is right to refuse
	// an AI principal without one.
	r := actorRecord(person(), "agent.run", audit.Success, bot(), nil, nil)
	if r.Kind != audit.KindHuman {
		t.Errorf("a manifest walk is recorded as %s", r.Kind)
	}
	if strings.HasPrefix(r.Principal, "agent/") {
		t.Errorf("a manifest walk names %q as the actor", r.Principal)
	}
}

func TestAnUnverifiedStarterIsSaidSo(t *testing.T) {
	// The Unattributed strike is "an action recorded with no verified
	// identity behind it, from a surface that should have one". This is such
	// a surface, so the field has to be true when somebody presented a token
	// and false when nobody did — otherwise every legitimate run is flagged
	// and the signal is worth nothing.
	anon := &Caller{Name: "somebody", Kind: audit.KindUnknown,
		Why: "no token was presented"}
	r := actorRecord(anon, "agent.run", audit.Success, bot(), fakeModel{}, nil)
	if r.Verified {
		t.Error("a run nobody proved they started was recorded as verified")
	}
	if r.Detail["started_by_unverified"] == "" {
		t.Error("the record does not say why the starter was unverified")
	}

	known := actorRecord(person(), "agent.run", audit.Success, bot(),
		fakeModel{}, nil)
	if !known.Verified {
		t.Error("a run a verified person started was recorded as unattributed")
	}
}

// The failure this whole change exists to fix.
//
// internal/agentwatch reads the audit log filtered to events where the actor
// was a model, and every agent run was recorded as a human. Six runs in the
// log and `quilzo agents` said "no model has acted in the last 24h".
func TestTheWatchdogCanSeeAnAgentRun(t *testing.T) {
	now := time.Now().UTC()
	at := now.Add(-time.Minute).Format(time.RFC3339)

	// Recorded the way actorRecord records them.
	r := actorRecord(person(), "agent.run", audit.Denied, bot(), fakeModel{},
		map[string]string{"stopped": "refused"})
	events := make([]audit.Event, 0, 3)
	for i := range 3 {
		events = append(events, audit.Event{
			Seq: int64(i + 1), At: at, Action: r.Action, Resource: r.Resource,
			Outcome: r.Outcome, Principal: r.Principal, Kind: r.Kind,
			Verified: r.Verified, Model: r.Model, Detail: r.Detail,
		})
	}

	reports := agentwatch.Look(events, now)
	if len(reports) == 0 {
		t.Fatal("the watchdog cannot see an agent run at all, which is the " +
			"state this change exists to leave")
	}
	if reports[0].Principal != "agent/support" {
		t.Errorf("the watchdog reports on %q", reports[0].Principal)
	}
	if reports[0].Actions != 3 {
		t.Errorf("three runs were seen as %d actions", reports[0].Actions)
	}
	// And it must not call a verified starter unattributed.
	if n := reports[0].Counts[agentwatch.Unattributed]; n > 0 {
		t.Errorf("%d unattributed strike(s) against runs a verified person "+
			"started", n)
	}
}

// An outcome is not a bill.
func TestAnUnreachableModelIsAFailureAndNotARefusal(t *testing.T) {
	// Both call sites asked Billable and wrote Denied when it said no.
	// Billable asks "is there an outcome to charge for"; Denied means the
	// gate refused something. Three runs that could not reach the model were
	// recorded as denied, and the watchdog reported an agent repeatedly
	// refused — its signal for one that has not accepted the answer, which
	// describes a broken endpoint not at all.
	unreachable := agent.Receipt{
		Agent: "support", Complete: false,
		Stopped: "the model could not be reached",
	}
	if got := outcomeOf(unreachable); got != audit.Failure {
		t.Errorf("an unreachable model is recorded as %s", got)
	}

	refused := agent.Receipt{Agent: "support", Complete: true, Refused: 2}
	if got := outcomeOf(refused); got != audit.Denied {
		t.Errorf("a run the gate refused twice is recorded as %s", got)
	}

	worked := agent.Receipt{Agent: "support", Complete: true, Did: 3}
	if got := outcomeOf(worked); got != audit.Success {
		t.Errorf("a run that did three things is recorded as %s", got)
	}

	// Nothing refused and nothing done is a failure, not a denial: the budget
	// went, or it was cancelled.
	empty := agent.Receipt{Agent: "support", Complete: true}
	if got := outcomeOf(empty); got != audit.Failure {
		t.Errorf("a run that did nothing is recorded as %s", got)
	}
}
