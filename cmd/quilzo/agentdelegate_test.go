// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
)

// boss hands pages to the agents it names, and handedWriter writes them.
func boss(delegates ...string) agent.Manifest {
	return agent.Manifest{Name: "boss", Kind: agent.KindSupervisor, Purpose: "Hand page writing to the writer",
		Capabilities: []string{"list_pages", "write_page"}, Autonomy: agent.AutonomyDraft,
		Delegates: delegates, Retrieval: agent.Retrieval{Ref: "draft"},
		Budget: agent.Budget{Steps: 6, Tools: 2, Duration: agent.Duration(time.Minute)}}
}

func handedWriter() agent.Manifest {
	return agent.Manifest{Name: "writer", Kind: agent.KindTask, Purpose: "Write the pages it is handed",
		Capabilities: []string{"list_pages", "write_page"}, Autonomy: agent.AutonomyDraft,
		Retrieval: agent.Retrieval{Ref: "draft"},
		Budget:    agent.Budget{Steps: 12, Tools: 2, Duration: agent.Duration(time.Minute)}}
}

// declareBoss declares the writer and a supervisor handing work to it.
func declareBoss(t *testing.T, root string, sup, del agent.Manifest) {
	t.Helper()
	for _, m := range []agent.Manifest{del, sup} {
		if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
			t.Fatal(err)
		}
	}
}

// A delegate's work is done for the person who started the run it was
// handed on from. It was done for whoever the server process's token
// named, or an unverified identity taken from the operating system, so
// the log named somebody else as the one behind the delegate, and its
// tool calls went with that somebody's connected accounts.
func TestADelegateActsForThePersonWhoStartedTheRun(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := demoStore(t)
	declareBoss(t, root, boss("writer"), handedWriter())
	if _, err := runAgentOnce(root, "boss", "", false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var run, delegated *audit.Event
	for i := range events {
		switch events[i].Action {
		case "agent.run":
			run = &events[i]
		case "agent.delegate":
			delegated = &events[i]
		}
	}
	if run == nil || delegated == nil {
		t.Fatalf("the log holds no run (%v) or no delegation (%v)", run != nil, delegated != nil)
	}
	if delegated.Principal != run.Principal || !delegated.Verified || delegated.Kind != run.Kind {
		t.Errorf("the run was dana's (%s, verified=%v) and its delegate's was %s's (verified=%v)",
			run.Principal, run.Verified, delegated.Principal, delegated.Verified)
	}
}
