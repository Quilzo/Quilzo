// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentexec"
)

// Every shipped archetype must declare only what an agent can actually do.
//
// # What this found
//
// A manifest's capabilities are validated against the MCP server's operation
// registry — twenty-five names — because that is what an agent could in
// principle be granted. The executor performs six. So seven of the eight
// archetypes shipped with capabilities that validated, appeared on the A2A
// card, and failed at runtime:
//
//	quilzo agent new a-retrieval --kind retrieval
//	quilzo agent run a-retrieval
//	  did 0, refused 0, failed 4
//	  run_listing   "run_listing" is permitted for this agent and not
//	                implemented here
//	  list_terms    "list_terms" is permitted for this agent and not
//	                implemented here
//
// The retrieval archetype could do neither of the two things beyond reading
// that its own purpose describes. The error string was honest and nothing
// read it, because there was no list to check against — the mismatch could
// only be found by running an agent and reading its failures, which is how it
// was found.
//
// # Why the archetypes move and not the executor
//
// Because an archetype is a promise about what you get, and the cheap way to
// keep a promise is to make a smaller one. Widening an archetype when the
// executor learns an operation is the safe direction; shipping one that names
// an operation nothing performs is not.
//
// This test is in an external test package so it can see both sides. That is
// the whole difficulty: internal/agent deliberately cannot reach the store, so
// it cannot import the executor, and the two could not be compared from
// either one.
func TestNoArchetypeDeclaresWhatTheExecutorCannotDo(t *testing.T) {
	performs := map[string]bool{}
	for _, op := range agentexec.Performs() {
		performs[op] = true
	}
	refuses := agentexec.Refuses()
	if len(performs) == 0 {
		t.Fatal("the executor performs nothing; the list is wrong")
	}

	// Constructed the way a real caller does: against everything the machine
	// interface registers, which is what Validate is given. Narrowing that
	// here would fail at construction and report the wrong thing — the
	// question is not whether the archetype validates, it is whether what it
	// validated to can be performed.
	checked := 0
	for _, kind := range agent.Kinds {
		m, err := agent.New(kind, "test-"+string(kind), everyRegisteredOp())
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		checked++

		var unperformable, refused []string
		for _, c := range m.Capabilities {
			switch {
			case performs[c]:
			case refuses[c] != "":
				refused = append(refused, c+" — "+refuses[c])
			default:
				unperformable = append(unperformable, c)
			}
		}
		sort.Strings(unperformable)
		sort.Strings(refused)

		if len(unperformable) > 0 {
			t.Errorf("the %s archetype declares capabilities nothing "+
				"performs:\n  %s\nAn agent made from it validates, publishes "+
				"them on its card, and fails at runtime.",
				kind, strings.Join(unperformable, "\n  "))
		}
		if len(refused) > 0 {
			t.Errorf("the %s archetype declares capabilities this executor "+
				"refuses by design:\n  %s", kind, strings.Join(refused, "\n  "))
		}
	}
	if checked < 5 {
		t.Fatalf("checked %d archetypes; the list is wrong", checked)
	}
}

// everyRegisteredOp stands in for the MCP server's registry, which this
// package cannot import — it deliberately reaches neither the store nor a
// server. Built from what the archetypes themselves ask for, so construction
// always succeeds and the comparison below is about the executor rather than
// about validation.
func everyRegisteredOp() map[string]bool {
	out := map[string]bool{}
	for _, kind := range agent.Kinds {
		tpl, ok := agent.For(kind)
		if !ok {
			continue
		}
		for _, c := range tpl.Manifest.Capabilities {
			out[c] = true
		}
	}
	return out
}
