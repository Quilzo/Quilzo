// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package mcp

import (
	"fmt"
	"strings"
	"testing"
)

// A server with no authorisation hook serves nothing.
//
// NeedsRole used to be read in exactly one place — describe — so it printed a
// role requirement to the agent and enforced nothing. Three of twenty-three
// operations checked authority in their own handler; twenty did not, and a
// twenty-fourth would have defaulted to open.
//
// So the gate is central and a nil hook refuses, because the defect being
// fixed is a surface that was open by omission. Failing closed is the only
// arrangement where forgetting produces a refusal rather than a leak.
func TestNoAuthorisationHookRefusesEverything(t *testing.T) {
	s := NewServer("t", "1")
	s.Register(Operation{Name: "peek", Summary: "read", NeedsRole: "reader"},
		func(map[string]any) (any, error) { return "the whole draft", nil })

	r := call(t, s, "tools/call", callParams{
		Name: "quilzo_read", Arguments: map[string]any{"operation": "peek"}})
	if r.Error == nil {
		t.Fatal("an operation ran with no authorisation hook wired")
	}
	if !strings.Contains(r.Error.Message, "no authorisation hook") {
		t.Errorf("refused without saying why: %s", r.Error.Message)
	}
}

// The hook is given the operation, and a refusal from it reaches the agent as
// a refusal rather than as a malfunction.
//
// The distinction is load-bearing on this surface: an agent that reads
// "denied" as "the server broke" retries, and retrying a refusal turns one
// blocked action into a hundred.
func TestARefusedOperationIsNotRetryable(t *testing.T) {
	s := NewServer("t", "1")
	var asked string
	s.Authorise = func(op Operation) error {
		asked = op.Name + "/" + op.NeedsRole
		return fmt.Errorf("bob is author on /; grant needs admin")
	}
	s.Register(Operation{Name: "inventory", Summary: "the bill of materials",
		NeedsRole: "admin"},
		func(map[string]any) (any, error) { return "components", nil })

	r := call(t, s, "tools/call", callParams{
		Name: "quilzo_read", Arguments: map[string]any{"operation": "inventory"}})
	if r.Error == nil {
		t.Fatal("the hook refused and the operation ran anyway")
	}
	if asked != "inventory/admin" {
		t.Errorf("the hook was not told which operation and role: %q", asked)
	}
	if r.Error.Code != CodeRefused {
		t.Errorf("a refusal should carry the refusal code, got %d", r.Error.Code)
	}
	data, _ := r.Error.Data.(map[string]any)
	if v, _ := data["retryable"].(bool); v {
		t.Error("a refusal must not invite a retry")
	}
}

// The hook runs before the handler, not after it.
//
// A gate that runs after the work is done has already read the thing it was
// meant to protect.
func TestTheHookRunsBeforeTheHandler(t *testing.T) {
	s := NewServer("t", "1")
	ran := false
	s.Authorise = func(Operation) error { return fmt.Errorf("no") }
	s.Register(Operation{Name: "peek", Summary: "read", NeedsRole: "reader"},
		func(map[string]any) (any, error) {
			ran = true
			return "secret", nil
		})

	call(t, s, "tools/call", callParams{
		Name: "quilzo_read", Arguments: map[string]any{"operation": "peek"}})
	if ran {
		t.Error("the handler ran despite the refusal, so it had already read " +
			"whatever the gate was protecting")
	}
}
