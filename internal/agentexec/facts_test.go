// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentexec

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/memory"
)

// A run that remembers a fact with a key replaces what it said before, and
// recall says since when the fact has held.
func TestARunReplacesAFactByItsKey(t *testing.T) {
	store := &memory.Store{Dir: t.TempDir()}
	mem := Memory{About: "dana",
		Remember: func(kind, text string, held bool, sources, tier, key string) (memory.Entry, error) {
			return store.Remember(memory.Entry{Agent: "helper", About: "dana", Kind: kind, Text: text, Run: "r1", By: "dana",
				Held: held, Sources: sources, Tier: tier, Key: key}, memory.MaxRetain, time.Now())
		},
		Recall: func(query string, kinds map[string]bool) ([]memory.Entry, error) {
			return store.Recall("helper", "dana", query, kinds, MaxRecalled, time.Now())
		},
	}
	man := agent.Manifest{Name: "helper", Kind: agent.KindTask, Purpose: "help", Capabilities: []string{"remember", "recall"},
		Autonomy: agent.AutonomyPropose, Memory: agent.Memory{Semantic: true, Retain: agent.Duration(memory.MaxRetain)},
		Budget: agent.Budget{Steps: 10, Tools: 1, Duration: agent.Duration(time.Minute)}}
	s := agent.NewSession(man, nil)
	do := WithMemory(mem, s, func(context.Context, agent.Action) (string, error) { return "", nil })
	first, err := do(context.Background(), agent.Action{Op: "remember", Input: map[string]any{
		"text": "Dana ships to Lisbon", "kind": "semantic", "key": "shipping_city"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := do(context.Background(), agent.Action{Op: "remember", Input: map[string]any{
		"text": "Dana ships to Porto now", "kind": "semantic", "key": "shipping_city"}})
	if err != nil || !strings.Contains(second, "replacing") {
		t.Fatalf("%q %v (first %q)", second, err, first)
	}
	got, err := do(context.Background(), agent.Action{Op: "recall", Input: map[string]any{"query": "where does Dana ship"}})
	if err != nil || !strings.Contains(got, "Porto") || strings.Contains(got, "Lisbon") || !strings.Contains(got, "true since") {
		t.Fatalf("recalled %q %v", got, err)
	}
}
