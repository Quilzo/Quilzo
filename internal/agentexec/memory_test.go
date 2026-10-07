// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/memory"
)

func TestARunRemembersOnlyTheKindsItKeeps(t *testing.T) {
	m := agent.Manifest{Name: "helper", Kind: agent.KindTask, Purpose: "help",
		Capabilities: []string{"remember", "recall"}, Autonomy: agent.AutonomyDraft,
		Memory: agent.Memory{Semantic: true, Retain: agent.Duration(time.Hour)},
		Budget: agent.Budget{Steps: 5, Tools: 1, Duration: agent.Duration(time.Hour)}}
	s := agent.NewSession(m, nil)
	var kept []string
	perform := WithMemory(Memory{About: "dana",
		Remember: func(kind, text string, held bool, sources string) (memory.Entry, error) {
			kept = append(kept, kind+":"+text)
			return memory.Entry{ID: "m_1", Held: held}, nil
		},
		Recall: func(string, map[string]bool) ([]memory.Entry, error) { return nil, nil }},
		s, func(context.Context, agent.Action) (string, error) { return "other", nil })
	if _, err := perform(context.Background(), agent.Action{Op: "remember", Input: map[string]any{"kind": "procedural", "text": "how"}}); err == nil ||
		!strings.Contains(err.Error(), "does not keep procedural") {
		t.Fatalf("an undeclared kind: %v", err)
	}
	out, err := perform(context.Background(), agent.Action{Op: "remember", Input: map[string]any{"text": "Dana prefers Spanish"}})
	if err != nil || out != "remembered as m_1" || len(kept) != 1 || kept[0] != "semantic:Dana prefers Spanish" {
		t.Fatalf("%q %v %v", out, err, kept)
	}
	if out, _ := perform(context.Background(), agent.Action{Op: "list_pages"}); out != "other" {
		t.Fatal("another operation was not passed on")
	}
}
