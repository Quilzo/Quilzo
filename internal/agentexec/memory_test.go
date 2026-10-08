// SPDX-FileCopyrightText: 2026 Rashik Adhikari
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
		Remember: func(kind, text string, held bool, sources, tier string) (memory.Entry, error) {
			kept = append(kept, kind+":"+text+":"+tier)
			return memory.Entry{ID: "m_1", Held: held}, nil
		},
		Recall: func(string, map[string]bool) ([]memory.Entry, error) { return nil, nil }},
		s, func(context.Context, agent.Action) (string, error) { return "other", nil })
	if _, err := perform(context.Background(), agent.Action{Op: "remember", Input: map[string]any{"kind": "procedural", "text": "how"}}); err == nil ||
		!strings.Contains(err.Error(), "does not keep procedural") {
		t.Fatalf("an undeclared kind: %v", err)
	}
	out, err := perform(context.Background(), agent.Action{Op: "remember", Input: map[string]any{"text": "Dana prefers Spanish"}})
	if err != nil || out != "remembered as m_1" || len(kept) != 1 || kept[0] != "semantic:Dana prefers Spanish:person" {
		t.Fatalf("%q %v %v", out, err, kept)
	}
	if out, _ := perform(context.Background(), agent.Action{Op: "list_pages"}); out != "other" {
		t.Fatal("another operation was not passed on")
	}
}

// What a run learns is as trusted as what it had read, and the receipt
// names the memory it used and kept.
func TestWhatARunLearnsIsAsTrustedAsWhatItRead(t *testing.T) {
	learn := func(ref string, read func(*agent.Session)) (string, *agent.Session) {
		m := agent.Manifest{Name: "helper", Kind: agent.KindTask, Purpose: "help",
			Capabilities: []string{"remember", "recall", "read_page"}, Autonomy: agent.AutonomyDraft,
			Retrieval: agent.Retrieval{Ref: ref},
			Tools:     []agent.Tool{{Name: "lookup", Host: "crm.example", Purpose: "customers"}},
			Memory:    agent.Memory{Semantic: true, Retain: agent.Duration(time.Hour)},
			Budget:    agent.Budget{Steps: 5, Tools: 2, Duration: agent.Duration(time.Hour)}}
		s := agent.NewSession(m, nil)
		if read != nil {
			read(s)
		}
		tier := ""
		perform := WithMemory(Memory{About: "dana",
			Remember: func(_, _ string, _ bool, _, t string) (memory.Entry, error) {
				tier = t
				return memory.Entry{ID: "m_new"}, nil
			},
			Recall: func(string, map[string]bool) ([]memory.Entry, error) {
				return []memory.Entry{{ID: "m_old", Kind: "semantic", Text: "Dana prefers Spanish", Tier: memory.TierPerson}}, nil
			}}, s, nil)
		if out, err := perform(context.Background(), agent.Action{Op: "recall"}); err != nil ||
			!strings.Contains(out, "from what the person said") {
			t.Fatalf("recall: %q %v", out, err)
		}
		if _, err := perform(context.Background(), agent.Action{Op: "remember", Input: map[string]any{"text": "x"}}); err != nil {
			t.Fatal(err)
		}
		return tier, s
	}
	if tier, s := learn("live", nil); tier != memory.TierPerson {
		t.Errorf("having read nothing: %s", tier)
	} else if rc := (agent.Trace{}).Receipt(s); strings.Join(rc.Recalled, ",") != "m_old" || strings.Join(rc.Remembered, ",") != "m_new" ||
		rc.Detail()["recalled"] != "m_old" || rc.Detail()["remembered"] != "m_new" {
		t.Errorf("the receipt: %+v", rc)
	}
	if tier, _ := learn("live", func(s *agent.Session) { _ = s.Retrieve("live", "pricing", "", "") }); tier != memory.TierPublished {
		t.Errorf("having read a published page: %s", tier)
	}
	if tier, _ := learn("draft", func(s *agent.Session) { _ = s.Retrieve("draft", "pricing", "", "") }); tier != memory.TierUnreviewed {
		t.Errorf("having read a draft: %s", tier)
	}
	if tier, _ := learn("live", func(s *agent.Session) {
		_ = s.Retrieve("live", "pricing", "", "")
		_ = s.MayCallTool("lookup", "")
	}); tier != memory.TierUnreviewed {
		t.Errorf("having called a tool: %s", tier)
	}
}
