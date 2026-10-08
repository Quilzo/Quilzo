// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/posture"
)

func driftFindings(t *testing.T, root string) map[string]finding.Finding {
	t.Helper()
	reg, _, err := finding.Load(findingsPath(root))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]finding.Finding{}
	for _, f := range reg.All(time.Now()) {
		if strings.HasPrefix(f.Source, postureSource) {
			out[f.Source+"|"+f.Entity.Value] = f
		}
	}
	return out
}

// A check that starts failing is a finding in the queue, once; fixing it
// stales the finding; a check that could not run changes nothing.
func TestAComplianceCheckThatStartsFailingIsAFindingAtOnce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	state := Observe(root, t.TempDir(), posture.ServerFacts{})
	state.AI = posture.AIFacts{Checked: true, Chatbots: []posture.ChatbotFact{{
		Name: "help", Public: true, Disclosed: false, LastEval: time.Now()}}}
	now := time.Now()

	opened, _, err := postureDrift(root, state, now)
	if err != nil {
		t.Fatal(err)
	}
	key := postureSource + "ai.chatbot-undisclosed|help"
	f, ok := driftFindings(t, root)[key]
	if !ok || opened == 0 || f.Kind != finding.FromControl || f.State != finding.Open {
		t.Fatalf("the failing check is not an open finding: %+v (opened %d)", f, opened)
	}
	if !strings.Contains(f.Evidence[0].What, "eu-ai-act Art. 50(1)") {
		t.Errorf("the finding does not say what it bears on: %s", f.Evidence[0].What)
	}

	// The same failure again is the same finding, not a second one.
	again, _, _ := postureDrift(root, state, now.Add(time.Hour))
	if again != 0 {
		t.Errorf("the same failure opened %d more", again)
	}

	// The check could not run: nothing is fixed by not looking.
	blind := state
	blind.AI = posture.AIFacts{}
	if _, fixed, _ := postureDrift(root, blind, now.Add(2*time.Hour)); fixed != 0 ||
		driftFindings(t, root)[key].State != finding.Open {
		t.Error("a check that did not run marked its finding fixed")
	}

	// Fixed, and seen to be fixed.
	state.AI.Chatbots[0].Disclosed = true
	if _, fixed, _ := postureDrift(root, state, now.Add(3*time.Hour)); fixed == 0 ||
		driftFindings(t, root)[key].State != finding.Stale {
		t.Error("the fixed check's finding is still open")
	}
}
