// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/posture"
)

// driftRecords are the drift records the log holds about one rule.
func driftRecords(t *testing.T, root, action, rule string) []audit.Event {
	t.Helper()
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range evs {
		if e.Action == action && e.Detail["rule"] == rule {
			out = append(out, e)
		}
	}
	return out
}

// A check that starts failing is on the record at once, once; fixing it is
// on the record too; a check that could not run changes nothing.
func TestAComplianceCheckThatStartsFailingIsOnTheRecordAtOnce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	state := Observe(root, t.TempDir(), posture.ServerFacts{})
	state.AI = posture.AIFacts{Checked: true, Chatbots: []posture.ChatbotFact{{
		Name: "help", Public: true, Disclosed: false, LastEval: time.Now()}}}
	now := time.Now()
	const rule = "ai.chatbot-undisclosed"

	opened, _, err := postureDrift(root, state, now)
	if err != nil {
		t.Fatal(err)
	}
	drifted := driftRecords(t, root, "posture.drifted", rule)
	if opened == 0 || len(drifted) != 1 || drifted[0].Detail["resource"] != "help" {
		t.Fatalf("the failing check is not on the record: %+v (opened %d)", drifted, opened)
	}
	if !strings.Contains(drifted[0].Detail["detail"], "eu-ai-act Art. 50(1)") {
		t.Errorf("the record does not say what it bears on: %s", drifted[0].Detail["detail"])
	}
	if st, _ := loadDrift(root); st.Failing[driftKey(rule, "help")].Rule != rule {
		t.Errorf("the failing check is not remembered: %+v", st.Failing)
	}

	// The same failure again is not recorded a second time.
	if again, _, _ := postureDrift(root, state, now.Add(time.Hour)); again != 0 ||
		len(driftRecords(t, root, "posture.drifted", rule)) != 1 {
		t.Errorf("the same failure was recorded %d more times", again)
	}

	// The check could not run: nothing is fixed by not looking.
	blind := state
	blind.AI = posture.AIFacts{}
	if _, fixed, _ := postureDrift(root, blind, now.Add(2*time.Hour)); fixed != 0 ||
		len(driftRecords(t, root, "posture.restored", rule)) != 0 {
		t.Error("a check that did not run was recorded as fixed")
	}

	// Fixed, and seen to be fixed.
	state.AI.Chatbots[0].Disclosed = true
	if _, fixed, _ := postureDrift(root, state, now.Add(3*time.Hour)); fixed == 0 ||
		len(driftRecords(t, root, "posture.restored", rule)) != 1 {
		t.Error("the fixed check was not recorded as fixed")
	}
	if st, _ := loadDrift(root); len(st.Failing) != 0 {
		if _, still := st.Failing[driftKey(rule, "help")]; still {
			t.Error("the fixed check is still remembered as failing")
		}
	}
	finishBackground(10 * time.Second)
}
