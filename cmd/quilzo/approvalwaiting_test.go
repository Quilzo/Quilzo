// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/event"
)

// A run that stops to wait for a person says so once, naming the agent and
// never what it would do; staff hear of it, as they hear of a visitor
// waiting; and no agent may start from it.
func TestAnAgentWaitingForAPersonIsTold(t *testing.T) {
	root, id := waitingRunWithPolicy(t)
	evs, _, err := adminEvents(root).Read(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var waiting []event.Event
	for _, e := range evs {
		if e.Type == event.ApprovalWaiting {
			waiting = append(waiting, e)
		}
	}
	if len(waiting) != 1 || waiting[0].Subject != "tidy" {
		t.Fatalf("%+v", waiting)
	}
	_, body := staffNotice(waiting, 0, "https://cms.example")
	if !strings.Contains(body, "The agent “tidy” is waiting for a person") || !strings.Contains(body, "Approvals") ||
		!strings.Contains(body, "https://cms.example") {
		t.Fatalf("%s", body)
	}
	if rec, _ := loadAgentRun(root, id); rec.Trace.Waiting == nil {
		t.Fatal("the run is not waiting")
	}
	if !strings.Contains(mustConfig(root).Raw("notify.events"), "approval.waiting") {
		t.Error("staff are not told of a waiting agent by default")
	}
	tr := agent.Trigger{On: string(event.ApprovalWaiting), Goal: "approve it", Where: "/"}
	if err := tr.Validate(); err == nil {
		t.Error("an agent may start from another's waiting")
	}
}
