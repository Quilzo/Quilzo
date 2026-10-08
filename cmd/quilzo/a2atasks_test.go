// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a2a"
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
)

func a2aCaller(who string, role auth.Role, client string) *mcp.Caller {
	tok := auth.Token{Principal: who, Role: role, Resource: "/", Client: client}
	if client != "" {
		tok.Grant = "gr_00000000000000d1"
	}
	return &mcp.Caller{Principal: who, Client: client, Data: tok}
}

// A message from another agent runs one of this store's agents as whoever
// sent it, and the run is the task; it is theirs to read and nobody
// else's.
func TestAnotherAgentsMessageRunsAnAgentAsItsSender(t *testing.T) {
	root, _ := identityStore(t) // dana, an administrator, declared tidy
	answering := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"op\":\"done\",\"say\":\"The welcome page is tidy.\"}"}}]}`))
	}))
	defer answering.Close()
	t.Setenv("QUILZO_MODEL_URL", answering.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")
	h := a2aHost(root, a2aCaller("dana", auth.RoleAdmin, "https://agents.example.com/meta"))
	if got := h.Agents(); len(got) != 1 || got[0] != "tidy" {
		t.Fatalf("%v", got)
	}
	task, err := h.Send(nil, "tidy", "Tidy the welcome page")
	if err != nil {
		t.Fatal(err)
	}
	if task.Status.State != a2a.StateCompleted || len(task.Artifacts) != 1 || task.Artifacts[0].Parts[0].Text != "The welcome page is tidy." {
		t.Fatalf("%+v %+v", task.Status, task)
	}
	if task.ID == "" || task.Metadata["quilzo.agent"] != "tidy" || task.History[0].Parts[0].Text != "Tidy the welcome page" {
		t.Fatalf("%+v", task)
	}
	rec, err := loadAgentRun(root, task.ID)
	if err != nil || rec.By != "dana" {
		t.Fatalf("the run was not dana's: %+v %v", rec, err)
	}
	if got, err := h.Get(nil, task.ID); err != nil || got.ID != task.ID {
		t.Fatalf("%v", err)
	}
	// Somebody else's run is not among dana's tasks.
	if err := writeAgentRun(root, agent.Record{ID: "run-20261007-0000bb01", Agent: "tidy", Goal: "x", By: "sam",
		Started: time.Now().UTC(), Trace: agent.Trace{Agent: "tidy", Complete: true}}); err != nil {
		t.Fatal(err)
	}
	if ts, _ := h.List(nil, 50); len(ts) != 1 || ts[0].ID != task.ID {
		t.Fatalf("%d tasks", len(ts))
	}
	// Somebody else, who may not see dana's runs, is told there is no such task.
	var e *a2a.Error
	rae := a2aHost(root, a2aCaller("rae", auth.RoleAuthor, ""))
	if _, err := rae.Get(nil, task.ID); !errors.As(err, &e) || e.Code != a2a.CodeTaskNotFound {
		t.Fatalf("rae read dana's task: %v", err)
	}
	// An app given read only cannot start a run.
	reader := a2aHost(root, a2aCaller("dana", auth.RoleReader, "https://agents.example.com/meta"))
	if _, err := reader.Send(nil, "tidy", "Tidy it"); !errors.As(err, &e) || e.Code != CodeRefused {
		t.Fatalf("a read-only app ran an agent: %v", err)
	}
	evs, _ := audit.Read(auditPath(root))
	sends := 0
	for _, ev := range evs {
		if ev.Action == "a2a.task" && ev.Detail["method"] == "SendMessage" {
			sends++
		}
	}
	if sends != 2 {
		t.Fatalf("%d records of SendMessage", sends)
	}
}

// A task waiting for a person here is canceled by its sender; a finished
// one is not.
func TestAWaitingTaskIsCanceledAndAFinishedOneIsNot(t *testing.T) {
	root, _ := identityStore(t)
	now := time.Now().UTC()
	waiting := agent.Record{ID: "run-20261007-0000aa01", Agent: "tidy", Goal: "tidy", By: "dana", Started: now,
		Trace: agent.Trace{Agent: "tidy", Waiting: &agent.Pending{N: 2, Action: agent.Action{Op: "write_page"}, Since: now,
			Why: "this run has read what is not published"}}}
	done := agent.Record{ID: "run-20261007-0000aa02", Agent: "tidy", Goal: "tidy", By: "dana", Started: now,
		Trace: agent.Trace{Agent: "tidy", Complete: true, Answer: "Tidied."}}
	for _, r := range []agent.Record{waiting, done} {
		if err := writeAgentRun(root, r); err != nil {
			t.Fatal(err)
		}
	}
	h := a2aHost(root, a2aCaller("dana", auth.RoleAdmin, "https://agents.example.com/meta"))
	got, _ := h.Get(nil, waiting.ID)
	if got.Status.State != a2a.StateWorking || !strings.Contains(got.Status.Message.Parts[0].Text, "waiting for a person here to decide step 2") {
		t.Fatalf("%+v", got.Status)
	}
	got, _ = h.Get(nil, done.ID)
	if got.Status.State != a2a.StateCompleted || len(got.Artifacts) != 1 || got.Artifacts[0].Parts[0].Text != "Tidied." {
		t.Fatalf("%+v", got)
	}
	var e *a2a.Error
	if _, err := h.Cancel(nil, done.ID); !errors.As(err, &e) || e.Code != a2a.CodeTaskNotCancelable {
		t.Fatalf("a finished task was canceled: %v", err)
	}
	got, err := h.Cancel(nil, waiting.ID)
	if err != nil || got.Status.State != a2a.StateCanceled {
		t.Fatalf("%+v %v", got.Status, err)
	}
	if rec, _ := loadAgentRun(root, waiting.ID); rec.Trace.Waiting != nil || rec.Trace.Stopped != "canceled by dana" {
		t.Fatalf("%+v", rec.Trace)
	}
	if _, err := h.Get(nil, "run-20261007-0000ffff"); !errors.As(err, &e) || e.Code != a2a.CodeTaskNotFound {
		t.Fatalf("%v", err)
	}
}

// A store nobody has set access for takes no task from anybody.
func TestAStoreWithNoAccessPolicyTakesNoTasks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := declareAgent(root, asker("tidy"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	var e *a2a.Error
	h := a2aHost(root, a2aCaller("dana", auth.RoleAdmin, ""))
	if _, err := h.Send(nil, "tidy", "Tidy it"); !errors.As(err, &e) || e.Code != CodeRefused || !strings.Contains(e.Message, "access policy") {
		t.Fatalf("%v", err)
	}
}
