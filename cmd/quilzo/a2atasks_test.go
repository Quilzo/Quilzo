// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/quilzo/quilzo/internal/shield"
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
	if err := declareAgent(root, asker("tidy"), true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	var e *a2a.Error
	h := a2aHost(root, a2aCaller("dana", auth.RoleAdmin, ""))
	if _, err := h.Send(nil, "tidy", "Tidy it"); !errors.As(err, &e) || e.Code != CodeRefused || !strings.Contains(e.Message, "access policy") {
		t.Fatalf("%v", err)
	}
}

// What this program refused is on the record as denied, and what went wrong
// as a failure. Every error was recorded as denied, so a task whose run
// could not reach its model read as an attack refused, and a log reader
// looking for refusals found outages.
func TestATaskThatFailsIsRecordedAsAFailureAndARefusalAsDenied(t *testing.T) {
	root, _ := identityStore(t) // dana, an administrator, declared tidy
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "the model is down", http.StatusBadGateway)
	}))
	defer down.Close()
	t.Setenv("QUILZO_MODEL_URL", down.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")
	last := func() audit.Event {
		t.Helper()
		evs, err := audit.Read(auditPath(root))
		if err != nil {
			t.Fatal(err)
		}
		for i := len(evs) - 1; i >= 0; i-- {
			if evs[i].Action == "a2a.task" {
				return evs[i]
			}
		}
		t.Fatal("no a2a.task record")
		return audit.Event{}
	}
	app := "https://agents.example.com/meta"
	for who, h := range map[string]a2a.Host{
		// Holds nothing here.
		"somebody with no role": a2aHost(root, a2aCaller("rae", auth.RoleAuthor, "")),
		// Given read only.
		"an app given read only": a2aHost(root, a2aCaller("dana", auth.RoleReader, app)),
	} {
		if _, err := h.Send(nil, "tidy", "Tidy it"); err == nil {
			t.Fatalf("%s ran an agent", who)
		}
		if r := last(); r.Outcome != audit.Denied {
			t.Errorf("%s refused is on the record as %s", who, r.Outcome)
		}
	}
	dana := a2aHost(root, a2aCaller("dana", auth.RoleAdmin, app))
	// The run starts, and the task is the run that failed.
	if _, err := dana.Send(nil, "tidy", "Tidy the welcome page"); err != nil {
		t.Fatal(err)
	}
	if r := last(); r.Outcome != audit.Failure || r.Detail["error"] == "" {
		t.Errorf("a run that could not reach its model is on the record as %s: %v", r.Outcome, r.Detail)
	}
	// A task that has finished cannot be canceled: nobody refused anybody.
	done := agent.Record{ID: "run-20261007-0000cc01", Agent: "tidy", Goal: "tidy", By: "dana",
		Started: time.Now().UTC(), Trace: agent.Trace{Agent: "tidy", Complete: true, Answer: "Tidied."}}
	if err := writeAgentRun(root, done); err != nil {
		t.Fatal(err)
	}
	if _, err := dana.Cancel(nil, done.ID); err == nil {
		t.Fatal("a finished task was canceled")
	}
	if r := last(); r.Outcome != audit.Failure || r.Detail["method"] != "CancelTask" {
		t.Errorf("a finished task not canceled is on the record as %s: %v", r.Outcome, r.Detail)
	}
}

// An agent this program will not run is a task refused, on the record as
// one. Paused by the shield, or with nobody left to answer for it, the run
// never starts and the sender is told so with CodeRefused, but the record
// called it a failure, because the reason came back as words: a sender
// asking again and again for an agent the shield had stopped read as an
// outage rather than as what the shield exists to catch.
func TestATaskForAnAgentThatMayNotRunIsRecordedAsDenied(t *testing.T) {
	root, _ := identityStore(t) // dana, an administrator, declared tidy
	t.Setenv("QUILZO_MODEL_URL", "http://127.0.0.1:1/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")
	dana := a2aHost(root, a2aCaller("dana", auth.RoleAdmin, "https://agents.example.com/meta"))
	refused := func(why string) {
		t.Helper()
		_, err := dana.Send(nil, "tidy", "Tidy the welcome page")
		var ae *a2a.Error
		if !errors.As(err, &ae) || ae.Code != CodeRefused {
			t.Fatalf("%s, the task was answered %v", why, err)
		}
		evs, err := audit.Read(auditPath(root))
		if err != nil {
			t.Fatal(err)
		}
		for i := len(evs) - 1; i >= 0; i-- {
			if evs[i].Action == "a2a.task" {
				if evs[i].Outcome != audit.Denied {
					t.Errorf("%s, the task is on the record as %s: %v", why, evs[i].Outcome, evs[i].Detail)
				}
				return
			}
		}
		t.Fatal("no a2a.task record")
	}

	p, _, err := shield.Apply(root, shield.Protection{Kind: shield.Agent, Target: "tidy", Reason: "followed a planted instruction",
		By: "shield", Auto: true, Until: time.Now().Add(time.Hour)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	refused("paused by the shield")
	if _, err := shield.Lift(root, p.ID, "dana", time.Now()); err != nil {
		t.Fatal(err)
	}

	set, _ := loadAgents(root)
	id := set.Identities["tidy"]
	id.Expires = time.Now().Add(-time.Minute)
	set.Identities["tidy"] = id
	if err := saveJSON(agentsPath(root), set); err != nil {
		t.Fatal(err)
	}
	refused("its identity ended")
}
