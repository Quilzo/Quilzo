// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/a2a"
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/mcp"
)

// Tasks from other agents, over A2A 1.0. See internal/a2a/tasks.go.
//
// A message is a goal for one of this store's agents; the run is the task.
// The run is the same as one started on the screen: the agent's manifest,
// narrowed by the credential that sent the message, a model deciding, kept,
// recorded and receipted. A run that stops for a person to approve a step
// stays working until somebody here decides.

// CodeRefused is a task this program would not start, for a reason it gives:
// the sender may not run agents, say. In the range JSON-RPC leaves to
// servers, outside the one A2A numbers.
const CodeRefused = -32050

// a2aTaskURL is where tasks are taken, for the agent card: only when they
// are, and the admin's own address is known.
func a2aTaskURL(cfg *config.Config) string {
	base := strings.TrimRight(cfg.Raw("admin.base_url"), "/")
	if base == "" || !cfg.Bool("a2a.tasks") || !cfg.Bool("mcp.remote") {
		return ""
	}
	return base + "/a2a"
}

// a2aAgents are the agents a task may name: those the card offers.
func a2aAgents(root string) []string {
	set, err := loadAgents(root)
	if err != nil {
		return nil
	}
	known := knownCapabilities(root)
	var out []string
	for name, m := range set.Agents {
		if m.Validate(known) == nil {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// a2aHost answers one caller's tasks.
func a2aHost(root string, c *mcp.Caller) a2a.Host {
	tok, _ := c.Data.(auth.Token)
	caller := remoteCaller(tok)
	note := func(method, agentName, task string, err error) {
		d := map[string]string{"method": method, "on_behalf_of": tok.Principal}
		if agentName != "" {
			d["agent"] = agentName
		}
		if task != "" {
			d["task"] = task
		}
		if tok.Grant != "" {
			d["grant"] = tok.Grant
		}
		outcome := audit.Success
		if err != nil {
			outcome, d["error"] = audit.Denied, clip(err.Error(), 300)
		}
		who, kind := tok.Principal, audit.KindHuman
		if tok.Client != "" {
			who, kind = "app:"+tok.Client, audit.KindAI
		}
		record(root, audit.Record{Action: "a2a.task", Resource: "/a2a", Outcome: outcome,
			Principal: who, Kind: kind, Model: tok.Client, Verified: true, Detail: d})
	}
	mine := func(id string) (agent.Record, error) {
		rec, err := loadAgentRun(root, id)
		// Somebody else's task and no task at all look the same.
		if err != nil || (rec.By != caller.Name && authorise(root, caller, auth.ActGrant, "/") != nil) {
			return agent.Record{}, a2a.Errorf(a2a.CodeTaskNotFound, "no task of yours is "+clip(id, 60))
		}
		return rec, nil
	}
	return a2a.Host{
		Agents: func() []string { return a2aAgents(root) },
		Send: func(r *http.Request, name, text string) (a2a.Task, error) {
			// What running an agent needs anywhere: authoring, and for an
			// app, a connection given at least that.
			if err := remoteRefusal(root, caller, auth.RoleAuthor); err != nil {
				note("SendMessage", name, "", err)
				return a2a.Task{}, a2a.Errorf(CodeRefused, err.Error())
			}
			if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
				note("SendMessage", name, "", err)
				return a2a.Task{}, a2a.Errorf(CodeRefused, err.Error())
			}
			id, err := runAgentOnce(root, name, text, true, caller)
			note("SendMessage", name, id, err)
			if id == "" {
				if err == nil {
					err = errors.New("the run did not start")
				}
				return a2a.Task{}, a2a.Errorf(CodeRefused, err.Error())
			}
			rec, lerr := loadAgentRun(root, id)
			if lerr != nil {
				return a2a.Task{}, lerr
			}
			return taskOf(rec, time.Now()), nil
		},
		Get: func(r *http.Request, id string) (a2a.Task, error) {
			rec, err := mine(id)
			if err != nil {
				return a2a.Task{}, err
			}
			return taskOf(rec, time.Now()), nil
		},
		List: func(r *http.Request, limit int) ([]a2a.Task, error) {
			runs, err := listAgentRuns(root, "", 0)
			if err != nil {
				return nil, err
			}
			var out []a2a.Task
			for _, rec := range runs {
				if rec.By == caller.Name && len(out) < limit {
					out = append(out, taskOf(rec, time.Now()))
				}
			}
			return out, nil
		},
		Cancel: func(r *http.Request, id string) (a2a.Task, error) {
			if _, err := mine(id); err != nil {
				return a2a.Task{}, err
			}
			rec, err := cancelAgentRun(root, id, caller, tok.Client)
			note("CancelTask", rec.Agent, id, err)
			if err != nil {
				return a2a.Task{}, err
			}
			return taskOf(rec, time.Now()), nil
		},
	}
}

// taskOf is a kept run, as the task it is.
func taskOf(rec agent.Record, now time.Time) a2a.Task {
	t := a2a.Task{ID: rec.ID, ContextID: "ctx-" + rec.ID,
		History: []a2a.Message{{MessageID: "goal-" + rec.ID, Role: a2a.RoleUser, Parts: []a2a.Part{{Text: rec.Goal}}}},
		Metadata: map[string]any{"quilzo.agent": rec.Agent, "quilzo.run": rec.ID,
			"quilzo.receipt": "quilzo agent receipt " + rec.ID,
			"quilzo.tainted": rec.Receipt.Tainted, "quilzo.refused": rec.Receipt.Refused}}
	at := rec.Beat
	if at.IsZero() {
		at = rec.Started
	}
	t.Status.Timestamp = at.UTC().Format(time.RFC3339)
	say := func(s string) *a2a.Message {
		return &a2a.Message{MessageID: "status-" + rec.ID, Role: a2a.RoleAgent, Parts: []a2a.Part{{Text: s}}}
	}
	switch outcome := rec.OutcomeAt(now); {
	case strings.HasPrefix(rec.Trace.Stopped, "canceled by "):
		t.Status.State, t.Status.Message = a2a.StateCanceled, say(rec.Trace.Stopped)
	case outcome == "waiting":
		w := rec.Trace.Waiting
		why := fmt.Sprintf("waiting for a person here to decide step %d", w.N)
		if w.Why != "" {
			why += ": " + w.Why
		}
		t.Status.State, t.Status.Message = a2a.StateWorking, say(why)
	case outcome == "running":
		t.Status.State = a2a.StateWorking
	case outcome == "interrupted":
		t.Status.State, t.Status.Message = a2a.StateWorking, say("interrupted; a person here can resume it")
	case rec.Trace.Complete:
		t.Status.State = a2a.StateCompleted
	default:
		t.Status.State, t.Status.Message = a2a.StateFailed, say(nonEmpty(rec.Trace.Stopped, "it stopped before finishing"))
	}
	if rec.Trace.Answer != "" {
		t.Artifacts = []a2a.Artifact{{ArtifactID: "answer", Name: "answer", Parts: []a2a.Part{{Text: rec.Trace.Answer}}}}
		t.History = append(t.History, a2a.Message{MessageID: "answer-" + rec.ID, Role: a2a.RoleAgent,
			Parts: []a2a.Part{{Text: rec.Trace.Answer}}})
	}
	return t
}

// cancelAgentRun ends a run that is waiting for a person or was cut off.
// app names the app that asked, when one did.
func cancelAgentRun(root, id string, by *Caller, app string) (agent.Record, error) {
	audited := func(rec agent.Record) error {
		r := by.auditRecord("agent.canceled", "/agents", audit.Success, map[string]string{"agent": rec.Agent, "run": id})
		if r.Kind == audit.KindAI {
			// Whatever asked through the interface is named: the app, or the
			// protocol when a person's own token was used.
			r.Model = nonEmpty(app, "a2a client")
		}
		return recordE(root, r)
	}
	// A run going on in a process (a browser's, waiting on a person or
	// not) is asked to stop there, and its process records how it ended:
	// written from here, the next beat of that process would undo it.
	if rec, err := loadAgentRun(root, id); err == nil && rec.Eval == "" && goingOn(rec, time.Now()) {
		if err := askToStop(root, rec, "canceled by "+by.Name, time.Now()); err != nil {
			return rec, err
		}
		rec.Trace.Waiting, rec.State = nil, ""
		rec.Trace.Stopped = "canceled by " + by.Name
		return rec, audited(rec)
	}
	release, err := holdAgentRun(root, id)
	if err != nil {
		return agent.Record{}, err
	}
	defer release()
	rec, err := loadAgentRun(root, id)
	if err != nil {
		return rec, a2a.Errorf(a2a.CodeTaskNotFound, err.Error())
	}
	switch rec.OutcomeAt(time.Now()) {
	case "waiting", "interrupted":
	default:
		return rec, a2a.Errorf(a2a.CodeTaskNotCancelable, id+" is "+rec.OutcomeAt(time.Now())+", and only a task waiting or cut off can be canceled")
	}
	rec.Trace.Waiting, rec.State = nil, ""
	rec.Trace.Stopped = "canceled by " + by.Name
	if err := writeAgentRun(root, rec); err != nil {
		return rec, err
	}
	return rec, audited(rec)
}
