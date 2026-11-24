// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// runDiesMain is a process that keeps a step of a run and then ends without
// finishing it, as a process killed half way through does.
func runDiesMain(root, id string) {
	k := &keptRun{root: root, rec: agent.Record{ID: id, Agent: "tidy", Goal: "tidy the about page",
		By: "dana", Started: time.Now().UTC()}}
	k.checkpoint(agent.Trace{Agent: "tidy", Goal: "tidy the about page",
		Steps: []agent.Step{{N: 1, Action: agent.Action{Op: "list_pages"}, Allowed: true, Result: "about"}}})
}

// A run whose process has ended can be gone on with at once.
//
// When the process working on a run was killed, its record went on saying
// "running" until five minutes had passed since it was last written, and
// for all that time `agent runs` listed a dead run as running and `agent
// resume` refused it as one, so nobody could recover it, or tell it was
// dead. The process now holds a lock on the run that the kernel lets go of
// when it ends, however it ends.
func TestARunWhoseProcessDiedCanBeResumedAtOnce(t *testing.T) {
	root, _ := identityStore(t)
	id, err := newAgentRunID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "agentrun-dies", root, id)
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(err.Error(), "exit status 3") {
		t.Fatalf("the dying process: %v %s", err, out)
	}
	rec, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != agent.Running {
		t.Fatalf("the run it left says %q", rec.State)
	}
	if o := rec.OutcomeAt(time.Now()); o != "interrupted" {
		t.Errorf("a run whose process has ended is listed as %s", o)
	}
	_, release, err := prepareContinue(root, id, nil, asAdmin("dana"))
	if err != nil {
		t.Fatalf("a run whose process has ended could not be resumed: %v", err)
	}
	release()

	// And one whose process is still working on it is not.
	k := &keptRun{root: root, rec: agent.Record{ID: id, Agent: "tidy", Goal: "tidy the about page", By: "dana",
		Started: rec.Started}}
	k.checkpoint(rec.Trace)
	defer k.finish(agentOutcome{Trace: rec.Trace})
	if rec, err = loadAgentRun(root, id); err != nil {
		t.Fatal(err)
	}
	if o := rec.OutcomeAt(time.Now()); o != "running" {
		t.Errorf("a run its process is working on is listed as %s", o)
	}
	if _, _, err := prepareContinue(root, id, nil, asAdmin("dana")); err == nil ||
		!strings.Contains(err.Error(), "it is running") {
		t.Errorf("a run its process is working on was resumed: %v", err)
	}
}
