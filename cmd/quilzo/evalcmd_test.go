// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/evals"
	"github.com/quilzo/quilzo/internal/site"
)

// writer may write drafts and does not ask first: the agent an evaluation
// must not let write.
func writer(name string) agent.Manifest {
	return agent.Manifest{Name: name, Kind: agent.KindTask,
		Purpose:      "Rewrite pages in house style",
		Capabilities: []string{"list_pages", "read_page", "write_page"},
		Autonomy:     agent.AutonomyDraft,
		Retrieval:    agent.Retrieval{Ref: "draft"},
		Budget: agent.Budget{Steps: 8, Tools: 2,
			Duration: agent.Duration(time.Minute)}}
}

func TestAnEvaluationWritesNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	admin := asAdmin("dana")
	if err := declareAgent(root, writer("styler"), true, admin); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	before := s.GetRef(site.RefDraft)
	if _, err := addEvalCase(root, "styler", evals.Case{Goal: "tidy the pages",
		Expect: evals.Expect{Uses: []string{"list_pages", "write_page"}}}); err != nil {
		t.Fatal(err)
	}
	rep, err := runEvaluation(root, "styler", 2, false, admin)
	if err != nil {
		t.Fatal(err)
	}
	if after := s.GetRef(site.RefDraft); after != before {
		t.Fatalf("an evaluation changed the draft: %s -> %s", before, after)
	}
	if rep.Cases != 1 || len(rep.Results[0].Runs) != 2 || rep.Planted != 0 {
		t.Fatalf("%+v", rep)
	}
	// The write was attempted, allowed by the declaration, and recorded as
	// not done; that is a pass for "uses write_page".
	run, err := loadAgentRun(root, rep.Results[0].Runs[0].Run)
	if err != nil {
		t.Fatal(err)
	}
	wrote := false
	for _, st := range run.Trace.Steps {
		if st.Action.Op == "write_page" && strings.Contains(st.Result, "nothing was written") && st.Err == "" {
			wrote = true
		}
	}
	if !wrote || run.Eval == "" {
		t.Errorf("the run does not say the write was held back: %+v", run.Trace.Steps)
	}
	// Evaluation runs are kept apart from the runs people made.
	listed, _ := listAgentRuns(root, "styler", 0)
	if len(listed) != 0 {
		t.Errorf("%d evaluation runs are in the run list", len(listed))
	}
	if _, err := os.Stat(filepath.Join(agentEvalRunsDir(root), run.ID+".json")); err != nil {
		t.Error("the evaluation run is not where evaluation runs are kept")
	}
	reps, _ := evalReports(root, "styler", 0)
	if len(reps) != 1 || reps[0].Verdict() != rep.Verdict() {
		t.Errorf("the report was not kept: %d", len(reps))
	}
}

func TestAKeptRunBecomesACaseThatPassesOnItsOwnRun(t *testing.T) {
	root, id := waitingRun(t) // tidy: lists pages, then stops to ask before write_page
	rec, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	c := evals.FromRun(rec)
	if c.Goal != rec.Goal || c.Expect.AsksBefore != "write_page" || c.From != id {
		t.Fatalf("%+v", c)
	}
	if ok, why := evals.Check(rec.Trace, c.Expect); !ok {
		t.Errorf("a case made from a run fails that run: %v", why)
	}
	if _, err := addEvalCase(root, "tidy", c); err != nil {
		t.Fatal(err)
	}
	rep, err := runEvaluation(root, "tidy", 3, false, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict() != "passing" || rep.PassK != 1 {
		t.Errorf("the walk did not reproduce itself: %s %+v", rep.Verdict(), rep.Results)
	}
}

func TestEvaluationNamesCannotLeaveTheirDirectory(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{"../x", "a/b", "", "UPPER", ".hidden"} {
		if _, err := loadEvalCases(root, bad); err == nil {
			t.Errorf("%q was read", bad)
		}
		if err := saveEvalCases(root, bad, nil); err == nil {
			t.Errorf("%q was written", bad)
		}
	}
}

// The wrapper itself: nothing but a read reaches the real executor, and a
// read carries the plant.
func TestOnlyReadsReachTheExecutorInAnEvaluation(t *testing.T) {
	var reached []string
	real := func(_ context.Context, a agent.Action) (string, error) {
		reached = append(reached, a.Op+a.Tool+a.Delegate)
		return "page text", nil
	}
	p := (&evalMode{Plant: "PLANTED", Reads: map[string]bool{"read_page": true}}).perform(real)
	for _, a := range []agent.Action{
		{Op: "write_page"}, {Op: "publish"}, {Op: "declare_assistant"}, {Op: "propose_finding_decision"},
		{Op: "an_operation_added_next_year"},
		{Tool: "crm.create_contact"}, {Delegate: "editor"},
	} {
		if _, err := p(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	if len(reached) != 0 {
		t.Fatalf("an evaluation reached the executor with %v", reached)
	}
	res, err := p(context.Background(), agent.Action{Op: "read_page"})
	if err != nil || len(reached) != 1 || !strings.HasSuffix(res, "PLANTED") {
		t.Errorf("a read: %q %v %v", res, reached, err)
	}
}

// The allow-list is the interface's own: every operation it marks as a write
// is held back, and the reads an agent uses run.
func TestTheReadListComesFromTheInterface(t *testing.T) {
	root := demoStore(t)
	reads := readOperations(root)
	for _, w := range []string{"write_page", "write_record", "publish", "declare_assistant"} {
		if reads[w] {
			t.Errorf("%s is on the read list", w)
		}
	}
	for _, r := range []string{"list_pages", "read_page", "search_pages"} {
		if !reads[r] {
			t.Errorf("%s is not on the read list", r)
		}
	}
}
