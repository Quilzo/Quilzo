// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/evals"
)

// The whole of earning, against a real store: three approvals of the same
// write earn it; the fourth run writes without asking and says why; a
// regressed evaluation stops what was earned from counting; and a reset
// asks again.
func TestAnAgentEarnsAKindOfActionByItsRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	standInModel(t)
	declaredAutonomy(t, root)
	m := asker("tidy")
	m.EarnAfter = 3
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	clean := evals.Report{Agent: "tidy", At: time.Now().UTC(), K: 3, Model: "stand-in",
		Cases: 3, Reliable: 3, Planted: 3}
	if err := os.MkdirAll(evalResultsDir(root, "tidy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveEvalReport(root, clean); err != nil {
		t.Fatal(err)
	}
	approveOnce := func() agent.Record {
		t.Helper()
		id, err := runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
		if err != nil {
			t.Fatal(err)
		}
		rec, _ := loadAgentRun(root, id)
		w := rec.Trace.Waiting
		if w == nil {
			return rec
		}
		done, err := continueAgentRun(context.Background(), root, id,
			&agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
		if err != nil {
			t.Fatal(err)
		}
		return done
	}
	for i := 0; i < 3; i++ {
		if rec := approveOnce(); rec.Trace.Waiting != nil {
			t.Fatalf("run %d did not finish after its approval", i+1)
		}
	}
	id, err := runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := loadAgentRun(root, id)
	if rec.Trace.Waiting != nil {

		t.Fatal("after three approvals the write still asked")
	}
	earnedStep := false
	for _, st := range rec.Trace.Steps {
		earnedStep = earnedStep || strings.Contains(st.Earned, "earned it")
	}
	if !earnedStep {
		t.Fatalf("the write went ahead without saying it was earned: %+v", rec.Trace.Steps)
	}

	// An evaluation that regressed: nothing earned counts.
	bad := clean
	bad.At, bad.Hijacked = time.Now().UTC().Add(time.Second), 1
	if err := saveEvalReport(root, bad); err != nil {
		t.Fatal(err)
	}
	id, _ = runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	if rec, _ = loadAgentRun(root, id); rec.Trace.Waiting == nil && rec.Trace.Complete {
		for _, st := range rec.Trace.Steps {
			if st.Earned != "" {
				t.Fatal("a regressed evaluation still let earned writes skip asking")
			}
		}
	}

	// A reset sends it back, whatever the evaluations say.
	if err := saveEvalReport(root, evals.Report{Agent: "tidy", At: time.Now().UTC().Add(2 * time.Second),
		K: 3, Model: "stand-in", Cases: 3, Reliable: 3, Planted: 3}); err != nil {
		t.Fatal(err)
	}
	unearnHook(root, "tidy", asAdmin("dana"))("reset by a person")
	id, _ = runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	if rec, _ = loadAgentRun(root, id); rec.Trace.Waiting == nil {
		t.Fatal("after a reset the write did not ask")
	}
}
