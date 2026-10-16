// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/evolve"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/shell"
)

// The candidate and the evaluator of the end-to-end test, deliberately
// shaped so that only the number in the program decides the score: the
// candidate writes it, the evaluator reads it and reports it, and the
// search's job is to move it up.
const evolveSeed = `# EVOLVE-BLOCK-START
value = 1
# EVOLVE-BLOCK-END
import json, os
os.makedirs("output", exist_ok=True)
open("output/result.json", "w").write(json.dumps({"value": value}))
`

const evolveEvaluator = `import json, os
v = json.load(open("candidate/result.json"))["value"]
os.makedirs("output", exist_ok=True)
open("output/metrics.json", "w").write(json.dumps({"value": v}))
`

// answeringModel proposes one fixed diff per call.
type answeringModel struct{ answers []string }

func (m *answeringModel) Complete(_ context.Context, _, _ string) (string, error) {
	if len(m.answers) == 0 {
		return "", context.Canceled
	}
	a := m.answers[0]
	m.answers = m.answers[1:]
	return a, nil
}

func (m *answeringModel) Name() string { return "answering" }

// The whole search, through the real boxes: a seed is judged, a diff
// applies, the improved program runs, the sealed evaluator scores it from
// the candidate's output alone, and the journal and the candidates land on
// disk where an auditor can read them.
func TestASearchRunsInTheBoxes(t *testing.T) {
	root, _ := identityStore(t)
	n := agentbox.Native{Exe: os.Args[0], Init: []string{"agentbox-init"}, Shim: []string{"agentbox-shim"}}
	if a := n.Check(); !a.OK {
		t.Skip("no box here: " + a.Why)
	}
	if _, err := shell.Find("python3"); err != nil {
		t.Skip("no Python here")
	}
	testBackend = n
	t.Cleanup(func() { testBackend = nil })
	w = out.New(false)

	dir := t.TempDir()
	prog := filepath.Join(dir, "seed.py")
	eval := filepath.Join(dir, "evaluator.py")
	if err := os.WriteFile(prog, []byte(evolveSeed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eval, []byte(evolveEvaluator), 0o600); err != nil {
		t.Fatal(err)
	}
	model := &answeringModel{answers: []string{
		"<<<<<<< SEARCH\nvalue = 1\n=======\nvalue = 7\n>>>>>>> REPLACE\n",
	}}
	draftModelSeam = func(string) (assist.Model, string) { return model, "" }
	t.Cleanup(func() { draftModelSeam = nil })

	if err := evolveRun(root, []string{
		"--program", prog, "--evaluator", eval,
		"--generations", "1", "--population", "3",
		"--seed", "11", "--timeout", "30s",
	}, asAdmin("dana")); err != nil {
		t.Fatalf("the search failed: %v", err)
	}

	// One run directory, with a journal of two entries and the population's
	// programs beside it.
	runs, err := os.ReadDir(filepath.Join(root, "evolve"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs: %v %v", runs, err)
	}
	runDir := filepath.Join(root, "evolve", runs[0].Name())
	entries, err := (evolve.Journal{Path: filepath.Join(runDir, "journal.jsonl")}).Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("%d journal entries, want the seed and one generation", len(entries))
	}
	if !entries[0].Kept || !entries[1].Kept {
		t.Errorf("kept flags: %v %v", entries[0].Kept, entries[1].Kept)
	}
	if entries[1].Metrics["value"] != 7 {
		t.Errorf("the improved program scored %v", entries[1].Metrics["value"])
	}
	best, err := os.ReadFile(filepath.Join(runDir, "best.py"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(best), "value = 7") {
		t.Errorf("the best program:\n%s", best)
	}
	if !strings.Contains(string(best), "EVOLVE-BLOCK-START") {
		t.Error("the markers did not survive the search")
	}
	// No workspace outlives a generation: only the journal, the candidates
	// and the best program are kept.
	left, _ := os.ReadDir(runDir)
	for _, f := range left {
		if strings.HasPrefix(f.Name(), "cand-") || strings.HasPrefix(f.Name(), "eval-") ||
			strings.HasPrefix(f.Name(), "home-") {
			t.Errorf("a box's workspace survived: %s", f.Name())
		}
	}
}

// The bounds on what a run is handed are enforced where the files are.
func TestInputBounds(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, MaxInputAbs+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInputs([]string{big}); err == nil {
		t.Error("an oversized input was accepted")
	}
	var many []string
	for i := 0; i <= MaxInputs; i++ {
		many = append(many, big)
	}
	if _, err := readInputs(many); err == nil {
		t.Error("too many inputs were accepted")
	}
}

// A name with a path in it is not a file's name, wherever it came from.
func TestTraversalNamesAreRefused(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../escape", "a/b", `a\b`, ".", "..", ""} {
		if err := writeUnder(dir, bad, []byte("x")); err == nil {
			t.Errorf("%q was written", bad)
		}
	}
}

// checkScript accepts the three languages and refuses the rest.
func TestCheckScript(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.py")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ext, err := checkScript(p); err != nil || ext != ".py" {
		t.Errorf("py: %v %v", ext, err)
	}
	if _, err := checkScript(filepath.Join(dir, "a.go")); err == nil {
		t.Error("a Go file was accepted as a script")
	}
	if _, err := checkScript(""); err == nil {
		t.Error("an empty path was accepted")
	}
}
