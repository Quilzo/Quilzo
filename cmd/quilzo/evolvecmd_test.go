// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	// One run directory, with a journal of two entries and every program
	// that ran kept by its digest.
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
	if fi, _ := os.Stat(filepath.Join(runDir, "best.py")); fi == nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the best program is not private to its owner: %v", fi)
	}
	for _, e := range entries {
		if _, err := os.Stat(filepath.Join(runDir, "programs", e.Digest+".py")); err != nil {
			t.Errorf("%s ran and its program was not kept: %v", e.ID, err)
		}
	}
	if entries[0].Seed != 11 || entries[0].Model != "answering" {
		t.Errorf("the journal does not record the seed and model: %#v", entries[0])
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

// boxed sets up a real box for a search test, or skips.
func boxed(t *testing.T) string {
	t.Helper()
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
	// The writer is the package's, and a test that switches it to JSON
	// must not leave it that way for whichever test runs next.
	saved := w
	t.Cleanup(func() { w = saved })
	w = out.New(false)
	return root
}

// A diff that never applies: the search goes on past the seed without the
// model changing anything, so a test can look at what the seed did.
const noChange = "<<<<<<< SEARCH\nnot in the program\n=======\nx\n>>>>>>> REPLACE\n"

// Programs written to break the seal, each run as the seed through the
// real boxes. The evaluator scores what the candidate's output says, so a
// candidate that reached the evaluator's world would score 1000.
func TestAHostileCandidateCannotReachTheEvaluator(t *testing.T) {
	root := boxed(t)
	dir := t.TempDir()
	cases := filepath.Join(dir, "cases.json")
	if err := os.WriteFile(cases, []byte(`{"secret": 1000}`), 0o600); err != nil {
		t.Fatal(err)
	}
	evalPath := filepath.Join(dir, "evaluator.py")
	if err := os.WriteFile(evalPath, []byte(`import json, os
names = sorted(os.listdir("candidate")) if os.path.isdir("candidate") else []
v = json.load(open("candidate/result.json"))["value"] if "result.json" in names else 0
json.dump({"value": v, "files": len(names)}, open("output/metrics.json", "w"))
`), 0o600); err != nil {
		t.Fatal(err)
	}
	hostile := map[string]string{
		"reads the evaluator's cases by their path": `import json
v = 0
for p in [` + "\"" + cases + "\", \"" + evalPath + "\"" + `]:
    try:
        open(p).read(); v = 1000
    except Exception:
        pass
json.dump({"value": v}, open("output/result.json", "w"))
`,
		"writes the evaluator's metrics itself": `import json, os
json.dump({"value": 1000, "files": 0}, open("output/metrics.json", "w"))
json.dump({"value": 1}, open("output/result.json", "w"))
for p in ["../output/metrics.json", "/output/metrics.json"]:
    try:
        open(p, "w").write('{"value": 1000}')
    except Exception:
        pass
`,
		"leaves a link and a pipe in its output": `import json, os
json.dump({"value": 1}, open("output/result.json", "w"))
os.symlink("` + cases + `", "output/link.json")
os.mkfifo("output/pipe")
`,
	}
	for name, seed := range hostile {
		t.Run(name, func(t *testing.T) {
			prog := filepath.Join(t.TempDir(), "seed.py")
			if err := os.WriteFile(prog, []byte(seed), 0o600); err != nil {
				t.Fatal(err)
			}
			draftModelSeam = func(string) (assist.Model, string) { return &answeringModel{answers: []string{noChange}}, "" }
			t.Cleanup(func() { draftModelSeam = nil })
			w = out.New(true)
			var buf strings.Builder
			w.Out = &buf
			err := evolveRun(root, []string{"--program", prog, "--evaluator", evalPath,
				"--eval-input", cases, "--generations", "1", "--population", "2", "--timeout", "30s"}, asAdmin("dana"))
			if err != nil {
				t.Fatalf("the search failed: %v", err)
			}
			var res struct {
				Best struct {
					Metrics map[string]float64 `json:"metrics"`
				} `json:"best"`
			}
			if err := json.Unmarshal([]byte(buf.String()), &res); err != nil {
				t.Fatalf("%v: %s", err, buf.String())
			}
			if v := res.Best.Metrics["value"]; v != 1 && v != 0 {
				t.Errorf("the candidate reached the evaluator's world: it scored %v", v)
			}
			if f := res.Best.Metrics["files"]; f != 1 && f != 2 {
				t.Errorf("the evaluator was handed %v files; only the candidate's regular files cross", f)
			}
		})
	}
}

// A candidate that breaks the limits on what it may leave is not scored,
// and leaves nothing behind in the store.
func TestACandidateOverItsLimitsIsNotScoredAndLeavesNothing(t *testing.T) {
	root := boxed(t)
	saved := shell.QuotaEvery
	shell.QuotaEvery = 100 * time.Millisecond
	t.Cleanup(func() { shell.QuotaEvery = saved })
	eval := filepath.Join(t.TempDir(), "evaluator.py")
	if err := os.WriteFile(eval, []byte(evolveEvaluator), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, seed := range map[string][2]string{
		"too many files": {"more than 16 files", `import json
for i in range(17):
    open("output/f%d" % i, "w").write("x")
json.dump({"value": 1000}, open("output/result.json", "w"))
`},
		"its output area locked": {"output area could not be read", `import json, os
json.dump({"value": 1000}, open("output/result.json", "w"))
os.makedirs("output/stuck/deeper")
os.chmod("output/stuck", 0)
os.chmod("output", 0)
`},
		"more disk than it has": {"went over its 1 MiB of disk", `import json, time
json.dump({"value": 1000}, open("output/result.json", "w"))
with open("big", "wb") as f:
    f.write(b"0" * (3 << 20))
time.sleep(5)
`},
	} {
		t.Run(name, func(t *testing.T) {
			why, seed := seed[0], seed[1]
			prog := filepath.Join(t.TempDir(), "seed.py")
			if err := os.WriteFile(prog, []byte(seed), 0o600); err != nil {
				t.Fatal(err)
			}
			draftModelSeam = func(string) (assist.Model, string) { return &answeringModel{}, "" }
			t.Cleanup(func() { draftModelSeam = nil })
			out := filepath.Join(t.TempDir(), "keep.py")
			if err := os.WriteFile(out, []byte("somebody's program"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := evolveRun(root, []string{"--program", prog, "--evaluator", eval, "--generations", "1",
				"--population", "2", "--timeout", "30s", "--disk", "1", "--out", out}, asAdmin("dana"))
			if err == nil || !strings.Contains(err.Error(), "seed program did not run") ||
				!strings.Contains(err.Error(), why) {
				t.Fatalf("a seed over its limits was searched from, or refused for another reason: %v", err)
			}
			if kept, _ := os.ReadFile(out); string(kept) != "somebody's program" {
				t.Errorf("a failed search replaced --out with %q", kept)
			}
			runs, _ := os.ReadDir(filepath.Join(root, "evolve"))
			for _, r := range runs {
				left, _ := os.ReadDir(filepath.Join(root, "evolve", r.Name()))
				for _, f := range left {
					if n := f.Name(); strings.HasPrefix(n, "cand-") || strings.HasPrefix(n, "eval-") || strings.HasPrefix(n, "home-") {
						t.Errorf("a box's directory survived: %s", n)
					}
				}
			}
		})
	}
}

// The store's root is relative by default, and a search works from one.
func TestASearchWorksFromARelativeRoot(t *testing.T) {
	root := boxed(t)
	t.Chdir(filepath.Dir(root))
	dir := t.TempDir()
	prog, eval := filepath.Join(dir, "seed.py"), filepath.Join(dir, "evaluator.py")
	if err := os.WriteFile(prog, []byte(evolveSeed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eval, []byte(evolveEvaluator), 0o600); err != nil {
		t.Fatal(err)
	}
	draftModelSeam = func(string) (assist.Model, string) { return &answeringModel{answers: []string{noChange}}, "" }
	t.Cleanup(func() { draftModelSeam = nil })
	if err := evolveRun(filepath.Base(root), []string{"--program", prog, "--evaluator", eval,
		"--generations", "1", "--population", "2", "--timeout", "30s"}, asAdmin("dana")); err != nil {
		t.Fatalf("a search from a relative root failed: %v", err)
	}
}

// An evaluator or its cases kept where every box reads is refused, and so
// are inputs named like a run's own files or like each other.
func TestWhatWouldBreakTheSealIsRefusedBeforeAnythingRuns(t *testing.T) {
	if !agentbox.EveryBoxReads("/usr/lib/python3/thing.py") || agentbox.EveryBoxReads("/home/x/cases.json") ||
		agentbox.EveryBoxReads("/usrx/a") {
		t.Error("EveryBoxReads is wrong about which paths every box reads")
	}
	dir := t.TempDir()
	for _, name := range []string{"program.py", "candidate", "output", "program.R"} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte("x"), 0o600)
		if _, err := readInputs([]string{p}); err == nil {
			t.Errorf("an input named %s was accepted", name)
		}
	}
	a, b := filepath.Join(dir, "a", "cases.csv"), filepath.Join(dir, "b", "cases.csv")
	for _, p := range []string{a, b} {
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		_ = os.WriteFile(p, []byte("x"), 0o600)
	}
	if _, err := readInputs([]string{a, b}); err == nil {
		t.Error("two inputs with one name were accepted")
	}
}

// The demonstration's packing bench, run the way its README says: the
// search finds the parcel first fit wastes on Monday, and the test set
// says what that is worth on Tuesday's orders, which it never chose by.
func TestTheDemoPackingSearchSavesAParcel(t *testing.T) {
	root := boxed(t)
	work := t.TempDir()
	t.Chdir(work)
	store := filepath.Join(work, "shop")
	if err := cmdInit(store); err != nil {
		t.Fatal(err)
	}
	if err := cmdDemo(store, []string{"--templates", filepath.Join(work, "templates"),
		"--examples", "examples"}); err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(filepath.Join("examples", "evolve", "README.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// The command as the README prints it, continuation lines joined.
	cmdline := strings.ReplaceAll(string(readme), "\\\n", " ")
	i := strings.Index(cmdline, "quilzo evolve run ")
	if i < 0 {
		t.Fatal("the README has no evolve command")
	}
	line := cmdline[i+len("quilzo evolve run "):]
	line = line[:strings.Index(line, "\n")]
	args := splitArgs(line)
	draftModelSeam = func(string) (assist.Model, string) {
		return &answeringModel{answers: []string{
			"<<<<<<< SEARCH\n    for item in items:\n=======\n    for item in sorted(items, key=lambda i: -i[\"grams\"]):\n>>>>>>> REPLACE\n",
		}}, ""
	}
	t.Cleanup(func() { draftModelSeam = nil })
	w = out.New(true)
	var buf strings.Builder
	w.Out = &buf
	if err := evolveRun(root, append(args, "--generations", "1"), asAdmin("dana")); err != nil {
		t.Fatalf("the README's search failed: %v\n%s", err, buf.String())
	}
	var res struct {
		Best struct {
			Metrics   map[string]float64 `json:"metrics"`
			TestScore *float64           `json:"test_score"`
		} `json:"best"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &res); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	if res.Best.Metrics["parcels"] != 5 {
		t.Errorf("the search did not find the five-parcel packing: %v", res.Best.Metrics)
	}
	if res.Best.TestScore == nil || *res.Best.TestScore != -5 {
		t.Errorf("the test set was not scored, or not as five parcels: %v", res.Best.TestScore)
	}
}

// splitArgs splits a command line on spaces, keeping double-quoted words.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ' ' && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
