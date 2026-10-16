// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evolve"
	"github.com/quilzo/quilzo/internal/shell"
)

// cmdEvolve searches over programs: a model proposes changes, candidates
// and a sealed evaluator each run in their own box, and every generation is
// journalled. See internal/evolve for the argument for the seal.
func cmdEvolve(root string, args []string) error {
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "run":
		return evolveRun(root, args[1:], resolveCaller(root, flagToken))
	default:
		fmt.Print(`quilzo evolve — search over programs, against an evaluator they cannot reach

  run --program FILE --evaluator FILE [--input FILE]... [--eval-input FILE]...
      [--task TEXT] [--weight NAME=NUMBER]... [--generations N] [--population N]
      [--seed N] [--timeout 2m] [--memory 2048] [--out FILE]

The seed program may mark the part to evolve with # EVOLVE-BLOCK-START and
# EVOLVE-BLOCK-END; without markers the whole program evolves. A candidate
writes what it wants judged under output/; the evaluator receives it under
candidate/, with only the inputs given by --eval-input, and writes
output/metrics.json, a flat object of numbers. Keep the cases worth
believing in --eval-input and out of the candidate's inputs: that is the
hold-out the seal protects.
`)
		if cmd != "" {
			return fmt.Errorf("unknown evolve command %q", cmd)
		}
		return nil
	}
}

// The bounds on what a run is handed, beyond the search's own: inputs are
// files copied into boxes, so they are counted and sized like everything
// else a program can reach.
const (
	MaxInputs   = 16
	MaxInputAbs = 64 << 20
)

// scriptSuffix spells an interpreter's extension the way its own files are
// named: .r seeds become .R on disk, because R cares.
var scriptSuffix = map[string]string{".py": ".py", ".r": ".R", ".jl": ".jl"}

// evolveRun performs one search, as the caller who asked.
func evolveRun(root string, args []string, caller *Caller) error {
	fs := flag.NewFlagSet("evolve run", flag.ContinueOnError)
	program := fs.String("program", "", "the seed program to improve (Python, R or Julia)")
	evaluator := fs.String("evaluator", "",
		"the evaluator: reads candidate/, writes output/metrics.json")
	task := fs.String("task", "", "what the program is for, told to the model")
	out := fs.String("out", "", "where to write the best program found (default: the run's directory)")
	seed := fs.Int64("seed", 0, "the search's random seed; 0 picks one and records it")
	generations := fs.Int("generations", 20, fmt.Sprintf(
		"how many generations, at most %d", evolve.MaxGenerations))
	population := fs.Int("population", 8, fmt.Sprintf(
		"how many programs to keep, between 2 and %d", evolve.MaxPopulation))
	timeout := fs.Duration("timeout", 2*time.Minute, "each run's time limit, at most 30m")
	memory := fs.Int("memory", 2048, "each run's memory limit in MB")
	var inputs, evalInputs, weights multiFlag
	fs.Var(&inputs, "input", "a file the candidate receives (repeatable)")
	fs.Var(&evalInputs, "eval-input",
		"a file only the evaluator receives, such as held-out cases (repeatable)")
	fs.Var(&weights, "weight", "NAME=NUMBER, how a metric counts (repeatable; default: the mean)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	wts, err := evolve.ParseWeights(weights)
	if err != nil {
		return err
	}

	progExt, err := checkScript(*program)
	if err != nil {
		return err
	}
	evalExt, err := checkScript(*evaluator)
	if err != nil {
		return err
	}
	if len(*task) > evolve.MaxTask {
		return fmt.Errorf("the task is longer than %d characters", evolve.MaxTask)
	}
	if *generations < 1 || *generations > evolve.MaxGenerations {
		return fmt.Errorf("a search runs between 1 and %d generations", evolve.MaxGenerations)
	}
	if *population < 2 || *population > evolve.MaxPopulation {
		return fmt.Errorf("a population is between 2 and %d programs", evolve.MaxPopulation)
	}
	if *timeout <= 0 || *timeout > 30*time.Minute {
		return fmt.Errorf("each run's time limit is between a second and thirty minutes")
	}
	if *memory <= 0 || *memory > 65536 {
		return fmt.Errorf("each run's memory limit is between 1 and 65536 MB")
	}
	progBytes, err := os.ReadFile(*program)
	if err != nil {
		return err
	}
	if err := evolve.ValidateProgram(progBytes); err != nil {
		return fmt.Errorf("the seed program: %w", err)
	}
	progInterp, err := shell.Find(interpreters[progExt])
	if err != nil {
		return err
	}
	evalInterp, err := shell.Find(interpreters[evalExt])
	if err != nil {
		return err
	}
	model, why := draftModelFor(root, caller, "evolve")
	if model == nil {
		return fmt.Errorf("a search needs a model to propose changes, and %s", why)
	}
	candInputs, err := readInputs(inputs)
	if err != nil {
		return err
	}
	evalInputsRead, err := readInputs(evalInputs)
	if err != nil {
		return err
	}

	id, err := evolve.NewID()
	if err != nil {
		return err
	}
	dir := evolve.RunDir(root, id)
	if err := os.MkdirAll(filepath.Join(dir, "candidates"), 0o755); err != nil {
		return err
	}
	// The same seam the research runs use: the test backend when one is
	// standing in, the real one otherwise.
	backend := testBackend
	if backend == nil {
		var berr error
		backend, berr = programBackend(root, "native", "")
		if berr != nil {
			return berr
		}
	}
	runner := &boxRunner{backend: backend, runID: id, dir: dir,
		progSuffix: scriptSuffix[progExt], evalSuffix: scriptSuffix[evalExt],
		progInterp: progInterp, evalInterp: evalInterp,
		evaluatorBytes: nil, inputs: candInputs, evalInputs: evalInputsRead,
		timeout: *timeout, memory: *memory}
	// The evaluator's own bytes are read once here, hashed into the record,
	// and given to each evaluator box from memory: what is sealed is what
	// was hashed, and no later change to the file on disk quietly becomes
	// the thing scoring this search.
	runner.evaluatorBytes, err = os.ReadFile(*evaluator)
	if err != nil {
		return err
	}

	record(root, caller.auditRecord("evolve.run", dir, audit.Success, map[string]string{
		"generations": fmt.Sprint(*generations),
		"program":     evolve.DigestOf(progBytes),
		"evaluator":   evolve.DigestOf(runner.evaluatorBytes),
	}))

	search := &evolve.Search{
		Task: *task, Program: progBytes, Inputs: candInputs, Weights: wts,
		Generations: *generations, PopSize: *population,
		Model: model, Runner: runner, Seed: *seed,
		Journal: evolve.Journal{Path: filepath.Join(dir, "journal.jsonl")},
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(*generations)*(*timeout)*2+10*time.Minute)
	defer cancel()
	best, err := search.Run(ctx)

	// The population's programs, kept for their digests.
	for _, ind := range search.Population() {
		if werr := os.WriteFile(filepath.Join(dir, "candidates", ind.ID+runner.progSuffix),
			ind.Code, 0o644); werr != nil && err == nil {
			err = werr
		}
	}
	outPath := *out
	if outPath == "" {
		outPath = filepath.Join(dir, "best"+runner.progSuffix)
	}
	if werr := os.WriteFile(outPath, best.Code, 0o644); werr != nil && err == nil {
		err = werr
	}
	score, _ := evolve.Combine(best.Metrics, wts)
	record(root, caller.auditRecord("evolve.done", dir, audit.Success, map[string]string{
		"best": best.ID, "digest": best.Digest, "score": fmt.Sprintf("%.6g", score),
	}))
	w.Human("best %s, combined %.6g, program at %s\n", best.ID, score, outPath)
	names := make([]string, 0, len(best.Metrics))
	for k := range best.Metrics {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		w.Human("  %s=%.6g\n", k, best.Metrics[k])
	}
	return err
}

// boxRunner runs candidates and the evaluator in boxes of their own.
//
// One workspace per run, made under the search's directory and removed
// after: nothing a candidate or an evaluator wrote persists except what is
// collected here, and the collected files are the only things that ever
// cross from one side to the other.
type boxRunner struct {
	backend                agentbox.Backend
	runID, dir             string
	progSuffix, evalSuffix string
	progInterp, evalInterp string
	evaluatorBytes         []byte
	inputs, evalInputs     []evolve.Input
	timeout                time.Duration
	memory                 int
}

// RunCandidate implements evolve.Runner: the candidate, its inputs, its
// output area.
func (b *boxRunner) RunCandidate(ctx context.Context, code []byte, inputs []evolve.Input) (evolve.RunOutcome, error) {
	workspace, err := os.MkdirTemp(b.dir, "cand-")
	if err != nil {
		return evolve.RunOutcome{}, err
	}
	defer os.RemoveAll(workspace)
	if err := os.WriteFile(filepath.Join(workspace, "program"+b.progSuffix), code, 0o644); err != nil {
		return evolve.RunOutcome{}, err
	}
	if err := placeInputs(workspace, inputs); err != nil {
		return evolve.RunOutcome{}, err
	}
	if err := os.MkdirAll(filepath.Join(workspace, "output"), 0o755); err != nil {
		return evolve.RunOutcome{}, err
	}
	out, err := b.box(ctx, workspace, b.progInterp, "program"+b.progSuffix)
	if err != nil {
		return evolve.RunOutcome{}, err
	}
	files, cerr := collect(filepath.Join(workspace, "output"))
	if cerr != nil {
		out.Stopped = cerr.Error()
	}
	return toOutcome(out, files), nil
}

// RunEvaluator implements evolve.Runner: the evaluator, its own inputs, and
// what the candidate wrote — nothing else.
func (b *boxRunner) RunEvaluator(ctx context.Context, outputs map[string][]byte) (evolve.RunOutcome, error) {
	workspace, err := os.MkdirTemp(b.dir, "eval-")
	if err != nil {
		return evolve.RunOutcome{}, err
	}
	defer os.RemoveAll(workspace)
	if err := os.WriteFile(filepath.Join(workspace, "program"+b.evalSuffix), b.evaluatorBytes, 0o644); err != nil {
		return evolve.RunOutcome{}, err
	}
	if err := placeInputs(workspace, b.evalInputs); err != nil {
		return evolve.RunOutcome{}, err
	}
	// The seal's one crossing: the candidate's files, and only its files.
	cand := filepath.Join(workspace, "candidate")
	if len(outputs) > 0 {
		if err := os.MkdirAll(cand, 0o755); err != nil {
			return evolve.RunOutcome{}, err
		}
		for name, data := range outputs {
			if err := writeUnder(cand, name, data); err != nil {
				return evolve.RunOutcome{}, err
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(workspace, "output"), 0o755); err != nil {
		return evolve.RunOutcome{}, err
	}
	out, err := b.box(ctx, workspace, b.evalInterp, "program"+b.evalSuffix)
	if err != nil {
		return evolve.RunOutcome{}, err
	}
	files, cerr := collect(filepath.Join(workspace, "output"))
	if cerr != nil {
		out.Stopped = cerr.Error()
	}
	return toOutcome(out, files), nil
}

// box runs one command in a fresh home, the way research runs do.
func (b *boxRunner) box(ctx context.Context, workspace, interp, script string) (shell.Output, error) {
	home, err := os.MkdirTemp(b.dir, "home-")
	if err != nil {
		return shell.Output{}, err
	}
	defer os.RemoveAll(home)
	sb := shell.Box{Backend: b.backend, RunID: b.runID, Agent: "evolve",
		Workspace: workspace, Home: home, Timeout: b.timeout, MemoryMB: b.memory}
	return sb.Run(ctx, shell.Command{Path: interp, Args: []string{script},
		Kind: shell.Kind{Writes: true}})
}

// toOutcome carries a shell output into the search's shape.
func toOutcome(out shell.Output, files map[string][]byte) evolve.RunOutcome {
	return evolve.RunOutcome{Exit: out.Exit, Stopped: out.Stopped, Took: out.Took,
		Text: out.Text, Outputs: files}
}

// placeInputs writes a run's inputs into its workspace by name.
func placeInputs(workspace string, inputs []evolve.Input) error {
	for _, in := range inputs {
		if err := writeUnder(workspace, in.Name, in.Bytes); err != nil {
			return err
		}
	}
	return nil
}

// writeUnder writes one file at a safe relative path.
//
// The names came from this program — inputs from file base names, outputs
// from walking a collected directory — but they are written into paths all
// the same, and the walk that produced them ran in a world a candidate
// wrote to. A name with a separator or a parent in it is refused.
func writeUnder(dir, name string, data []byte) error {
	if name == "" || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
		return fmt.Errorf("%q is not a file's name", name)
	}
	return os.WriteFile(filepath.Join(dir, name), data, 0o644)
}

// collect reads a run's output area: the files, bounded in count and size.
func collect(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if len(files) >= evolve.MaxOutputs {
			return fmt.Errorf("the run wrote more than %d files", evolve.MaxOutputs)
		}
		fi, serr := d.Info()
		if serr != nil {
			return serr
		}
		if fi.Size() > evolve.MaxOutputBytes {
			return fmt.Errorf("%s is larger than a collected file may be", rel)
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// readInputs loads the input files a run was named, bounded.
func readInputs(paths []string) ([]evolve.Input, error) {
	if len(paths) > MaxInputs {
		return nil, fmt.Errorf("more than %d inputs", MaxInputs)
	}
	var out []evolve.Input
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a file", p)
		}
		if fi.Size() > MaxInputAbs {
			return nil, fmt.Errorf("%s is larger than an input may be", p)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, evolve.Input{Name: filepath.Base(p), Bytes: data})
	}
	return out, nil
}

// checkScript validates a script path's shape and returns its extension.
func checkScript(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("a path is required")
	}
	ext := strings.ToLower(filepath.Ext(path))
	if _, ok := interpreters[ext]; !ok {
		return "", fmt.Errorf("%s is not a script this runs: Python (.py), R (.R) or Julia (.jl)", path)
	}
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return ext, nil
}
