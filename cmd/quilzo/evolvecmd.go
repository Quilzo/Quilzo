// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/atomicfile"
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
      [--test-input FILE]... [--test-eval-input FILE]...
      [--task TEXT] [--weight NAME=NUMBER]... [--generations N] [--population N]
      [--seed N] [--timeout 2m] [--memory 2048] [--disk 512] [--out FILE]

The seed program may mark the part to evolve with # EVOLVE-BLOCK-START and
# EVOLVE-BLOCK-END; without markers the whole program evolves. A candidate
writes what it wants judged as files in output/; the evaluator receives them
in candidate/, with only the files given by --eval-input, and writes
output/metrics.json, one flat object of numbers.

The candidate cannot read the evaluator's files, but the search adapts to
the scores they produce, so the best program's score is a selection score.
To know how it does on cases it never saw, give a test set: --test-input
files the candidates run on and --test-eval-input files the evaluator
judges them with, used once on the final population and never to choose.
The evaluator must not run what a candidate wrote: it would run inside the
evaluator's box, beside its cases.

A weight counts a metric toward the score; a negative weight counts it
against, which minimises it (--weight time=-1). --memory is per process.
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
func evolveRun(root string, args []string, caller *Caller) (err error) {
	fs := flag.NewFlagSet("evolve run", flag.ContinueOnError)
	program := fs.String("program", "", "the seed program to improve (Python, R or Julia)")
	evaluator := fs.String("evaluator", "",
		"the evaluator: reads candidate/, writes output/metrics.json")
	task := fs.String("task", "", "what the program is for, told to the model")
	out := fs.String("out", "", "where to write the best program found, once the search succeeds (default: the run's directory)")
	seed := fs.Int64("seed", 0, "the search's random seed; 0 picks one, and the journal records it")
	generations := fs.Int("generations", 20, fmt.Sprintf(
		"how many generations, at most %d", evolve.MaxGenerations))
	population := fs.Int("population", 8, fmt.Sprintf(
		"how many programs to keep, between 2 and %d", evolve.MaxPopulation))
	timeout := fs.Duration("timeout", 2*time.Minute, "each run's time limit, at most 30m")
	memory := fs.Int("memory", 2048, "each process's memory limit in MB")
	disk := fs.Int("disk", 512, "each run's disk in MB, its workspace and home together")
	var inputs, evalInputs, testInputs, testEvalInputs, weights multiFlag
	fs.Var(&inputs, "input", "a file the candidate receives (repeatable)")
	fs.Var(&evalInputs, "eval-input",
		"a file only the evaluator receives, such as the cases it scores (repeatable)")
	fs.Var(&testInputs, "test-input", "a file the candidates receive for the test set (repeatable)")
	fs.Var(&testEvalInputs, "test-eval-input",
		"a file the evaluator receives for the test set, never used to choose (repeatable)")
	fs.Var(&weights, "weight", "NAME=NUMBER, how a metric counts; negative counts against (repeatable; default: the mean)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Both: a search runs programs in the box, as a research run does, and
	// spends the store's models, which is its own permission to give.
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	if err := authorise(root, caller, auth.ActUseModels, "/"); err != nil {
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
		return fmt.Errorf("each process's memory limit is between 1 and 65536 MB")
	}
	if *disk < 1 || *disk > 65536 {
		return fmt.Errorf("each run's disk is between 1 and 65536 MB")
	}
	if len(testInputs) > 0 && len(testEvalInputs) == 0 {
		return fmt.Errorf("--test-input needs --test-eval-input: a test set is judged with cases of its own")
	}
	// Where the evaluator and its cases live is part of the seal: a file
	// every box can read is a file the candidate can read.
	for _, p := range append(append([]string{*evaluator}, evalInputs...), testEvalInputs...) {
		if abs, aerr := filepath.Abs(p); aerr == nil {
			if real, rerr := filepath.EvalSymlinks(abs); rerr == nil && agentbox.EveryBoxReads(real) {
				return fmt.Errorf("%s is under a directory every box can read, so a candidate could read it; "+
					"keep the evaluator and its cases somewhere else", p)
			}
		}
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
	candInputs, err := readInputs(inputs)
	if err != nil {
		return err
	}
	evalInputsRead, err := readInputs(evalInputs)
	if err != nil {
		return err
	}
	testCandRead, err := readInputs(testInputs)
	if err != nil {
		return err
	}
	testEvalRead, err := readInputs(testEvalInputs)
	if err != nil {
		return err
	}
	evaluatorBytes, err := os.ReadFile(*evaluator)
	if err != nil {
		return err
	}
	model, why := draftModelFor(root, caller, "evolve")
	if model == nil {
		return fmt.Errorf("a search needs a model to propose changes, and %s", why)
	}
	if *seed == 0 {
		*seed, err = randomSeed()
		if err != nil {
			return err
		}
	}

	id, err := evolve.NewID()
	if err != nil {
		return err
	}
	// Absolute, because a box is given absolute paths and the store's root
	// may be relative.
	dir, err := filepath.Abs(evolve.RunDir(root, id))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "programs"), 0o700); err != nil {
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
	// The evaluator's own bytes were read once above, are hashed into the
	// record, and are given to each evaluator box from memory: what is
	// sealed is what was hashed, and no later change to the file on disk
	// quietly becomes the thing scoring this search.
	runner := &boxRunner{backend: backend, runID: id, dir: dir,
		progSuffix: scriptSuffix[progExt], evalSuffix: scriptSuffix[evalExt],
		progInterp: progInterp, evalInterp: evalInterp,
		evaluatorBytes: evaluatorBytes, evalInputs: evalInputsRead, testEvalInputs: testEvalRead,
		timeout: *timeout, memory: *memory, disk: int64(*disk) << 20}

	details := map[string]string{
		"generations": fmt.Sprint(*generations),
		"seed":        fmt.Sprint(*seed),
		"model":       model.Name(),
		"program":     evolve.DigestOf(progBytes),
		"evaluator":   evolve.DigestOf(evaluatorBytes),
		"eval_inputs": inputsDigest(evalInputsRead),
	}
	if len(testEvalRead) > 0 {
		details["test_inputs"] = inputsDigest(append(append([]evolve.Input(nil), testCandRead...), testEvalRead...))
	}
	record(root, caller.auditRecord("evolve.run", dir, audit.Success, details))

	// Without inputs of its own, the test set's candidates run on the same
	// inputs as selection, and only the evaluator's cases differ.
	if len(testCandRead) == 0 {
		testCandRead = candInputs
	}
	journal := evolve.Journal{Path: filepath.Join(dir, "journal.jsonl")}
	search := &evolve.Search{
		Task: *task, Program: progBytes, Inputs: candInputs, Weights: wts,
		Generations: *generations, PopSize: *population,
		Model: model, ModelName: model.Name(), Runner: runner, Seed: *seed,
		Journal: journal, Test: len(testEvalRead) > 0, TestInputs: testCandRead,
		Save: func(code []byte, digest string) error {
			return saveProgram(filepath.Join(dir, "programs", digest+runner.progSuffix), code)
		},
		Progress: func(e evolve.Entry) {
			score := ""
			if e.Combined != nil {
				score = fmt.Sprintf(" %.6g", *e.Combined)
			}
			w.Human("  %s %d %s: %s%s\n", e.Phase, e.Generation, e.ID, e.Outcome, score)
		},
	}
	w.Human("search %s, seed %d, journal at %s\n", id, *seed, journal.Path)
	// Interrupting a search ends it the way a failure does: the population
	// is written and the end is recorded, so a stopped search is not one
	// with no record.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx,
		time.Duration(*generations+*population)*(*timeout)*2+10*time.Minute)
	defer cancel()
	best, runErr := search.Run(ctx)
	return evolveFinish(root, caller, dir, id, *seed, *out, runner.progSuffix, search, best, runErr)
}

// evolveFinish writes what a search found and records how it ended.
//
// The best program is written only when the search succeeded and found one:
// a failed search must not replace the file somebody named with nothing.
func evolveFinish(root string, caller *Caller, dir, id string, seed int64, out, suffix string,
	search *evolve.Search, best evolve.Individual, runErr error) error {

	outPath := ""
	if runErr == nil && len(best.Code) > 0 {
		outPath = out
		if outPath == "" {
			outPath = filepath.Join(dir, "best"+suffix)
		}
		if werr := atomicfile.Write(outPath, best.Code, 0o600); werr != nil {
			runErr = werr
			outPath = ""
		}
	}
	details := map[string]string{"seed": fmt.Sprint(seed)}
	if sum, ok := fileDigest(search.Journal.Path); ok {
		details["journal"] = sum
	}
	outcome := audit.Success
	if runErr != nil {
		outcome = audit.Failure
		details["error"] = clampStr(runErr.Error(), 300)
	}
	if best.Digest != "" {
		details["best"], details["digest"] = best.ID, best.Digest
		details["score"] = fmt.Sprintf("%.6g", best.Combined)
		if best.Test != nil {
			details["test_score"] = fmt.Sprintf("%.6g", *best.Test)
		}
	}
	record(root, caller.auditRecord("evolve.done", dir, outcome, details))

	result := map[string]any{"run": id, "seed": seed, "journal": search.Journal.Path, "ok": runErr == nil}
	if best.Digest != "" {
		result["best"] = map[string]any{"id": best.ID, "digest": best.Digest,
			"score": best.Combined, "test_score": best.Test, "metrics": best.Metrics, "program": outPath}
	}
	if runErr != nil {
		result["error"] = runErr.Error()
	}
	if !w.JSON(result) && best.Digest != "" {
		w.Human("best %s, score %.6g", best.ID, best.Combined)
		if best.Test != nil {
			w.Human(", test score %.6g", *best.Test)
		}
		if outPath != "" {
			w.Human(", program at %s", outPath)
		}
		w.Human("\n")
		names := make([]string, 0, len(best.Metrics))
		for k := range best.Metrics {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			w.Human("  %s=%.6g\n", k, best.Metrics[k])
		}
	}
	return runErr
}

// saveProgram keeps one program by its digest. The name is the content's
// digest, so a file already there already holds these bytes.
func saveProgram(path string, code []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(code); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// randomSeed picks a seed when none was given; the journal records it.
func randomSeed() (int64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(b[:]) & (1<<62 - 1)), nil
}

// inputsDigest names a set of inputs by their names and contents.
func inputsDigest(in []evolve.Input) string {
	h := sha256.New()
	for _, i := range in {
		fmt.Fprintf(h, "%s\x00%d\x00", i.Name, len(i.Bytes))
		h.Write(i.Bytes)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fileDigest is the SHA-256 of a file, when it can be read.
func fileDigest(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return evolve.DigestOf(data), true
}

// clampStr cuts a string for a record.
func clampStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
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
	evalInputs             []evolve.Input
	testEvalInputs         []evolve.Input
	timeout                time.Duration
	memory                 int
	disk                   int64
}

// RunCandidate implements evolve.Runner: the candidate, its inputs, its
// output area.
func (b *boxRunner) RunCandidate(ctx context.Context, code []byte, inputs []evolve.Input) (evolve.RunOutcome, error) {
	return b.run(ctx, "cand-", b.progInterp, "program"+b.progSuffix, code, inputs, nil)
}

// RunEvaluator implements evolve.Runner: the evaluator, its own inputs, and
// what the candidate wrote — nothing else.
func (b *boxRunner) RunEvaluator(ctx context.Context, outputs map[string][]byte, test bool) (evolve.RunOutcome, error) {
	inputs := b.evalInputs
	if test {
		inputs = b.testEvalInputs
	}
	// The seal's one crossing: the candidate's files, and only its files.
	return b.run(ctx, "eval-", b.evalInterp, "program"+b.evalSuffix, b.evaluatorBytes, inputs, outputs)
}

// run makes a workspace, places the program and its inputs and, for the
// evaluator, the candidate's files, runs it in a box with its disk
// watched, collects its output area, and removes everything it made.
func (b *boxRunner) run(ctx context.Context, prefix, interp, script string, code []byte,
	inputs []evolve.Input, candidate map[string][]byte) (evolve.RunOutcome, error) {

	workspace, err := os.MkdirTemp(b.dir, prefix)
	if err != nil {
		return evolve.RunOutcome{}, err
	}
	// Forced, because a program can make a directory it then takes its own
	// permissions off, and plain removal would leave it behind every run.
	defer removeAllForce(workspace)
	for _, in := range inputs {
		if err := writeUnder(workspace, in.Name, in.Bytes); err != nil {
			return evolve.RunOutcome{}, err
		}
	}
	if err := writeUnder(workspace, script, code); err != nil {
		return evolve.RunOutcome{}, err
	}
	if candidate != nil {
		cand := filepath.Join(workspace, "candidate")
		if err := os.Mkdir(cand, 0o700); err != nil {
			return evolve.RunOutcome{}, err
		}
		for name, data := range candidate {
			if err := writeUnder(cand, name, data); err != nil {
				return evolve.RunOutcome{}, err
			}
		}
	}
	if err := os.Mkdir(filepath.Join(workspace, "output"), 0o700); err != nil {
		return evolve.RunOutcome{}, err
	}
	home, err := os.MkdirTemp(b.dir, "home-")
	if err != nil {
		return evolve.RunOutcome{}, err
	}
	defer removeAllForce(home)
	sb := shell.Box{Backend: b.backend, RunID: b.runID, Agent: "evolve",
		Workspace: workspace, Home: home, Timeout: b.timeout, MemoryMB: b.memory}
	out, err := sb.RunWithin(ctx, shell.Command{Path: interp, Args: []string{script},
		Kind: shell.Kind{Writes: true}}, b.disk)
	if err != nil {
		return evolve.RunOutcome{}, err
	}
	files, cerr := collect(filepath.Join(workspace, "output"))
	if cerr != nil && out.Stopped == "" {
		out.Stopped = cerr.Error()
	}
	return toOutcome(out, files), nil
}

// toOutcome carries a shell output into the search's shape.
func toOutcome(out shell.Output, files map[string][]byte) evolve.RunOutcome {
	return evolve.RunOutcome{Exit: out.Exit, Stopped: out.Stopped, Took: out.Took,
		Text: out.Text, Outputs: files}
}

// writeUnder writes one new file at a safe name in dir.
//
// The names came from this program — inputs from file base names, outputs
// from a collected directory — but they are written into paths all the
// same, and the directory that produced them was one a candidate wrote to.
// A name with a separator or a parent in it is refused, and so is writing
// over a file already there: an input named like the program, or two inputs
// with one name, would otherwise replace what was placed first.
func writeUnder(dir, name string, data []byte) error {
	if name == "" || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
		return fmt.Errorf("%q is not a file's name", name)
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("two files would be named %s in one run", name)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// collect reads a run's output area: its files, bounded in count and size.
//
// Flat: a file in a subdirectory is not collected, and neither is anything
// that is not a regular file, so a link or a pipe a program left there is
// never followed or read.
func collect(dir string) (map[string][]byte, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("the output area could not be read: %w", err)
	}
	files := map[string][]byte{}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		if len(files) == evolve.MaxOutputs {
			return nil, fmt.Errorf("the run wrote more than %d files", evolve.MaxOutputs)
		}
		fi, err := e.Info()
		if err != nil {
			return nil, err
		}
		if fi.Size() > evolve.MaxOutputBytes {
			return nil, fmt.Errorf("%s is larger than a collected file may be", e.Name())
		}
		data, err := readRegular(filepath.Join(dir, e.Name()), evolve.MaxOutputBytes)
		if err != nil {
			return nil, err
		}
		files[e.Name()] = data
	}
	return files, nil
}

// readRegular reads a file that must be a regular file when opened, and no
// more than limit bytes of it. The box's processes are gone by now, so
// nothing can swap the file between the listing and the open; the check on
// the opened file is there all the same, and costs nothing.
func readRegular(path string, limit int64) ([]byte, error) {
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a file", filepath.Base(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a file", filepath.Base(path))
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than a collected file may be", filepath.Base(path))
	}
	return data, nil
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
		name := filepath.Base(p)
		if reservedInput(name) {
			return nil, fmt.Errorf("%s: an input may not be named program, candidate or output; rename it", p)
		}
		for _, in := range out {
			if in.Name == name {
				return nil, fmt.Errorf("two inputs are named %s; a run's inputs sit side by side by name", name)
			}
		}
		out = append(out, evolve.Input{Name: name, Bytes: data})
	}
	return out, nil
}

// reservedInput is a name a run's own files take: the program, and the
// candidate and output areas.
func reservedInput(name string) bool {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	return base == "program" || name == "candidate" || name == "output"
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
