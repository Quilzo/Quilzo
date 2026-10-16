// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evolve

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// The loop: mutate, run, judge, record, keep.
//
// One generation is one turn of AlphaEvolve's cycle, made synchronous and
// small enough to audit: pick a parent from the population, ask the model
// for diffs, apply them to the parent's evolvable region, run the new
// program in a box, and — only if it ran within its limits — hand what it
// wrote to the evaluator in its own box, parse the metrics, and keep the
// program if it beats the population's floor. Every turn writes its journal
// line before the population changes, so a crash cannot leave a kept
// program with no record.

// Model is what proposes changes: the gateway's own interface, so the
// search is charged and logged like every other thing this program asks a
// model to do.
type Model interface {
	Complete(ctx context.Context, system, user string) (string, error)
}

// Runner runs programs in boxes, one side at a time. The two methods are
// the seal made an interface: nothing in this package can run the evaluator
// with the candidate, or the candidate with the evaluator, because nothing
// here has a way to run them together.
type Runner interface {
	// RunCandidate runs a program with its inputs and reports what it
	// wrote in its output area.
	RunCandidate(ctx context.Context, code []byte, inputs []Input) (RunOutcome, error)
	// RunEvaluator runs the evaluator over what a candidate wrote, with the
	// evaluator's selection inputs, or its test inputs when test is true.
	RunEvaluator(ctx context.Context, outputs map[string][]byte, test bool) (RunOutcome, error)
}

// Search is one evolution run's configuration and state.
type Search struct {
	Task        string
	Program     []byte // the seed, validated before the loop starts
	Inputs      []Input
	Weights     Weights
	Generations int
	PopSize     int
	Model       Model
	// ModelName is recorded on the journal's first entry.
	ModelName string
	Runner    Runner
	Journal   Journal
	Seed      int64
	// TestInputs, when Test is set, are what the candidates receive for the
	// final scoring on the test set; the evaluator gets its test inputs.
	Test       bool
	TestInputs []Input
	// Save keeps a program by its digest before it runs, so every program
	// the journal names can be read back, kept or not.
	Save func(code []byte, digest string) error
	// Progress is told each journal entry as it is written.
	Progress func(Entry)
	// Now is the clock; the journal stamps with it.
	Now func() time.Time

	pop     []Individual
	failWhy string
	failTXT string
	rng     *randSource
}

// Best returns the standing best program.
func (s *Search) Best() Individual {
	if len(s.pop) == 0 {
		return Individual{}
	}
	return s.pop[0]
}

// Population returns the standing population, best first. The slice is a
// copy, so the search's own order cannot be shuffled through it.
func (s *Search) Population() []Individual {
	out := make([]Individual, len(s.pop))
	copy(out, s.pop)
	return out
}

// Run performs the search.
//
// The seed program is evaluated first — generation 0 — so the population
// starts from a measurement rather than an assumption. A seed that does not
// run within its limits is an error: evolving from a program that never
// worked optimises the wrong baseline.
func (s *Search) Run(ctx context.Context) (Individual, error) {
	if err := ValidateProgram(s.Program); err != nil {
		return Individual{}, err
	}
	if s.Generations < 1 || s.Generations > MaxGenerations {
		return Individual{}, fmt.Errorf("a search runs between 1 and %d generations",
			MaxGenerations)
	}
	if s.PopSize < 2 || s.PopSize > MaxPopulation {
		return Individual{}, fmt.Errorf("a population is between 2 and %d programs", MaxPopulation)
	}
	if s.Model == nil || s.Runner == nil {
		return Individual{}, fmt.Errorf("a search needs a model and a runner")
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Seed == 0 {
		s.Seed = time.Now().UnixNano()
	}
	s.rng = newRNG(s.Seed)

	seed := Individual{ID: "c_seed", Code: append([]byte(nil), s.Program...),
		Digest: DigestOf(s.Program), Gen: 0}
	if err := s.save(seed); err != nil {
		return Individual{}, err
	}
	outcome, err := s.Runner.RunCandidate(ctx, seed.Code, s.Inputs)
	first := Entry{Generation: 0, ID: seed.ID, Digest: seed.Digest, Seed: s.Seed,
		Model: s.ModelName, Applied: true, Exit: outcome.Exit, Stopped: outcome.Stopped,
		TookMS: outcome.Took.Milliseconds()}
	if failed(outcome, err) {
		first.Outcome = "the seed program did not run"
		first.Note = runNote(outcome, err)
		_ = s.write(first)
		return Individual{}, fmt.Errorf(
			"the seed program did not run, and a search starts from one that does: %s",
			runNote(outcome, err))
	}
	seed.Metrics, err = s.judge(ctx, outcome, false)
	if err == nil {
		seed.Combined, err = Combine(seed.Metrics, s.Weights)
	}
	if err != nil {
		first.Outcome = "the seed program could not be judged"
		first.Note = err.Error()
		_ = s.write(first)
		return Individual{}, fmt.Errorf("the seed program could not be judged: %w", err)
	}
	first.Outcome, first.Metrics, first.Combined, first.Kept = "the seed program",
		seed.Metrics, &seed.Combined, true
	if err := s.write(first); err != nil {
		return Individual{}, err
	}
	s.pop = []Individual{seed}

	for gen := 1; gen <= s.Generations; gen++ {
		if ctx.Err() != nil {
			return s.pop[0], ctx.Err()
		}
		if err := s.generation(ctx, gen); err != nil {
			return s.pop[0], err
		}
	}
	if s.Test {
		if err := s.test(ctx); err != nil {
			return s.pop[0], err
		}
	}
	return s.pop[0], nil
}

// generation is one turn. Its error ends the search; everything a program
// can do wrong is a journalled refusal and the search goes on.
func (s *Search) generation(ctx context.Context, gen int) error {
	parent := s.pick()
	id := fmt.Sprintf("c_%06d", gen)
	e := Entry{Generation: gen, ID: id, Parent: parent.ID}
	refuse := func(outcome, why string) error {
		e.Outcome = outcome
		s.failWhy, s.failTXT = why, ""
		return s.write(e)
	}
	answer, err := s.Model.Complete(ctx, SystemPrompt(),
		UserPrompt(s.Task, s.pop, parent, s.failWhy, s.failTXT))
	if err != nil {
		e.Outcome, e.Note = "the model did not answer", err.Error()
		_ = s.write(e)
		return fmt.Errorf("the model did not answer in generation %d: %w", gen, err)
	}
	e.Diff = clip(answer, MaxDiffKept)
	diffs, derr := ParseDiff(answer)
	if derr != nil {
		e.Note = derr.Error()
		return refuse("the answer had no usable diff", "the proposed change did not parse as diff blocks")
	}
	code, aerr := Apply(regionOf(parent.Code), diffs)
	if aerr != nil {
		e.Note = aerr.Error()
		return refuse("the diff did not apply", "the proposed change did not apply to the program to change")
	}
	codeBytes := []byte(code)
	if verr := ValidateProgram(codeBytes); verr != nil {
		e.Note = verr.Error()
		return refuse("the changed program is not usable", "the changed program was too large or lost its block markers")
	}
	ind := Individual{ID: id, Code: codeBytes, Digest: DigestOf(codeBytes), Gen: gen, Parent: parent.ID}
	e.Applied, e.Digest = true, ind.Digest
	// A program already in the population is not run again: it would score
	// what it scored, and a copy kept twice crowds out a different one.
	for _, p := range s.pop {
		if p.Digest == ind.Digest {
			e.Note = "the same program as " + p.ID
			return refuse("a program already in the population", "the proposed change made a program that is already in the population")
		}
	}
	if err := s.save(ind); err != nil {
		return err
	}
	outcome, rerr := s.Runner.RunCandidate(ctx, ind.Code, s.Inputs)
	e.Exit, e.Stopped, e.TookMS = outcome.Exit, outcome.Stopped, outcome.Took.Milliseconds()
	if failed(outcome, rerr) {
		e.Outcome, e.Note = "the program ran and failed", runNote(outcome, rerr)
		s.failWhy, s.failTXT = "The last program did not finish within its limits.", outcome.Text
		return s.write(e)
	}
	metrics, merr := s.judge(ctx, outcome, false)
	if merr != nil {
		e.Outcome, e.Note = "the evaluator refused it", merr.Error()
		s.failWhy, s.failTXT = "The last program ran, and the evaluator could not score what it wrote.", outcome.Text
		return s.write(e)
	}
	ind.Metrics, e.Metrics = metrics, metrics
	combined, cerr := Combine(metrics, s.Weights)
	if cerr != nil {
		e.Outcome, e.Note = "its score could not be combined", cerr.Error()
		s.failWhy, s.failTXT = "The last program's metrics could not be combined into a score.", ""
		return s.write(e)
	}
	ind.Combined, e.Combined = combined, &combined
	e.Kept = len(s.pop) < s.PopSize || better(ind, s.pop[len(s.pop)-1])
	e.Outcome = "judged"
	if err := s.write(e); err != nil {
		return err
	}
	if e.Kept {
		s.insert(ind)
		s.failWhy, s.failTXT = "", ""
	} else {
		s.failWhy, s.failTXT = "The last program ran and scored below every program kept.", outcome.Text
	}
	return nil
}

// test scores the final population once on the test set: each program run
// on the test inputs, its output judged with the evaluator's test inputs.
// The score is reported, never used to choose: the best program is still
// the one the selection cases chose.
func (s *Search) test(ctx context.Context) error {
	for i := range s.pop {
		ind := &s.pop[i]
		e := Entry{Phase: "test", Generation: ind.Gen, ID: ind.ID, Digest: ind.Digest, Applied: true}
		outcome, err := s.Runner.RunCandidate(ctx, ind.Code, s.TestInputs)
		e.Exit, e.Stopped, e.TookMS = outcome.Exit, outcome.Stopped, outcome.Took.Milliseconds()
		if failed(outcome, err) {
			e.Outcome, e.Note = "it did not run on the test inputs", runNote(outcome, err)
		} else if metrics, merr := s.judge(ctx, outcome, true); merr != nil {
			e.Outcome, e.Note = "the evaluator refused its test output", merr.Error()
		} else if score, cerr := Combine(metrics, s.Weights); cerr != nil {
			e.Outcome, e.Metrics, e.Note = "its test score could not be combined", metrics, cerr.Error()
		} else {
			e.Outcome, e.Metrics, e.Combined = "tested", metrics, &score
			ind.Test = &score
		}
		if err := s.write(e); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

// failed says a run is not one to judge: it errored, exited non-zero, or
// was stopped for going over a limit, whatever it exited with.
func failed(out RunOutcome, err error) bool {
	return err != nil || out.Exit != 0 || out.Stopped != ""
}

// judge hands a candidate's outputs to the sealed evaluator and reads the
// metrics back. This is the only line between the two sides, and it carries
// the candidate's files and nothing else.
func (s *Search) judge(ctx context.Context, candidate RunOutcome, test bool) (map[string]float64, error) {
	out, err := s.Runner.RunEvaluator(ctx, candidate.Outputs, test)
	if err != nil {
		return nil, fmt.Errorf("the evaluator did not run: %w", err)
	}
	if out.Stopped != "" {
		return nil, fmt.Errorf("the evaluator was stopped: %s", out.Stopped)
	}
	if out.Exit != 0 {
		return nil, fmt.Errorf("the evaluator exited %d: %s", out.Exit,
			clip(strings.TrimSpace(out.Text), 400))
	}
	data, ok := out.Outputs["metrics.json"]
	if !ok {
		return nil, fmt.Errorf("the evaluator wrote no metrics.json")
	}
	return ParseMetrics(data)
}

// write appends one entry, stamped, and tells Progress.
func (s *Search) write(e Entry) error {
	e.At = s.Now().UTC()
	if e.Phase == "" {
		e.Phase = "search"
	}
	if err := s.Journal.Append(e); err != nil {
		return err
	}
	if s.Progress != nil {
		s.Progress(e)
	}
	return nil
}

// save keeps a program by digest, when the caller asked for that.
func (s *Search) save(ind Individual) error {
	if s.Save == nil {
		return nil
	}
	return s.Save(ind.Code, ind.Digest)
}

// pick chooses a parent: the best most of the time, and otherwise a random
// member of the population. The prompt shows the parent first, as the
// program to change, so the model's diffs are written against the program
// they are applied to.
func (s *Search) pick() Individual {
	if len(s.pop) == 1 || s.rng.intn(10) < 7 {
		return s.pop[0]
	}
	return s.pop[s.rng.intn(len(s.pop))]
}

// insert keeps the population sorted and bounded.
func (s *Search) insert(ind Individual) {
	s.pop = append(s.pop, ind)
	sort.SliceStable(s.pop, func(i, j int) bool { return better(s.pop[i], s.pop[j]) })
	if len(s.pop) > s.PopSize {
		s.pop = s.pop[:s.PopSize]
	}
}

// better is the standing order: score first, digest second, so two programs
// that score identically do not trade places by map order or clock.
func better(a, b Individual) bool {
	if a.Combined != b.Combined {
		return a.Combined > b.Combined
	}
	return a.Digest < b.Digest
}

// clip cuts text to at most n bytes at a character boundary, saying so.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// runNote says why a run did not finish, briefly.
func runNote(out RunOutcome, err error) string {
	if err != nil {
		return err.Error()
	}
	if out.Stopped != "" {
		return out.Stopped
	}
	txt := clip(strings.TrimSpace(out.Text), 400)
	if txt == "" {
		return fmt.Sprintf("it exited %d and said nothing", out.Exit)
	}
	return fmt.Sprintf("it exited %d: %s", out.Exit, txt)
}

// randSource is deterministic randomness seeded from the run, so the same
// seed makes the same parent choices. math/rand's seeded source is exactly
// this, and nothing here needs unpredictability: the adversary, if any, is
// the candidate being scored, and it never sees the choice.
type randSource struct{ r *rand.Rand }

func newRNG(seed int64) *randSource {
	return &randSource{r: rand.New(rand.NewSource(seed))}
}

func (r *randSource) intn(n int) int {
	if n <= 1 {
		return 0
	}
	return r.r.Intn(n)
}

// NewID mints a run's identifier.
func NewID() (string, error) {
	b := make([]byte, 6)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return "ev_" + hex.EncodeToString(b), nil
}
