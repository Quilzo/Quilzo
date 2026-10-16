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
)

// The loop: mutate, run, judge, keep, record.
//
// One generation is one turn of AlphaEvolve's cycle, made synchronous and
// small enough to audit: pick a parent from the population, ask the model
// for diffs, apply them to the parent's evolvable region, run the new
// program in a box, and — only if it ran — hand what it wrote to the
// evaluator in its own box, parse the metrics, and keep the program if it
// beats the population's floor. Every turn writes a journal line first and
// changes the population after, so a crash cannot leave a kept program with
// no record or a record with no program.

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
	// wrote under its output area.
	RunCandidate(ctx context.Context, code []byte, inputs []Input) (RunOutcome, error)
	// RunEvaluator runs the evaluator over what a candidate wrote.
	RunEvaluator(ctx context.Context, outputs map[string][]byte) (RunOutcome, error)
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
	Runner      Runner
	Journal     Journal
	Seed        int64
	// Now is the clock; the journal stamps with it.
	Now func() time.Time

	pop     []Individual
	failTXT string
	rng     *randSource
}

// Best returns the standing best program.
func (s *Search) Best() Individual { return s.pop[0] }

// Population returns the standing population, best first. Called after Run
// to write the kept programs out; the slice is a copy, so the search's own
// order cannot be shuffled through it.
func (s *Search) Population() []Individual {
	out := make([]Individual, len(s.pop))
	copy(out, s.pop)
	return out
}

// Run performs the search.
//
// The seed program is evaluated first — generation 0 — so the population
// starts from a measurement rather than an assumption, and every later
// generation is compared against something real. A seed that does not run
// is an error: evolving from a program that never worked optimises the
// wrong baseline.
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
	outcome, err := s.Runner.RunCandidate(ctx, seed.Code, s.Inputs)
	if err != nil || outcome.Exit != 0 {
		return Individual{}, fmt.Errorf(
			"the seed program did not run, and a search starts from one that does: %s",
			runNote(outcome, err))
	}
	seed.Metrics, err = s.judge(ctx, outcome)
	if err != nil {
		return Individual{}, fmt.Errorf("the seed program could not be judged: %w", err)
	}
	seed.Combined, err = Combine(seed.Metrics, s.Weights)
	if err != nil {
		return Individual{}, err
	}
	s.pop = []Individual{seed}
	if err := s.Journal.Append(s.entry(0, seed, seed.ID, "the seed program",
		true, outcome, "", true)); err != nil {
		return Individual{}, err
	}

	for gen := 1; gen <= s.Generations; gen++ {
		if ctx.Err() != nil {
			return s.pop[0], ctx.Err()
		}
		parent := s.pick()
		answer, err := s.Model.Complete(ctx, SystemPrompt(),
			UserPrompt(s.Task, s.pop, parent, s.failTXT))
		if err != nil {
			return s.pop[0], fmt.Errorf("the model did not answer in generation %d: %w", gen, err)
		}
		diffs, derr := ParseDiff(answer)
		id := fmt.Sprintf("c_%06d", gen)
		if derr != nil {
			if aerr := s.Journal.Append(s.entry(gen, Individual{ID: id}, parent.ID,
				"the answer had no usable diff: "+derr.Error(), false, RunOutcome{}, "", false)); aerr != nil {
				return s.pop[0], aerr
			}
			s.failTXT = "the proposed change did not parse as diff blocks"
			continue
		}
		code, aerr := Apply(regionOf(parent.Code), diffs)
		if aerr != nil {
			if jerr := s.Journal.Append(s.entry(gen, Individual{ID: id}, parent.ID,
				"the diff did not apply: "+aerr.Error(), false, RunOutcome{}, "", false)); jerr != nil {
				return s.pop[0], jerr
			}
			s.failTXT = "the proposed change did not apply to the program"
			continue
		}
		codeBytes := []byte(code)
		if verr := ValidateProgram(codeBytes); verr != nil {
			if jerr := s.Journal.Append(s.entry(gen, Individual{ID: id}, parent.ID,
				"the changed program is not usable: "+verr.Error(), false, RunOutcome{}, "", false)); jerr != nil {
				return s.pop[0], jerr
			}
			s.failTXT = "the changed program was too large or lost its block markers"
			continue
		}

		ind := Individual{ID: id, Code: codeBytes, Digest: DigestOf(codeBytes),
			Gen: gen, Parent: parent.ID}
		outcome, rerr := s.Runner.RunCandidate(ctx, ind.Code, s.Inputs)
		if rerr != nil || outcome.Exit != 0 {
			note := runNote(outcome, rerr)
			if jerr := s.Journal.Append(s.entry(gen, ind, parent.ID, "the program ran and failed",
				true, outcome, note, false)); jerr != nil {
				return s.pop[0], jerr
			}
			s.failTXT = outcome.Text
			continue
		}
		metrics, merr := s.judge(ctx, outcome)
		if merr != nil {
			if jerr := s.Journal.Append(s.entry(gen, ind, parent.ID,
				"the evaluator refused: "+merr.Error(), true, outcome, "", false)); jerr != nil {
				return s.pop[0], jerr
			}
			s.failTXT = outcome.Text
			continue
		}
		ind.Metrics = metrics
		combined, cerr := Combine(metrics, s.Weights)
		if cerr != nil {
			return s.pop[0], cerr
		}
		ind.Combined = combined

		kept := len(s.pop) < s.PopSize || better(ind, s.pop[len(s.pop)-1])
		if kept {
			s.insert(ind)
			s.failTXT = ""
		} else {
			s.failTXT = outcome.Text
		}
		if jerr := s.Journal.Append(s.entry(gen, ind, parent.ID, "judged", true,
			outcome, "", kept)); jerr != nil {
			return s.pop[0], jerr
		}
	}
	return s.pop[0], nil
}

// judge hands a candidate's outputs to the sealed evaluator and reads the
// metrics back. This is the only line between the two sides, and it carries
// the candidate's files and nothing else.
func (s *Search) judge(ctx context.Context, candidate RunOutcome) (map[string]float64, error) {
	out, err := s.Runner.RunEvaluator(ctx, candidate.Outputs)
	if err != nil {
		return nil, fmt.Errorf("the evaluator did not run: %w", err)
	}
	if out.Exit != 0 {
		return nil, fmt.Errorf("the evaluator exited %d: %s", out.Exit,
			strings.TrimSpace(out.Text))
	}
	data, ok := out.Outputs["metrics.json"]
	if !ok {
		return nil, fmt.Errorf("the evaluator wrote no metrics.json")
	}
	return ParseMetrics(data)
}

// pick chooses a parent: the best most of the time, and otherwise a random
// member of the population, which is the whole of this version's diversity
// mechanism and is recorded here rather than implied — islands and niches
// are a refinement on a loop that already works.
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

// entry is one journal line assembled.
func (s *Search) entry(gen int, ind Individual, parent, model string, applied bool,
	out RunOutcome, note string, kept bool) Entry {

	combined := ind.Combined
	e := Entry{
		At: s.Now().UTC(), Generation: gen, ID: ind.ID, Parent: parent,
		Model: model, Applied: applied, Digest: ind.Digest,
		Exit: out.Exit, Stopped: out.Stopped, TookMS: out.Took.Milliseconds(),
		Metrics: ind.Metrics, Kept: kept, Note: note,
	}
	if ind.Metrics != nil {
		e.Combined = &combined
	}
	return e
}

// runNote says why a run did not finish, briefly.
func runNote(out RunOutcome, err error) string {
	if err != nil {
		return err.Error()
	}
	if out.Stopped != "" {
		return out.Stopped
	}
	txt := strings.TrimSpace(out.Text)
	if len(txt) > 400 {
		txt = txt[:400] + "…"
	}
	if txt == "" {
		return fmt.Sprintf("it exited %d and said nothing", out.Exit)
	}
	return fmt.Sprintf("it exited %d: %s", out.Exit, txt)
}

// randSource is deterministic randomness seeded from the run, so the same
// seed walks the same search and the journal can be replayed against that
// claim. math/rand's seeded source is exactly this, and nothing here needs
// unpredictability: the adversary, if any, is the candidate being scored.
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
