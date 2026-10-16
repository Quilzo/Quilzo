// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package evolve searches over programs: a model proposes changes, the
// programs run in a box, and a sealed evaluator decides which is best.
//
// # What this is, and whose idea it is
//
// DeepMind's AlphaEvolve (2025) and its predecessor FunSearch showed that an
// evolutionary loop over code — a database of programs, a prompt sampler, an
// LLM emitting diffs, and an evaluator returning numbers — can find
// algorithms nobody had written. OpenEvolve and Sakana's ShinkaEvolve are
// open versions of the same loop. In their published evaluators the
// candidate runs in the evaluator's own process, or in an unconfined
// subprocess as the same user, and the AlphaEvolve paper puts evaluate() in
// the evolved program's own file and describes no sandbox. A candidate there
// that reads files or patches the evaluator can see the test cases and write
// its own score. Their candidates are not treated as adversaries; a program a
// model wrote, steered by other programs' output, is exactly what this
// program does not extend trust to.
//
// # The seal
//
// So the two halves never meet. A candidate runs in one box — the agent box,
// with its namespaces, Landlock and system-call filter, no network, bounded
// time, memory, files and disk — and the evaluator runs in another, with its
// own workspace and scratch home. The only thing that crosses from the
// candidate's side to the evaluator's is what the candidate wrote in its
// output area, copied by this program. The candidate cannot read the
// evaluator's code or inputs, patch its functions or write its metrics,
// because no path leads from its filesystem to any of them (SP 800-53 SC-39,
// process isolation, with that copy as the one information flow, AC-4).
//
// What the seal does not do is keep the search from adapting to the
// evaluator's cases. Their scores choose which programs survive, for
// hundreds of generations, so the winner is fitted to them and its score is
// a selection score, not a measure of how it does on cases it has not seen.
// That is what the test set is for: cases scored once, on the final
// population, never used to choose and never shown to the model.
//
// The model is inside the same boundary: it is shown programs, scores and
// bounded output, never the evaluator. What a candidate prints, and the
// programs themselves, are data — possibly adversarial, aimed at the model
// reading them — so they are cleaned of invisible characters and fenced with
// a mark the content cannot predict. A steered model can still waste
// generations, or write programs that game the evaluator's cases; the diff
// it writes still has to apply, run in a box, and be scored by an evaluator
// it cannot reach, and the test set is where gaming the cases shows.
//
// # What decides, and what records
//
// Selection is deterministic code: a combined score from weights the
// operator declared, a population of the best kept, ties broken by digest.
// Every generation is journalled before the population changes — the
// diff, the program's digest, the box's exit, the metrics, whether it was
// kept — because a search whose losers vanish teaches nothing about where
// the winners came from (AI RMF MEASURE). The random seed is the journal's
// first entry: the same seed makes the same parent choices, and with the
// same answers from the model, the same search.
package evolve

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The bounds. A search is a loop a model drives, so every dimension of it
// is capped: how many generations, how big a program, how many metrics, how
// much of anything a candidate may write. A search that could be told to
// run forever, or to evolve a program the size of its own journal, is a
// denial of service with a research budget (SP 800-53 SC-5, SI-10).
// MaxOutputs counts files in a run's output area, which is flat: a file
// in a subdirectory is not collected.
const (
	MaxGenerations = 500
	MaxPopulation  = 32
	MaxProgram     = 64 << 10 // bytes
	MaxMetrics     = 32
	MaxOutputs     = 16      // files collected from a candidate
	MaxOutputBytes = 1 << 20 // per file
	MaxTask        = 4000    // the task description, in characters
)

// Input is one file handed to a run, by safe name.
type Input struct {
	Name  string `json:"name"`
	Bytes []byte `json:"-"`
}

// RunOutcome is how one boxed run went, and what it wrote.
type RunOutcome struct {
	Exit    int
	Stopped string
	Took    time.Duration
	// Text is the combined output, bounded, for the model to read.
	Text string
	// Outputs is what the run wrote under its output area, by relative
	// name — for a candidate, its deliverable; for an evaluator, metrics.
	Outputs map[string][]byte
}

// Individual is one program and its standing.
type Individual struct {
	ID       string             `json:"id"`
	Code     []byte             `json:"-"`
	Digest   string             `json:"digest"`
	Metrics  map[string]float64 `json:"metrics,omitempty"`
	Combined float64            `json:"combined"`
	Gen      int                `json:"gen"`
	Parent   string             `json:"parent,omitempty"`
	// Test is the program's score on the test set, when there is one: a
	// figure reported beside the selection score, never used to choose.
	Test *float64 `json:"test,omitempty"`
}

// Entry is one generation in the journal, kept whatever happened.
type Entry struct {
	At         time.Time `json:"at"`
	Generation int       `json:"generation"`
	// Phase is "search" for a generation and "test" for the final scoring
	// of the population on the test set.
	Phase  string `json:"phase,omitempty"`
	ID     string `json:"id,omitempty"`
	Parent string `json:"parent,omitempty"`
	// Outcome says what happened, in words.
	Outcome string `json:"outcome"`
	// Seed and Model are on the first entry: what would have to be the same
	// for the search to walk the same way.
	Seed  int64  `json:"seed,omitempty"`
	Model string `json:"model,omitempty"`
	// Diff is what the model proposed, bounded, so a program in the journal
	// can be traced to the change that made it.
	Diff     string             `json:"diff,omitempty"`
	Applied  bool               `json:"applied,omitempty"`
	Digest   string             `json:"digest,omitempty"`
	Exit     int                `json:"exit,omitempty"`
	Stopped  string             `json:"stopped,omitempty"`
	TookMS   int64              `json:"took_ms,omitempty"`
	Metrics  map[string]float64 `json:"metrics,omitempty"`
	Combined *float64           `json:"combined,omitempty"`
	Kept     bool               `json:"kept,omitempty"`
	Note     string             `json:"note,omitempty"`
}

// MaxDiffKept bounds the diff a journal line carries.
const MaxDiffKept = 8 << 10

// Weights names the metrics the combined score is built from, and how much
// each counts. A negative weight counts a metric against a program, which
// is how a search minimises something, such as time. A metric the evaluator
// returns that no weight names is recorded and ignored, not silently
// averaged in.
type Weights map[string]float64

// ParseWeights reads NAME=VALUE pairs.
func ParseWeights(pairs []string) (Weights, error) {
	w := Weights{}
	for _, p := range pairs {
		name, value, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not NAME=NUMBER", p)
		}
		if !metricName(name) {
			return nil, fmt.Errorf("%q is not a metric's name: letters, digits, dot, dash and underscore, at most 64", name)
		}
		v, err := parseNumber(value)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", p, err)
		}
		if v == 0 {
			return nil, fmt.Errorf("%q counts for nothing; leave it out instead", p)
		}
		if _, twice := w[name]; twice {
			return nil, fmt.Errorf("%s is weighted twice", name)
		}
		if len(w) >= MaxMetrics {
			return nil, fmt.Errorf("more than %d weights", MaxMetrics)
		}
		w[name] = v
	}
	return w, nil
}

func parseNumber(s string) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("%q is not finite", s)
	}
	return v, nil
}

// metricName is the shape a metric's name has: what fits in a prompt, a
// journal line and a terminal without being able to look like anything else.
func metricName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

// ParseMetrics reads what an evaluator wrote, strictly.
//
// The file is one flat object of numbers — the whole contract, and anything
// beyond it is refused rather than interpreted: a string metric, a nested
// one, a name given twice, a second value after the object, or a name that
// is not a plain identifier, because a score this program cannot read
// exactly is a score a candidate may as well have written itself. NaN and
// infinities are refused after decoding too.
func ParseMetrics(data []byte) (map[string]float64, error) {
	if len(data) > MaxOutputBytes {
		return nil, fmt.Errorf("the metrics are larger than a file this accepts")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("the metrics are not a JSON object")
	}
	out := map[string]float64{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("the metrics are not a JSON object: %w", err)
		}
		k := t.(string)
		if !metricName(k) {
			return nil, fmt.Errorf("%q is not a metric's name: letters, digits, dot, dash and underscore, at most 64", k)
		}
		if _, twice := out[k]; twice {
			return nil, fmt.Errorf("the metric %s is given twice", k)
		}
		v, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("the metric %s could not be read: %w", k, err)
		}
		n, ok := v.(json.Number)
		if !ok {
			return nil, fmt.Errorf("the metric %s is not a number", k)
		}
		f, err := n.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("the metric %s is not finite", k)
		}
		if len(out) == MaxMetrics {
			return nil, fmt.Errorf("the metrics name more than %d things", MaxMetrics)
		}
		out[k] = f
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("the metrics object does not close")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("the metrics file holds more than one JSON object")
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the metrics name nothing")
	}
	return out, nil
}

// Combine folds metrics into one score, deterministically.
//
// With weights, the weighted sum over the sum of the weights' sizes, so a
// negative weight counts against a program rather than turning the whole
// score around. Without, the plain mean of everything the evaluator
// returned, over the sorted names so the order an evaluator writes them in
// changes nothing. A weight naming a metric the evaluator did not return is
// an error, not a zero: a search optimising a metric nobody measured is a
// search optimising a typo. A result that is not finite is refused, because
// it would sort above or below everything and stop meaning anything.
func Combine(m map[string]float64, w Weights) (float64, error) {
	if len(m) == 0 {
		return 0, fmt.Errorf("no metrics to combine")
	}
	var sum, total float64
	if len(w) == 0 {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			sum += m[k] / float64(len(names))
		}
		total = 1
	} else {
		names := make([]string, 0, len(w))
		for k := range w {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			v, ok := m[k]
			if !ok {
				return 0, fmt.Errorf("the weight %s names a metric the evaluator did not return", k)
			}
			sum += w[k] * v
			total += math.Abs(w[k])
		}
	}
	if total == 0 {
		return 0, fmt.Errorf("the weights add up to nothing")
	}
	score := sum / total
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 0, fmt.Errorf("the combined score is not a finite number")
	}
	return score, nil
}

// DigestOf names a program by the SHA-256 of its bytes.
func DigestOf(code []byte) string {
	sum := sha256.Sum256(code)
	return hex.EncodeToString(sum[:])
}

// Journal appends one line per generation, and reads back what it wrote.
type Journal struct {
	Path string
}

// Append writes one entry, flushing before the search continues: a crash
// between generations loses at most the generation it was in, never the
// record of the ones before it (SP 800-53 AU-3's point, applied to a
// research log).
func (j Journal) Append(e Entry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(j.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// Read loads the whole journal, oldest first.
func (j Journal) Read() ([]Entry, error) {
	data, err := os.ReadFile(j.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("%s has a line that is not an entry: %w", j.Path, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// RunDir is where one search's journal and candidates live.
func RunDir(root, id string) string { return filepath.Join(root, "evolve", id) }
