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
// algorithms nobody had written: a 48-multiplication product of 4×4 complex
// matrices, the first improvement on Strassen's setting in 56 years.
// OpenEvolve, the open reimplementation, runs the same loop with islands and
// a MAP-Elites database. What none of them isolates is the evaluator: the
// candidate runs inside the evaluator's process, so a candidate that reads
// files, imports the evaluator or patches its functions sees the test cases
// and can forge its own scores. The papers do not treat that as a threat
// because their candidates are not adversaries. Quilzo's doctrine says a
// program that was written by a model, steered by other programs' output, is
// exactly the thing not to extend trust to.
//
// # The seal
//
// So the two halves never meet. A candidate runs in one box — the agent box,
// with its namespaces, Landlock and system-call filter, no network, bounded
// time, memory and files — and the evaluator runs in another, with its own
// workspace and scratch home. The only thing that crosses from the
// candidate's side to the evaluator's is what the candidate wrote under its
// declared output area, copied by this program. The candidate cannot read
// the evaluator's code, cannot see its inputs, cannot patch its functions
// and cannot write its metrics, because there is no path from its
// filesystem to any of it (SP 800-53 SC-3, isolation by structure rather
// than by convention). The evaluator's held-out cases are therefore a real
// hold-out, not a shared directory both sides can read.
//
// The model is inside the same boundary: it is asked to improve programs and
// shown programs, scores and bounded output, never the evaluator. What a
// candidate prints is data — possibly adversarial data, a prompt injection
// aimed at the very model reading it — so it is capped, delimited, and named
// in the system prompt as data from a program being judged, never as
// instructions. The worst a successful injection can do is waste a
// generation: the diff it steers the model to write still has to apply
// cleanly, run in a box with no network, and be scored by an evaluator it
// cannot reach.
//
// # What decides, and what records
//
// Selection is deterministic code: a combined score from weights the
// operator declared, a population of the best kept, ties broken by digest so
// two runs of the same search agree. Every generation is journalled — the
// model's answer parsed or refused, the program's digest, the box's exit,
// the metrics, whether it was kept — because a search whose losers vanish
// teaches nothing about where the winners came from (AI RMF MEASURE: a
// record that lets somebody later ask why the best program is the best
// program). No money, no network and no store reach: a search that goes
// wrong costs its own time.
package evolve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The bounds. A search is a loop a model drives, so every dimension of it
// is capped: how many generations, how big a program, how many metrics, how
// much of anything a candidate may write. A search that could be told to
// run forever, or to evolve a program the size of its own journal, is a
// denial of service with a research budget (SP 800-53 SC-5, SI-10).
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
}

// Entry is one generation in the journal, kept whatever happened.
type Entry struct {
	At         time.Time          `json:"at"`
	Generation int                `json:"generation"`
	ID         string             `json:"id"`
	Parent     string             `json:"parent,omitempty"`
	Model      string             `json:"model"`
	Applied    bool               `json:"applied,omitempty"`
	Digest     string             `json:"digest,omitempty"`
	Exit       int                `json:"exit,omitempty"`
	Stopped    string             `json:"stopped,omitempty"`
	TookMS     int64              `json:"took_ms,omitempty"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
	Combined   *float64           `json:"combined,omitempty"`
	Kept       bool               `json:"kept,omitempty"`
	Note       string             `json:"note,omitempty"`
}

// Weights names the metrics the combined score is built from, and how much
// each counts. A metric the evaluator returns that no weight names is
// recorded and ignored, not silently averaged in.
type Weights map[string]float64

// ParseWeights reads NAME=VALUE pairs.
func ParseWeights(pairs []string) (Weights, error) {
	w := Weights{}
	for _, p := range pairs {
		name, value, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not NAME=NUMBER", p)
		}
		v, err := parseNumber(value)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", p, err)
		}
		if len(w) >= MaxMetrics {
			return nil, fmt.Errorf("more than %d weights", MaxMetrics)
		}
		w[name] = v
	}
	return w, nil
}

func parseNumber(s string) (float64, error) {
	var v float64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%g", &v); err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("%q is not finite", s)
	}
	return v, nil
}

// ParseMetrics reads what an evaluator wrote, strictly.
//
// The file is a flat object of numbers — the whole contract, and anything
// beyond it is refused rather than interpreted: a string metric, a nested
// one, a NaN smuggled in as a word, are all refused, because a score this
// program cannot parse is a score a candidate may as well have written
// itself. NaN and infinities are refused after decoding too, since JSON
// spells them as null or as very large numbers this side of the parse.
func ParseMetrics(data []byte) (map[string]float64, error) {
	if len(data) > MaxOutputBytes {
		return nil, fmt.Errorf("the metrics are larger than a file this accepts")
	}
	var raw map[string]any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("the metrics are not a JSON object: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("the metrics name nothing")
	}
	if len(raw) > MaxMetrics {
		return nil, fmt.Errorf("the metrics name %d things, and %d is the most", len(raw), MaxMetrics)
	}
	out := map[string]float64{}
	for k, v := range raw {
		n, ok := v.(json.Number)
		if !ok {
			return nil, fmt.Errorf("the metric %q is not a number", k)
		}
		f, err := n.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("the metric %q is not finite", k)
		}
		if len(k) > 64 {
			return nil, fmt.Errorf("the metric %q has too long a name", k)
		}
		out[k] = f
	}
	return out, nil
}

// Combine folds metrics into one score, deterministically.
//
// Named weights are used when the metrics carry them; the default is the
// plain mean of everything the evaluator returned, over the sorted names so
// two evaluators that write the same metrics in a different order score the
// same. A weight naming a metric the evaluator did not return is an error,
// not a zero: a search optimising a metric nobody measured is a search
// optimising a typo.
func Combine(m map[string]float64, w Weights) (float64, error) {
	if len(m) == 0 {
		return 0, fmt.Errorf("no metrics to combine")
	}
	if len(w) == 0 {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		var sum float64
		for _, k := range names {
			sum += m[k]
		}
		return sum / float64(len(names)), nil
	}
	var sum, total float64
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
		total += w[k]
	}
	if total == 0 {
		return 0, fmt.Errorf("the weights add up to nothing")
	}
	return sum / total, nil
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
