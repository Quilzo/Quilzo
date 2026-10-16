// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The metrics contract: numbers, finite, bounded, and nothing else.
func TestMetricsParseStrictly(t *testing.T) {
	m, err := ParseMetrics([]byte(`{"accuracy": 0.9, "speed": 12}`))
	if err != nil {
		t.Fatalf("good metrics refused: %v", err)
	}
	if m["accuracy"] != 0.9 || m["speed"] != 12 {
		t.Errorf("parsed %#v", m)
	}
	for _, bad := range []string{
		`{}`,
		`{"a": "high"}`,
		`{"a": null}`,
		`{"a": [1]}`,
		`{"a": {"b": 1}}`,
		`not json`,
		`{"a": 1e999}`,
	} {
		if _, err := ParseMetrics([]byte(bad)); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

// The combined score: the plain mean by default, weights when named, and a
// weight for a metric nobody returned is an error, not a zero.
func TestCombineIsDeterministicAndStrict(t *testing.T) {
	mean, err := Combine(map[string]float64{"a": 1, "b": 3}, nil)
	if err != nil || mean != 2 {
		t.Fatalf("mean: %v %v", mean, err)
	}
	w, err := Combine(map[string]float64{"a": 1, "b": 3, "ignored": 100},
		Weights{"a": 1, "b": 1})
	if err != nil || w != 2 {
		t.Fatalf("weighted: %v %v", w, err)
	}
	if _, err := Combine(map[string]float64{"a": 1}, Weights{"missing": 1}); err == nil {
		t.Error("a weight naming nothing was accepted")
	}
	if _, err := Combine(map[string]float64{"a": 1}, Weights{"a": 0}); err == nil {
		t.Error("weights summing to nothing were accepted")
	}
	if _, err := Combine(nil, nil); err == nil {
		t.Error("no metrics was accepted")
	}
}

// The journal round-trips, and appends survive each other.
func TestTheJournalRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j := Journal{Path: path}
	score := 1.5
	if err := j.Append(Entry{Generation: 0, ID: "c_seed", Model: "the seed program",
		Kept: true, Metrics: map[string]float64{"a": 1}, Combined: &score}); err != nil {
		t.Fatal(err)
	}
	if err := j.Append(Entry{Generation: 1, ID: "c_000001", Parent: "c_seed",
		Model: "the answer had no usable diff: nothing"}); err != nil {
		t.Fatal(err)
	}
	entries, err := j.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].ID != "c_seed" || entries[1].Parent != "c_seed" {
		t.Fatalf("read back %#v", entries)
	}
	if !entries[0].Kept || entries[1].Kept {
		t.Error("kept flags did not survive")
	}
}

// The block markers bound the region that evolves, and a program that
// misuses them is refused before anything runs it.
func TestProgramValidation(t *testing.T) {
	if err := ValidateProgram([]byte("print(1)")); err != nil {
		t.Fatalf("an unmarked program is the whole region: %v", err)
	}
	if err := ValidateProgram([]byte("# EVOLVE-BLOCK-START\nx\n# EVOLVE-BLOCK-END")); err != nil {
		t.Fatalf("one marked block refused: %v", err)
	}
	for _, bad := range []string{
		"",
		"# EVOLVE-BLOCK-START\nx",
		"# EVOLVE-BLOCK-START\n# EVOLVE-BLOCK-END\n# EVOLVE-BLOCK-START\n# EVOLVE-BLOCK-END",
		"# EVOLVE-BLOCK-END\n# EVOLVE-BLOCK-START",
	} {
		if err := ValidateProgram([]byte(bad)); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if err := ValidateProgram([]byte(strings.Repeat("x", MaxProgram+1))); err == nil {
		t.Error("an oversized program was accepted")
	}
}

// A diff parses with prose around it, and refuses anything it cannot read
// exactly.
func TestDiffParsing(t *testing.T) {
	answer := "Here is my change:\n" +
		"<<<<<<< SEARCH\n" +
		"return 1\n" +
		"=======\n" +
		"return 2\n" +
		">>>>>>> REPLACE\n" +
		"This should be better.\n"
	diffs, err := ParseDiff(answer)
	if err != nil {
		t.Fatalf("a good answer with prose refused: %v", err)
	}
	if len(diffs) != 1 || diffs[0].Search != "return 1" || diffs[0].Replace != "return 2" {
		t.Fatalf("parsed %#v", diffs)
	}
	for _, bad := range []string{
		"no diff here",
		"<<<<<<< SEARCH\nreturn 1\n",
		"<<<<<<< SEARCH\nreturn 1\n=======\nreturn 2\n",
		"<<<<<<< SEARCH\n=======\n>>>>>>> REPLACE\n",
	} {
		if _, err := ParseDiff(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// A diff applies once and exactly once, inside the region, and the markers
// themselves stay put.
func TestDiffApplication(t *testing.T) {
	code := []byte("before\n# EVOLVE-BLOCK-START\nreturn 1\n# EVOLVE-BLOCK-END\nafter\n")
	diffs := []Diff{{Search: "return 1", Replace: "return 2"}}
	out, err := Apply(regionOf(code), diffs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "return 2") || !strings.Contains(out, BlockStart) ||
		!strings.Contains(out, "before") {
		t.Fatalf("applied wrongly: %q", out)
	}
	// Outside the region: refused, because that part is not the search's.
	if _, err := Apply(regionOf(code), []Diff{{Search: "before", Replace: "x"}}); err == nil {
		t.Error("a diff outside the block was applied")
	}
	// Not present.
	if _, err := Apply(regionOf(code), []Diff{{Search: "absent", Replace: "x"}}); err == nil ||
		!strings.Contains(err.Error(), "absent") {
		t.Fatalf("an unmatched search was applied or said nothing useful: %v", err)
	}
	// Present twice.
	twice := []byte("# EVOLVE-BLOCK-START\nx\nx\n# EVOLVE-BLOCK-END")
	if _, err := Apply(regionOf(twice), []Diff{{Search: "x", Replace: "y"}}); err == nil {
		t.Error("an ambiguous search was applied")
	}
	// Two diffs, the second seeing the first's result.
	seq := []Diff{{Search: "a", Replace: "ab"}, {Search: "ab", Replace: "abc"}}
	out, err = Apply(regionOf([]byte("a")), seq)
	if err != nil || out != "abc" {
		t.Fatalf("sequential diffs: %q %v", out, err)
	}
}

// ParseWeights reads what it is given and refuses the rest.
func TestWeights(t *testing.T) {
	w, err := ParseWeights([]string{"accuracy=2", "speed=0.5"})
	if err != nil || w["accuracy"] != 2 || w["speed"] != 0.5 {
		t.Fatalf("parsed %#v %v", w, err)
	}
	for _, bad := range []string{"accuracy", "accuracy=", "accuracy=high", "a=NaN"} {
		if _, err := ParseWeights([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// The seed's own run directory is where the journal says it is.
func TestRunDir(t *testing.T) {
	if RunDir("/r", "ev_1") != filepath.Join("/r", "evolve", "ev_1") {
		t.Error("the run directory moved")
	}
	if _, err := os.Stat(RunDir(t.TempDir(), "ev_none")); err == nil {
		t.Error("a run that never was, was")
	}
}
