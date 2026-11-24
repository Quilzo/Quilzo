// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
)

// scoreShaped is a figure out of a hundred, written any way a person reads
// one: "87/100", "87 / 100", "87 out of 100".
var scoreShaped = regexp.MustCompile(`(?i)\b\d{1,3}\s*(/|out of)\s*100\b|\bscore`)

// quilzo posture scan says what it found as counts by severity and what it
// covered as rules checked of rules, and prints no score.
//
// It opened on "posture 87/100": a number that put a misconfigured audit
// key and a missing input on one scale, so two different installations
// could read the same, and one figure somebody reads from across a room
// becomes the figure that is argued about instead of the findings.
func TestPostureScanPrintsNoScore(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	tpl := t.TempDir()
	text, _ := humanOutput(t, func() error { return postureScan(root, []string{"--templates", tpl}) })
	rep := posture.Scan(Observe(root, tpl, posture.ServerFacts{}), nil)
	tl := rep.Tally()

	if m := scoreShaped.FindString(text); m != "" {
		t.Errorf("posture scan printed %q, a score, to a person:\n%s", m, text)
	}
	for _, c := range tl.Severities {
		if want := fmt.Sprintf("%d %s", c.Count, c.Severity); !strings.Contains(text, want) {
			t.Errorf("posture scan does not say %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, tl.Coverage()) {
		t.Errorf("posture scan does not say %q:\n%s", tl.Coverage(), text)
	}
	if tl.NotChecked > 0 && !strings.Contains(text, fmt.Sprintf("%d not checked", tl.NotChecked)) {
		t.Errorf("posture scan does not say how many rules were not checked (%d):\n%s", tl.NotChecked, text)
	}

	// Nor does the reading by framework, the other report a person reads.
	var frameworks string
	if _, err := humanOutput(t, func() error {
		_, read := captureStdout(t)
		err := postureFrameworks(root, []string{"--templates", tpl})
		frameworks = read()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if m := scoreShaped.FindString(frameworks); m != "" {
		t.Errorf("posture frameworks printed %q:\n%s", m, frameworks)
	}
}

// --json still carries the score, for the scripts and dashboards that read
// it, beside the tally a person reads.
func TestPostureJSONKeepsScore(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	tpl := t.TempDir()
	old := w
	t.Cleanup(func() { w = old })
	var b strings.Builder
	w = &out.Writer{Mode: out.JSON, Out: &b, Err: io.Discard}
	_ = postureScan(root, []string{"--templates", tpl})

	var doc struct {
		Score *int `json:"score"`
		Tally *struct {
			Rules   int `json:"rules"`
			Checked int `json:"checked"`
		} `json:"tally"`
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatalf("posture scan --json is not JSON: %v\n%s", err, b.String())
	}
	rep := posture.Scan(Observe(root, tpl, posture.ServerFacts{}), nil)
	if doc.Score == nil || *doc.Score != rep.Score {
		t.Errorf("--json carries score %v; the scan's is %d", doc.Score, rep.Score)
	}
	if doc.Tally == nil || doc.Tally.Rules != len(posture.Rules()) || doc.Tally.Checked != rep.Tally().Checked {
		t.Errorf("--json does not carry the tally a person reads: %+v", doc.Tally)
	}
	if doc.Counts == nil {
		t.Error("--json dropped the counts it carried")
	}
}
