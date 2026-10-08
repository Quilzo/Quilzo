// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/oscal"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
)

// The assessment results name controls as the catalogue does, and list as
// reviewed only what a rule that ran bears on.
func TestTheAssessmentResultsClaimOnlyWhatRan(t *testing.T) {
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	r, pw, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = pw
	_ = postureScan(root, []string{"--oscal", "--templates", t.TempDir()})
	pw.Close()
	os.Stdout = stdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	var doc oscal.Results
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not OSCAL JSON: %v\n%s", err, buf.String())
	}
	listed := map[string]bool{}
	for _, c := range doc.AssessmentResults.Results[0].ReviewedControls.ControlSelections[0].IncludeControls {
		if strings.ContainsAny(c.ControlID, "()") || c.ControlID != strings.ToLower(c.ControlID) {
			t.Errorf("%s is not an OSCAL control id", c.ControlID)
		}
		listed[c.ControlID] = true
	}

	// A rule that did not run reviewed nothing: skip one whose controls no
	// other rule shares, and its controls leave the document.
	idx := posture.RuleIndex()
	share := map[string]int{}
	for _, rule := range idx {
		for _, c := range rule.Controls {
			share[oscal.ControlID(c)]++
		}
	}
	lone, alone := "", ""
	for id, rule := range idx {
		for _, c := range rule.Controls {
			if share[oscal.ControlID(c)] == 1 {
				lone, alone = id, oscal.ControlID(c)
			}
		}
	}
	if lone == "" {
		t.Fatal("no control is checked by one rule only; the test needs one")
	}
	if !listed[alone] {
		t.Fatalf("%s should be listed while %s runs", alone, lone)
	}
	doc2, err := assessmentResults(root, posture.Report{Skipped: []string{lone}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range doc2.AssessmentResults.Results[0].ReviewedControls.ControlSelections[0].IncludeControls {
		if c.ControlID == alone {
			t.Fatalf("%s is listed as reviewed although %s, its only rule, did not run", alone, lone)
		}
	}
}
