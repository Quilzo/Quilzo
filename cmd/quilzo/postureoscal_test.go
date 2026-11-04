// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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

// A finding an administrator accepted as a risk was dropped from the
// assessment results: the scan was handed the suppressions and only the
// unsuppressed findings reached the document, so the control read as
// reviewed and clean. The system security plan and the KSI report scan with
// no suppressions and show it failing, so the three exports disagreed about
// the same deployment. It is carried as not satisfied, and as accepted.
func TestAnAcceptedRiskStaysInTheAssessmentResults(t *testing.T) {
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	tpl := t.TempDir()
	scan := posture.Scan(Observe(root, tpl, posture.ServerFacts{}), nil)
	if len(scan.Findings) == 0 {
		t.Fatal("a new store has no finding to accept; the test needs one")
	}
	f := scan.Findings[0]
	if err := postureSuppress(root, []string{f.ID(), "--reason", "a migration is planned",
		"--by", "dana", "--days", "30"}); err != nil {
		t.Fatal(err)
	}

	r, pw, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = pw
	_ = postureScan(root, []string{"--oscal", "--templates", tpl})
	pw.Close()
	os.Stdout = stdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	var doc oscal.Results
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not OSCAL JSON: %v\n%s", err, buf.String())
	}
	found := false
	for _, got := range doc.AssessmentResults.Results[0].Findings {
		if got.Title != f.Title || got.Description != f.Detail {
			continue
		}
		found = true
		if got.Target.Status.State != "not-satisfied" {
			t.Errorf("an accepted risk reads as %q", got.Target.Status.State)
		}
		if !strings.Contains(strings.ToLower(got.Remarks), "accepted as a risk") ||
			!strings.Contains(got.Remarks, "a migration is planned") {
			t.Errorf("the finding does not say it was accepted, or why: %q", got.Remarks)
		}
	}
	if !found {
		t.Fatalf("%s was accepted as a risk and is missing from the assessment results, "+
			"so its controls read as reviewed and clean", f.ID())
	}
}

// quilzo posture says whose token a finding is about, from the token's id,
// since the finding no longer names the holder.
//
// token.admin-role said "deploy-bot belongs to lee", which went into the
// JSON and OSCAL output and the audit stream with it; the finding now
// names the token alone, and somebody acting on it at the command line
// still has to know whom to ask.
func TestPostureSaysWhoseTokenAFindingIsAbout(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.Issue("deploy-bot", "lee", "admin", "/", 30*24*time.Hour, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	text, _ := humanOutput(t, func() error { return postureScan(root, []string{"--templates", t.TempDir()}) })
	at := strings.Index(text, "the token deploy-bot can change the access policy itself")
	if at < 0 {
		t.Fatalf("no token.admin-role finding about deploy-bot:\n%s", text)
	}
	if finding := text[at:]; !strings.Contains(finding[:min(len(finding), 300)], "held by lee") {
		t.Errorf("the finding does not say whose token it is:\n%s", finding)
	}
}

// quilzo posture frameworks says whose token a finding is about too, as
// quilzo posture scan and the framework's page on the Security screen do.
//
// It lists each failing requirement with the detail of what fails it, and
// that detail said "deploy-bot belongs to lee" until the finding stopped
// naming the holder; from then on the command said which token and not
// whom to ask about it.
func TestPostureFrameworksSaysWhoseTokenAFindingIsAbout(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.Issue("deploy-bot", "lee", "admin", "/", 30*24*time.Hour, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	var text string
	if _, err := humanOutput(t, func() error {
		_, read := captureStdout(t)
		err := postureFrameworks(root, []string{"nist-800-53", "--templates", t.TempDir()})
		text = read()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	at := strings.Index(text, "the token deploy-bot can change the access policy itself")
	if at < 0 {
		t.Fatalf("control: no token.admin-role finding about deploy-bot:\n%s", text)
	}
	if finding := text[at:]; !strings.Contains(finding[:min(len(finding), 200)], "held by lee") {
		t.Errorf("the finding does not say whose token it is:\n%s", finding)
	}
}
