// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

const sprayCorrelation = `
title: Many failed privileged sign-ins for one account
id: corr.privileged-spray
correlation:
    type: event_count
    rules:
        - auth.privileged-failed
    group-by:
        - actor
    timespan: 15m
    condition:
        gte: 5
level: critical
`

// window is the start of a fifteen-minute window that closed well before
// now, so the watermark has passed it.
func closedWindow() time.Time {
	return time.Now().UTC().Add(-3 * time.Hour).Truncate(15 * time.Minute)
}

// failures is n failed sign-ins by one account, a minute apart from start.
func failures(who string, start time.Time, n int) []labelled {
	var out []labelled
	for i := 0; i < n; i++ {
		at := start.Add(time.Duration(i+1) * time.Minute)
		out = append(out, labelled{fmt.Sprintf("%s-%d", who, i), true,
			signIn("okta/system", who, telemetry.DispositionFailed,
				"sign-in failed", at)})
	}
	return out
}

func corrSite(t *testing.T, corpus []labelled) (root, rules string) {
	t.Helper()
	root, rules = siemSite(t, corpus)
	if err := os.WriteFile(filepath.Join(rules, "spray.yml"),
		[]byte(sprayCorrelation), 0o600); err != nil {
		t.Fatal(err)
	}
	// The single rule is not worth a finding on its own here; the
	// correlation is what this is testing.
	if err := cmdDetect(root, []string{"ring", rule, "trial", "--because",
		"only the correlation is worth waking anybody", "--rules", rules}); err != nil {
		t.Fatal(err)
	}
	return root, rules
}

func correlated(t *testing.T, root string) []finding.Finding {
	t.Helper()
	var out []finding.Finding
	for _, f := range queue(t, root) {
		if f.Source == "corr.privileged-spray" {
			out = append(out, f)
		}
	}
	return out
}

// Five failures for one account inside a window is a finding; four is not,
// and five spread across five accounts is not.
func TestACorrelationFiresOnItsConditionAndNotBelowIt(t *testing.T) {
	w0 := closedWindow()
	var corpus []labelled
	corpus = append(corpus, failures("admin-dana", w0, 5)...)
	corpus = append(corpus, failures("admin-raj", w0, 4)...)
	for i := 0; i < 5; i++ {
		corpus = append(corpus, failures(fmt.Sprintf("admin-x%d", i), w0, 1)...)
	}
	root, rules := corrSite(t, corpus)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := correlated(t, root)
	if len(got) != 1 || got[0].Entity.Value != "admin-dana" {
		t.Fatalf("correlated findings: %+v", got)
	}
	if got[0].Severity != telemetry.SeverityCritical || got[0].Trial {
		t.Errorf("%+v", got[0])
	}
	if !strings.Contains(got[0].Evidence[0].What, "5 within") {
		t.Errorf("the evidence does not say what was counted: %s",
			got[0].Evidence[0].What)
	}

	// A second run over the same events raises nothing again.
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if again := correlated(t, root); len(again) != 1 || again[0].Seen != 1 {
		t.Errorf("the same window was raised twice: %+v", again)
	}
}

// The reason the engine closes on a watermark: a window still inside the
// lateness is not decided yet, and an event that arrives late still counts.
func TestAWindowIsDecidedOnlyOnceItIsCompleteAndLateEventsCount(t *testing.T) {
	// Four on time, and the fifth happened in the window but arrived an
	// hour after it — still before this run.
	w0 := closedWindow()
	corpus := failures("admin-dana", w0, 4)
	late := signIn("okta/system", "admin-dana", telemetry.DispositionFailed,
		"sign-in failed", w0.Add(9*time.Minute))
	late.Received = w0.Add(75 * time.Minute)
	corpus = append(corpus, labelled{"late", true, late})
	root, rules := corrSite(t, corpus)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if n := len(correlated(t, root)); n != 1 {
		t.Errorf("%d findings: the fifth failure arrived late and should "+
			"still have been counted in its window", n)
	}

	// Five in the window that is open right now: not decided yet.
	now := time.Now().UTC()
	open := now.Truncate(15 * time.Minute)
	var fresh []labelled
	for i := 0; i < 5; i++ {
		at := open.Add(time.Duration(i) * time.Second)
		if at.After(now) {
			at = now
		}
		fresh = append(fresh, labelled{fmt.Sprintf("f%d", i), true,
			signIn("okta/system", "admin-eve", telemetry.DispositionFailed,
				"sign-in failed", at)})
	}
	root2, rules2 := corrSite(t, fresh)
	if err := detectRun(root2, []string{"--rules", rules2}); err != nil {
		t.Fatal(err)
	}
	if n := len(correlated(t, root2)); n != 0 {
		t.Errorf("a window still open was decided: %d finding(s)", n)
	}
}

func TestACorrelationRespectsSuppressionsAndItsOwnRing(t *testing.T) {
	w0 := closedWindow()
	root, rules := corrSite(t, failures("admin-backup", w0, 6))
	until := time.Now().AddDate(0, 0, 10).Format("2006-01-02")
	if err := cmdDetect(root, []string{"suppress", rule,
		"actor=okta:admin-backup", "--owner", "dana", "--until", until,
		"--because", "backup retries", "--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if n := len(correlated(t, root)); n != 0 {
		t.Error("a suppressed account's failures were counted into a spray")
	}

	// The correlation has a ring of its own.
	root, rules = corrSite(t, failures("admin-dana", w0, 5))
	if err := cmdDetect(root, []string{"ring", "corr.privileged-spray",
		"off", "--because", "rewriting it", "--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if n := len(correlated(t, root)); n != 0 {
		t.Error("a correlation that is switched off raised a finding")
	}
}

func TestACorrelationOverARuleNobodyHasIsRefused(t *testing.T) {
	root, rules := siemSite(t, nil)
	os.WriteFile(filepath.Join(rules, "bad.yml"), []byte(strings.Replace(
		sprayCorrelation, "auth.privileged-failed", "auth.renamed", 1)), 0o600)
	err := detectRun(root, []string{"--rules", rules})
	if err == nil || !strings.Contains(err.Error(), "no rule called") {
		t.Errorf("a correlation that can never fire: %v", err)
	}
	os.WriteFile(filepath.Join(rules, "bad.yml"), []byte(strings.Replace(
		sprayCorrelation, "id: corr.privileged-spray", "", 1)), 0o600)
	if err := detectRun(root, []string{"--rules", rules}); err == nil {
		t.Error("a correlation with no id was run")
	}
}
