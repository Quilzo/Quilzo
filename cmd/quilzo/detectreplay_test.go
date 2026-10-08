// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/finding"
)

// The whole loop: a false positive is closed, learned, known, fixed, and
// then guards against coming back.
func TestAFalsePositiveBecomesAGuardAgainstItsOwnReturn(t *testing.T) {
	root, rules := siemSite(t, []labelled{failedBy("admin-tools-svc", 40),
		failedBy("admin-dana", 30)})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	var svc, dana finding.Finding
	for _, f := range queue(t, root) {
		if f.Entity.Value == "admin-tools-svc" {
			svc = f
		} else {
			dana = f
		}
	}
	learn := func(id string) error {
		return cmdDetect(root, []string{"learn", id, "--rules", rules})
	}
	if err := learn(svc.ID); err == nil {
		t.Fatal("learned from a finding nobody has ruled on")
	}
	decide := func(f finding.Finding, to finding.State) {
		d := finding.Decision{Finding: f.ID, To: to, At: time.Now().UTC(),
			By: "dana", Kind: audit.KindHuman, Because: "a service account"}
		if err := recordE(root, d.Record()); err != nil {
			t.Fatal(err)
		}
	}
	decide(svc, finding.FalsePositive)
	decide(dana, finding.Triaged)
	if err := learn(svc.ID); err != nil {
		t.Fatal(err)
	}
	if err := learn(dana.ID); err != nil {
		t.Fatal(err)
	}
	if err := learn(svc.ID); err == nil {
		t.Error("the same finding was learned twice")
	}
	replay := func(extra ...string) error {
		return cmdDetect(root, append([]string{"replay", "--rules", rules}, extra...))
	}

	// Known and not fixed: passes, unless asked to be strict.
	if err := replay(); err != nil {
		t.Fatalf("a known false positive failed the replay: %v", err)
	}
	if err := replay("--strict"); err == nil {
		t.Error("--strict passed with a known false positive unfixed")
	}

	// The fix: the rule stops matching service accounts.
	rulePath := filepath.Join(rules, "privileged.json")
	narrowed := strings.Replace(privilegedFailRule,
		`{"match": {"field": "actor.value", "op": "prefix", "values": ["admin-"]}}`,
		`{"match": {"field": "actor.value", "op": "prefix", "values": ["admin-"]}},
    {"not": {"match": {"field": "actor.value", "op": "suffix", "values": ["-svc"]}}}`, 1)
	if narrowed == privilegedFailRule {
		t.Fatal("the rule text did not change")
	}
	os.WriteFile(rulePath, []byte(narrowed), 0o600)
	if err := replay("--strict"); err != nil {
		t.Fatalf("after the fix: %v", err)
	}

	// The pending mark comes off, and the entry is a guard.
	corpus := filepath.Join(rules, "corpus.jsonl")
	b, _ := os.ReadFile(corpus)
	os.WriteFile(corpus, []byte(strings.Replace(string(b), `,"pending":true`, "", 1)), 0o600)
	if err := replay(); err != nil {
		t.Fatalf("the settled corpus against the fixed rule: %v", err)
	}
	// Somebody widens the rule again.
	os.WriteFile(rulePath, []byte(privilegedFailRule), 0o600)
	err := replay()
	if err == nil || !strings.Contains(err.Error(), "wrongly raised") {
		t.Errorf("the false positive came back and the replay said: %v", err)
	}
	// And a rule broken so it misses the real one fails too.
	os.WriteFile(rulePath, []byte(strings.Replace(narrowed, `["admin-"]`,
		`["root-"]`, 1)), 0o600)
	if err := replay(); err == nil {
		t.Error("a rule that no longer catches the real sign-in passed")
	}
}

func TestAnEmptyCorpusIsNotAPass(t *testing.T) {
	root, rules := siemSite(t, nil)
	err := cmdDetect(root, []string{"replay", "--rules", rules})
	if err == nil || !strings.Contains(err.Error(), "checking nothing") {
		t.Errorf("a replay over nothing: %v", err)
	}
}
