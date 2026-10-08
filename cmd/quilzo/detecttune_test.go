// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

const rule = "auth.privileged-failed"

func failedBy(who string, minutesAgo int) labelled {
	at := time.Now().UTC().Add(-time.Duration(minutesAgo) * time.Minute).
		Truncate(time.Second)
	return labelled{who, true, signIn("okta/system", who,
		telemetry.DispositionFailed, "sign-in failed", at)}
}

func entities(q []finding.Finding) string {
	var out []string
	for _, f := range q {
		out = append(out, f.Entity.Value)
	}
	return strings.Join(out, " ")
}

// A suppression hides one account from one rule, counts what it hid, and
// lets everything else through.
func TestASuppressionHidesOneAccountAndCountsIt(t *testing.T) {
	root, rules := siemSite(t, nil)
	until := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	if err := cmdDetect(root, []string{"suppress", rule,
		"actor=okta:admin-backup", "--owner", "dana", "--until", until,
		"--because", "nightly backup job retries", "--rules", rules}); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, []labelled{failedBy("admin-backup", 50),
		failedBy("admin-backup", 40), failedBy("admin-dana", 30)})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if got := entities(queue(t, root)); got != "admin-dana" {
		t.Errorf("the queue holds %q; the backup account is suppressed and "+
			"the real administrator is not", got)
	}
	sups, _ := loadDetectSuppressions(root)
	hits, _ := loadHits(root)
	if len(sups) != 1 || hits[sups[0].ID] != 2 {
		t.Errorf("two events were hidden and %d were counted", hits[sups[0].ID])
	}

	// Removed, the account is reported again.
	if err := cmdDetect(root, []string{"unsuppress", sups[0].ID}); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, []labelled{failedBy("admin-backup", 5)})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if got := entities(queue(t, root)); !strings.Contains(got, "admin-backup") {
		t.Errorf("after the suppression was removed the queue holds %q", got)
	}
}

func TestASuppressionWithNoEdgesIsRefusedAtTheCommand(t *testing.T) {
	root, rules := siemSite(t, nil)
	soon := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	far := time.Now().AddDate(2, 0, 0).Format("2006-01-02")
	base := func(target string, extra ...string) []string {
		return append([]string{"suppress", rule, target, "--rules", rules},
			extra...)
	}
	for name, args := range map[string][]string{
		"no expiry":      base("actor=okta:x", "--owner", "d", "--because", "b"),
		"two years":      base("actor=okta:x", "--owner", "d", "--because", "b", "--until", far),
		"no owner":       base("actor=okta:x", "--because", "b", "--until", soon),
		"no reason":      base("actor=okta:x", "--owner", "d", "--until", soon),
		"a whole source": base("source=okta/system", "--owner", "d", "--because", "b", "--until", soon),
		"a rule nobody has": {"suppress", "auth.nothing", "actor=okta:x",
			"--owner", "d", "--because", "b", "--until", soon, "--rules", rules},
	} {
		if err := cmdDetect(root, args); err == nil {
			t.Errorf("a suppression with %s was accepted", name)
		}
	}
	if sups, _ := loadDetectSuppressions(root); len(sups) != 0 {
		t.Errorf("%d refused suppressions were stored", len(sups))
	}
}

// Trial: the rule runs, its findings are kept and can be decided, and none
// of it is in the queue people work from. Off: it does not run.
func TestTheRingDecidesWhatReachesTheQueue(t *testing.T) {
	root, rules := siemSite(t, nil)
	if err := cmdDetect(root, []string{"ring", rule, "trial", "--rules", rules}); err == nil {
		t.Fatal("a rule left the queue with no reason given")
	}
	if err := cmdDetect(root, []string{"ring", "auth.nothing", "trial",
		"--because", "x", "--rules", rules}); err == nil {
		t.Error("a ring was set for a rule that does not exist")
	}
	if err := cmdDetect(root, []string{"ring", rule, "trial", "--because",
		"noisy since the migration", "--rules", rules}); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, []labelled{failedBy("admin-dana", 30)})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	all := queue(t, root)
	if len(all) != 1 || !all[0].Trial {
		t.Fatalf("a trial rule's finding: %+v", all)
	}
	if n := len(filterQueue(all, "", "")); n != 0 {
		t.Errorf("%d trial finding(s) in the working queue", n)
	}
	if n := len(filterQueue(all, "trial", "")); n != 1 {
		t.Errorf("the trial filter shows %d", n)
	}

	// Promoted, what it found comes with it the next time it fires.
	if err := cmdDetect(root, []string{"ring", rule, "live", "--rules", rules}); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, []labelled{failedBy("admin-dana", 10)})
	detectRun(root, []string{"--rules", rules})
	if n := len(filterQueue(queue(t, root), "", "")); n != 1 {
		t.Errorf("after promotion the working queue holds %d", n)
	}

	// Off: not run at all, and the run says so rather than looking quiet.
	if err := cmdDetect(root, []string{"ring", rule, "off", "--because",
		"replaced", "--rules", rules}); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, []labelled{failedBy("admin-eve", 2)})
	err := detectRun(root, []string{"--rules", rules})
	if err == nil || !strings.Contains(err.Error(), "switched off") {
		t.Errorf("a run with every rule off: %v", err)
	}
	if strings.Contains(entities(queue(t, root)), "admin-eve") {
		t.Error("a rule that is off raised a finding")
	}
}

// From verdicts to a proposal: twelve accounts, eleven closed as false
// positives, and the rule is proposed for demotion — and not before.
func TestVerdictsBecomePrecisionAndAProposal(t *testing.T) {
	root, rules := siemSite(t, nil)
	var corpus []labelled
	for i := 0; i < 12; i++ {
		corpus = append(corpus, failedBy(fmt.Sprintf("admin-%02d", i), 60-i))
	}
	appendEvents(t, root, corpus)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	decide := func(f finding.Finding, to finding.State) {
		t.Helper()
		d := finding.Decision{Finding: f.ID, To: to, At: time.Now().UTC(),
			By: "dana", Kind: audit.KindHuman, Because: "checked with them"}
		if err := recordE(root, d.Record()); err != nil {
			t.Fatal(err)
		}
	}
	q := queue(t, root)
	for i, f := range q[:6] {
		to := finding.FalsePositive
		if i == 0 {
			to = finding.Triaged
		}
		decide(f, to)
	}
	tn, err := loadTuning(root, rules, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if s := tn.Stats[0]; s.Decided() != 6 || s.Undecided != 6 {
		t.Fatalf("%+v", s)
	}
	if len(tn.Proposals) != 0 {
		t.Errorf("proposed %v from six verdicts", tn.Proposals)
	}
	for _, f := range q[6:] {
		decide(f, finding.FalsePositive)
	}
	tn, _ = loadTuning(root, rules, time.Now().UTC())
	if s := tn.Stats[0]; s.Real != 1 || s.False != 11 {
		t.Fatalf("%+v", s)
	}
	if len(tn.Proposals) != 1 || tn.Proposals[0].Do != "demote" {
		t.Errorf("one real of twelve: proposed %v", tn.Proposals)
	}
	// Proposing changed nothing.
	if rings, _ := loadRings(root); len(rings) != 0 {
		t.Error("a proposal moved the rule by itself")
	}
}

func TestAModelCannotQuietenADetection(t *testing.T) {
	root, rules := siemSite(t, nil)
	if err := setRing(root, rules, rule, detect.Trial, "noisy", "agent",
		audit.KindAI); err == nil {
		t.Error("a model moved a rule out of the queue")
	}
	_, err := addSuppression(root, rules, detect.Suppression{Rule: rule,
		Field: "actor", Value: "okta:admin-dana", Owner: "dana",
		Because: "told to", By: "agent", Kind: audit.KindAI,
		Until: time.Now().AddDate(0, 0, 7)})
	if err == nil {
		t.Error("a model suppressed an administrator's failed sign-ins")
	}
	if _, serr := os.Stat(ringsPath(root)); serr == nil {
		t.Error("the refused change was written")
	}
}
