// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/shield"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// Compliance drift, as it happens.
//
// The posture scan answered whenever somebody opened the Security screen or
// ran `quilzo posture scan`. A setting weakened on a Friday evening, an
// agent that started being refused, a chatbot made public without saying it
// is automated: each was true for as long as nobody looked. The scan is
// cheap and reads only this store, so it runs on the server's schedule
// instead, and what it finds is put on the record: a check that starts
// failing is written to the audit log once (posture.drifted), and once more
// when a later scan in which that check ran no longer reports it
// (posture.restored). The audit log is what a security team's tools read as
// it is written — Vaigil, or another SIEM (siem.stream.url) — so that is
// where it is triaged, and the security contact is told at once of a newly
// failing check that is high or critical.
//
// A check that could not run (its input was not gathered) changes nothing
// either way: silence from a check that did not look is not a fix.

// driftItem is one failing check, as last reported.
type driftItem struct {
	Rule     string           `json:"rule"`
	Resource string           `json:"resource,omitempty"`
	Severity posture.Severity `json:"severity"`
	Title    string           `json:"title"`
	Since    time.Time        `json:"since"`
}

// driftState is every check failing at the last scan, by rule and resource.
type driftState struct {
	Failing map[string]driftItem `json:"failing"`
}

func driftPath(root string) string { return filepath.Join(root, "self", "drift.json") }

func driftKey(rule, resource string) string { return rule + "|" + resource }

// loadDrift is what the last scan found failing.
func loadDrift(root string) (driftState, error) {
	st := driftState{Failing: map[string]driftItem{}}
	b, err := os.ReadFile(driftPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("self/drift.json: %w", err)
	}
	if st.Failing == nil {
		st.Failing = map[string]driftItem{}
	}
	return st, nil
}

// postureDrift scans, records what is newly failing and what is fixed, and
// returns how many of each.
func postureDrift(root string, state posture.State, now time.Time) (int, int, error) {
	sup, _ := loadSuppressions(root)
	rep := posture.Scan(state, sup)

	path := driftPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, 0, err
	}
	unlock, err := atomicfile.Lock(path + ".lock")
	if err != nil {
		return 0, 0, err
	}
	defer unlock()
	st, err := loadDrift(root)
	if err != nil {
		return 0, 0, err
	}
	reported := map[string]bool{}
	opened, fixed := 0, 0
	for _, f := range rep.Findings {
		key := driftKey(f.Rule, f.Resource)
		reported[key] = true
		if _, known := st.Failing[key]; known {
			continue
		}
		st.Failing[key] = driftItem{Rule: f.Rule, Resource: f.Resource, Severity: f.Severity,
			Title: f.Title, Since: now}
		opened++
		var refs []string
		for _, r := range f.Refs {
			refs = append(refs, r.String())
		}
		record(root, audit.Record{Action: "posture.drifted", Resource: "/security",
			Outcome: audit.Success, Principal: "quilzo", Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"rule": f.Rule, "resource": f.Resource, "severity": string(f.Severity),
				"title": f.Title, "detail": f.Detail + bearsOn(refs), "fix": f.Fix}})
		if f.Severity == posture.Critical || f.Severity == posture.High {
			summary := fmt.Sprintf("%s: %s. %s", f.Title, f.Detail, f.Fix)
			if f.Resource != "" {
				summary = fmt.Sprintf("%s (%s): %s. %s", f.Title, f.Resource, f.Detail, f.Fix)
			}
			inBackground(func() { _, _ = tellSecurity(root, strings.TrimSpace(summary)) })
		}
	}
	skipped := map[string]bool{}
	for _, id := range rep.Skipped {
		skipped[id] = true
	}
	for key, it := range st.Failing {
		if reported[key] || skipped[it.Rule] {
			continue
		}
		delete(st.Failing, key)
		fixed++
		record(root, audit.Record{Action: "posture.restored", Resource: "/security",
			Outcome: audit.Success, Principal: "quilzo", Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"rule": it.Rule, "resource": it.Resource, "severity": string(it.Severity),
				"title": it.Title, "since": it.Since.UTC().Format(time.RFC3339)}})
	}
	if opened > 0 || fixed > 0 {
		b, err := json.MarshalIndent(st, "", " ")
		if err != nil {
			return opened, fixed, err
		}
		if err := atomicfile.Write(path, b, 0o600); err != nil {
			return opened, fixed, err
		}
		record(root, audit.Record{Action: "posture.drift", Resource: "/security",
			Outcome: audit.Success, Principal: "quilzo", Kind: audit.KindService,
			Verified: true,
			Detail: map[string]string{"opened": fmt.Sprint(opened),
				"fixed": fmt.Sprint(fixed)}})
	}
	return opened, fixed, nil
}

func bearsOn(refs []string) string {
	if len(refs) == 0 {
		return ""
	}
	if len(refs) > 8 {
		refs = append(refs[:8], fmt.Sprintf("and %d more", len(refs)-8))
	}
	return ". Bears on " + strings.Join(refs, ", ")
}

// postureJob runs the drift check on the server's schedule: first putting
// back what was weakened by hand, then raising whatever sits below the
// organisation's policy, then scanning.
func postureJob(root, tplDir string, facts posture.ServerFacts) upkeep.Job {
	return upkeep.Job{
		Name: "posture",
		Do: func(now time.Time) (int, error) {
			reverted, _ := revertDrift(root, now)
			raised, _ := enforcePolicy(root, "quilzo")
			state := Observe(root, tplDir, facts)
			opened, _, err := postureDrift(root, state, now)
			// And the evidence that Quilzo's own controls operated.
			evidenced, _ := recordSelfEvidence(root, posture.Scan(state, nil), now)
			return opened + len(reverted) + len(raised) + evidenced, err
		},
	}
}

// Reverted is a setting put back to its default because it had been
// weakened by hand.
type Reverted struct {
	Key   string    `json:"key"`
	Was   string    `json:"was"`
	At    time.Time `json:"at"`
	Why   string    `json:"why"`
	Again string    `json:"again"`
}

func revertedPath(root string) string { return filepath.Join(root, "self", "reverted.json") }

// revertDrift puts back every setting running weaker than its default with
// no recorded reason: one somebody edited into the file rather than set
// with --accept-risk, which the program cannot tell from an attacker's
// edit. What it was is kept, and the security contact is told how to have
// it again properly; a weaker setting with a reason is a decision and is
// left alone.
func revertDrift(root string, now time.Time) ([]Reverted, error) {
	cfg, err := loadConfig(root)
	if err != nil {
		return nil, err
	}
	var out []Reverted
	for _, e := range cfg.Weakened() {
		// A reason was recorded: a decision, even a lapsed one, which the
		// posture reports for a person to renew or undo.
		if e.Accepted != nil {
			continue
		}
		if err := cfg.Unset(e.Setting.Key); err != nil {
			continue
		}
		out = append(out, Reverted{Key: e.Setting.Key, Was: e.Value, At: now, Why: e.Why,
			Again: fmt.Sprintf("quilzo config set %s %s --accept-risk \"why this is right here\"", e.Setting.Key, e.Value)})
	}
	if len(out) == 0 {
		return nil, nil
	}
	if err := saveConfig(root, cfg); err != nil {
		return nil, err
	}
	var kept []Reverted
	if b, err := os.ReadFile(revertedPath(root)); err == nil {
		_ = json.Unmarshal(b, &kept)
	}
	kept = append(kept, out...)
	if len(kept) > 200 {
		kept = kept[len(kept)-200:]
	}
	if err := os.MkdirAll(filepath.Dir(revertedPath(root)), 0o700); err == nil {
		if b, err := json.MarshalIndent(kept, "", " "); err == nil {
			_ = atomicfile.Write(revertedPath(root), b, 0o600)
		}
	}
	sh := newShieldHost(root)
	for _, r := range out {
		record(root, audit.Record{Action: "config.reverted", Resource: "/settings", Outcome: audit.Success,
			Principal: "quilzo", Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"setting": r.Key, "was": r.Was, "why": r.Why}})
		sh.engine.Observe(shield.Signal{Name: "setting-reverted", Subject: r.Key})
	}
	return out, nil
}
