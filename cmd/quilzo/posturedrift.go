// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"fmt"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/shield"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// Compliance drift, as it happens.
//
// The posture scan answered whenever somebody opened the Security screen or
// ran `quilzo posture scan`. A setting weakened on a Friday evening, an
// agent that started being refused, a chatbot made public without saying it
// is automated: each was true for as long as nobody looked. The scan is
// cheap and reads only this store, so it runs on the server's schedule
// instead, and what it finds goes where every other security problem goes —
// the findings queue — where it can be assigned, gathered into an incident
// and ruled on.
//
// A finding is opened the first time its check reports it and goes stale
// when a later scan, in which that check ran, no longer does. A check that
// could not run (its input was not gathered) changes nothing either way:
// silence from a check that did not look is not a fix.

// postureSource is what a drift finding's Source starts with.
const postureSource = "posture/"

func postureSeverity(s posture.Severity) telemetry.Severity {
	switch s {
	case posture.Critical:
		return telemetry.SeverityCritical
	case posture.High:
		return telemetry.SeverityHigh
	case posture.Medium:
		return telemetry.SeverityMedium
	case posture.Low:
		return telemetry.SeverityLow
	}
	return telemetry.SeverityInfo
}

// postureDrift scans, records what is newly failing, stales what has been
// fixed, and returns how many findings it opened.
func postureDrift(root string, state posture.State, now time.Time) (int, int, error) {
	sup, _ := loadSuppressions(root)
	rep := posture.Scan(state, sup)

	path := findingsPath(root)
	unlock, err := finding.Lock(path)
	if err != nil {
		return 0, 0, err
	}
	defer unlock()
	reg, cursors, err := finding.Load(path)
	if err != nil {
		return 0, 0, err
	}
	opened := 0
	reported := map[string]bool{}
	for _, f := range rep.Findings {
		what := f.Resource
		if what == "" {
			what = f.Rule
		}
		var refs []string
		for _, r := range f.Refs {
			refs = append(refs, r.String())
		}
		fd := finding.Finding{Kind: finding.FromControl, Title: f.Title,
			Source:   postureSource + f.Rule,
			Entity:   telemetry.ID{Issuer: "quilzo", Value: what},
			Severity: postureSeverity(f.Severity), State: finding.Open,
			Evidence: []finding.Evidence{{At: now, Source: "posture",
				What: f.Detail + bearsOn(refs)}}}
		rec, isNew := reg.Record(fd, now)
		if rec != nil {
			reported[rec.ID] = true
		}
		if isNew {
			opened++
		}
	}
	skipped := map[string]bool{}
	for _, id := range rep.Skipped {
		skipped[postureSource+id] = true
	}
	staled := reg.Unreported(func(f finding.Finding) bool {
		return strings.HasPrefix(f.Source, postureSource) && !skipped[f.Source]
	}, reported)
	if err := finding.Save(path, reg, cursors); err != nil {
		return opened, len(staled), err
	}
	if opened > 0 || len(staled) > 0 {
		record(root, audit.Record{Action: "posture.drift", Resource: "/security",
			Outcome: audit.Success, Principal: "quilzo", Kind: audit.KindService,
			Verified: true,
			Detail: map[string]string{"opened": fmt.Sprint(opened),
				"fixed": fmt.Sprint(len(staled))}})
	}
	return opened, len(staled), nil
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
