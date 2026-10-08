// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/controls"
	"github.com/quilzo/quilzo/internal/oscal"
	"github.com/quilzo/quilzo/internal/posture"
)

// Evidence that Quilzo's own controls operated, over time.
//
// The posture scan runs on the server's schedule; each run is a moment. An
// auditor asks for a period — did AC-7 operate throughout the quarter — and
// internal/assurance measures periods. So each Quilzo control a check that
// ran bears on carries an outcome (failed if a finding names it, operated
// if not), and an evidence record is closed when the outcome changes or the
// day turns: about one record per control per day, not one per scan. Each
// goes into the evidence file and into the audit chain, whose signed heads
// are what make it evidence rather than a claim.
//
// The controls are named quilzo/AC-7 and so on, built in rather than
// declared, so they never collide with the organisation's own.

const selfEvidencePrefix = "quilzo/"

type selfOutcome struct {
	From    time.Time         `json:"from"`
	Outcome assurance.Outcome `json:"outcome"`
	Rules   []string          `json:"rules"`
}

func selfEvidenceState(root string) string {
	return filepath.Join(assuranceDir(root), "quilzo-controls.json")
}

// selfControls are Quilzo's controls as internal/assurance declares one:
// continuous, automated, named, mapped to their 800-53 control.
func selfControls() []assurance.Control {
	var out []assurance.Control
	for _, im := range controls.All() {
		if im.Responsibility == controls.Customer || len(im.Rules) == 0 {
			continue
		}
		out = append(out, assurance.Control{ID: selfEvidencePrefix + im.Control, Name: im.Title + " (Quilzo)",
			Cadence: assurance.Continuous, Owner: "Quilzo", Maps: []string{"NIST SP 800-53 " + im.Control},
			Automated: true})
	}
	return out
}

// recordSelfEvidence closes the evidence a scan ends, and opens what it
// begins.
func recordSelfEvidence(root string, rep posture.Report, now time.Time) (int, error) {
	skipped := map[string]bool{}
	for _, id := range rep.Skipped {
		skipped[id] = true
	}
	failed := map[string][]string{}
	for _, f := range rep.Findings {
		for _, c := range f.Controls {
			failed[oscal.ControlID(c)] = append(failed[oscal.ControlID(c)], f.Rule)
		}
	}
	state := map[string]selfOutcome{}
	if b, err := os.ReadFile(selfEvidenceState(root)); err == nil {
		_ = json.Unmarshal(b, &state)
	}
	var closed []assurance.Evidence
	for _, im := range controls.All() {
		if im.Responsibility == controls.Customer {
			continue
		}
		var ran []string
		for _, r := range im.Rules {
			if !skipped[r] {
				ran = append(ran, r)
			}
		}
		if len(ran) == 0 {
			continue
		}
		outcome := assurance.Operated
		if len(failed[oscal.ControlID(im.Control)]) > 0 {
			outcome = assurance.Failed
		}
		prev, seen := state[im.Control]
		switch {
		case !seen:
		case prev.Outcome == outcome && sameDay(prev.From, now):
			continue
		default:
			verb := "passed"
			if prev.Outcome == assurance.Failed {
				verb = "reported a failure"
			}
			closed = append(closed, assurance.Evidence{
				Control: selfEvidencePrefix + im.Control, From: prev.From, To: now, Outcome: prev.Outcome,
				What:   "the posture scan's checks on " + im.Control + " (" + strings.Join(prev.Rules, ", ") + ") " + verb + " throughout",
				Source: "quilzo posture, on the server's schedule", Ref: "audit log: posture.drift records in this period",
				At: now.UTC(), By: "quilzo", Kind: audit.KindService,
			})
		}
		sort.Strings(ran)
		state[im.Control] = selfOutcome{From: now.UTC(), Outcome: outcome, Rules: ran}
	}
	if len(closed) > 0 {
		if err := os.MkdirAll(assuranceDir(root), 0o700); err != nil {
			return 0, err
		}
		f, err := os.OpenFile(evidencePath(root), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return 0, err
		}
		for _, e := range closed {
			if e.Validate() != nil {
				continue
			}
			line, _ := json.Marshal(e)
			if _, err := f.Write(append(line, '\n')); err != nil {
				f.Close()
				return 0, err
			}
			record(root, e.Record())
		}
		if err := f.Close(); err != nil {
			return 0, err
		}
	}
	b, err := json.MarshalIndent(state, "", " ")
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(assuranceDir(root), 0o700); err != nil {
		return 0, err
	}
	return len(closed), atomicfile.Write(selfEvidenceState(root), b, 0o600)
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.UTC().Date()
	by, bm, bd := b.UTC().Date()
	return ay == by && am == bm && ad == bd
}
