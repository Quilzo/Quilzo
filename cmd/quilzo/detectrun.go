// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Running the detections over what the event store holds.
//
// The piece that was missing between two that existed. Events were stored by
// `spool add` and rules were tested by `detect test`, and nothing ran the one
// over the other: `triage` would, over events piped into it, and then printed
// twenty lines and kept nothing. So a rule could be written, proved and never
// once evaluated against the estate it was written for.
//
// This reads new arrivals since the last run, evaluates every rule, and folds
// matches into the finding register that the queue screen, the CLI and the
// machine interface all read.

// findingsPath is the finding register.
func findingsPath(root string) string { return filepath.Join(root, "findings.json") }

// detectCursor is the name this producer's position is kept under.
const detectCursor = "detect"

// detectRun evaluates the rules over events that arrived since the last run.
func detectRun(root string, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	rulesDir := fs.String("rules", "detections", "where the rules live")
	since := fs.Duration("since", 0,
		"on a first run, how far back to look (zero means everything held)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}

	loaded, err := rulesIn(*rulesDir)
	if err != nil {
		return err
	}
	var rules []detect.Rule
	for _, r := range loaded {
		if verr := r.Validate(); verr != nil {
			// Refused, not skipped. A run that silently dropped a rule looks
			// clean because nothing was asked.
			return fmt.Errorf("%s cannot be run: %w", r.ID, verr)
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return fmt.Errorf("no rules in %s, so a run would find nothing and "+
			"report that as a quiet estate", *rulesDir)
	}

	// Read the store without creating it: a run against a site that has
	// never collected anything is a mistake worth saying, not an empty
	// result worth recording.
	if _, serr := os.Stat(spoolDir(root)); serr != nil {
		return fmt.Errorf("no events have been stored in this site yet; " +
			"add some with quilzo spool add")
	}
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	defer sp.Close()

	path := findingsPath(root)
	unlock, err := finding.Lock(path)
	if err != nil {
		return err
	}
	defer unlock()

	reg, cursors, err := finding.Load(path)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	from := cursors[detectCursor]
	switch {
	case !from.IsZero():
		// Range is [from, to): the event at exactly the cursor was counted
		// last time.
		from = from.Add(time.Nanosecond)
	case *since > 0:
		from = now.Add(-*since)
	}

	var events, matches, opened int
	var through time.Time
	err = sp.Range(from, time.Time{}, func(e telemetry.Event) error {
		events++
		if e.Received.After(through) {
			through = e.Received
		}
		for _, r := range rules {
			if !r.Matches(e) {
				continue
			}
			matches++
			if _, isNew := reg.Record(finding.Finding{
				Kind: finding.FromDetection, Title: r.Title, Source: r.ID,
				Entity: e.Actor, Severity: r.Severity, State: finding.Open,
				Technique: r.Technique,
				Evidence: []finding.Evidence{{
					At: e.Time, What: e.Message, Source: e.Source,
					// Always. Log text is written by whoever can reach the
					// log, including whoever is being detected.
					Tainted: true,
				}},
			}, e.Time); isNew {
				opened++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !through.IsZero() {
		cursors[detectCursor] = through
	}
	if err := finding.Save(path, reg, cursors); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "detect.run", Resource: "/findings", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"rules": strconv.Itoa(len(rules)), "events": strconv.Itoa(events),
			"matches": strconv.Itoa(matches), "opened": strconv.Itoa(opened),
		},
	})

	if w.JSON(map[string]any{
		"rules": len(rules), "events": events, "matches": matches,
		"opened": opened, "findings": reg.Len(), "through": through,
	}) {
		return nil
	}
	w.Human("%s%d rule(s) over %d new event(s): %d match(es), %d new "+
		"finding(s)%s\n", bold, len(rules), events, matches, opened, reset)
	if events == 0 {
		w.Human("  %snothing arrived since the last run%s\n", dim, reset)
	} else {
		w.Human("  %sthe register holds %d finding(s); read them with "+
			"quilzo finding list%s\n", dim, reg.Len(), reset)
	}
	return nil
}

// findingsCapability is the finding register for the admin: the same queue
// `quilzo finding list` prints, and decisions written the way `quilzo finding
// decide` writes them.
func findingsCapability(root string) *admin.Findings {
	return &admin.Findings{
		Queue: func(now time.Time) ([]finding.Finding, bool, error) {
			q, err := loadQueue(root, now)
			return q, fileExists(findingsPath(root)), err
		},
		History: func(id string) ([]finding.Decision, error) {
			events, err := audit.Read(auditPath(root))
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			return finding.History(id, finding.FromAudit(events)), nil
		},
		Proposals: func(id string) ([]finding.Proposal, error) {
			events, err := audit.Read(auditPath(root))
			if err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			return finding.ProposalsFromAudit(events, id), nil
		},
		Decide: func(d finding.Decision) error {
			if err := d.Validate(); err != nil {
				return err
			}
			return recordE(root, d.Record())
		},
	}
}
