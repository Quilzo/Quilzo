// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
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

// postureJob runs the drift check on the server's schedule.
func postureJob(root, tplDir string, facts posture.ServerFacts) upkeep.Job {
	return upkeep.Job{
		Name: "posture",
		Do: func(now time.Time) (int, error) {
			opened, _, err := postureDrift(root, Observe(root, tplDir, facts), now)
			return opened, err
		},
	}
}
