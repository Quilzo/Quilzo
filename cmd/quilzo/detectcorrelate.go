// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/correlate"
	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Correlations, run over the estate's own events.
//
// internal/correlate was complete — four correlation types, windows closed
// on a watermark rather than a clock, a cap on groups — and the only thing
// that ever fed it was `correlate demo`, with five invented events. A
// correlation file beside the rules was parsed by nothing and raised
// nothing. This is the run.
//
// # Re-read, not remembered
//
// A correlation window outlives a run: five failures in fifteen minutes may
// arrive across three of them. Rather than keep half-open windows on disk
// between runs — state that can be corrupted, and that makes yesterday's
// run unrepeatable — each run re-reads the recent events, evaluates them
// afresh, and closes only the windows the watermark has passed. The same
// events give the same hits every time, which is the property the package
// was built for. What is kept is only which hits have been raised already,
// so a window is a finding once.

// MaxCorrelationFile bounds one file of correlations.
const MaxCorrelationFile = 1 << 20

// correlateCursor is the watermark the last correlation run decided up to.
const correlateCursor = "correlate"

func correlatedPath(root string) string {
	return filepath.Join(detectDir(root), "correlated.json")
}

// correlationsIn reads every correlation in the rules directory: Sigma
// YAML, in .yml or .yaml files.
func correlationsIn(dir string) ([]correlate.Rule, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml") {
			files = append(files, p)
		}
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []correlate.Rule
	seen := map[string]string{}
	for _, f := range files {
		fi, serr := os.Stat(f)
		if serr != nil {
			return nil, serr
		}
		if fi.Size() > MaxCorrelationFile {
			return nil, fmt.Errorf("%s is %d bytes; a correlation is not "+
				"that big", f, fi.Size())
		}
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			return nil, rerr
		}
		rules, perr := correlate.Read(b)
		if perr != nil {
			return nil, fmt.Errorf("%s: %w", f, perr)
		}
		for _, r := range rules {
			if strings.TrimSpace(r.ID) == "" {
				return nil, fmt.Errorf("%s: %q has no id, and a finding has "+
					"to say which correlation raised it", f, r.Title)
			}
			if where, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("%s and %s both define %q", where, f,
					r.ID)
			}
			seen[r.ID] = f
			out = append(out, r)
		}
	}
	return out, nil
}

// asRule presents a correlation on the screens and in the statistics that
// list detection rules, so its ring and its verdicts sit beside theirs.
func asRule(c correlate.Rule) detect.Rule {
	return detect.Rule{ID: c.ID, Title: c.Title, Severity: c.Severity,
		Why: fmt.Sprintf("a correlation (%s) over %s within %s", c.Type,
			strings.Join(c.Rules, ", "), plainClockSpan(c.Timespan))}
}

// hitEntity is who or what a hit is about: the actor it was grouped by
// when there is one, and the group itself otherwise.
func hitEntity(h correlate.Hit) telemetry.ID {
	for _, field := range []string{"actor", "target", "device"} {
		if v, ok := h.Group[field]; ok {
			if issuer, value, cut := strings.Cut(v, ":"); cut {
				return telemetry.ID{Issuer: issuer, Value: value}
			}
		}
	}
	// Grouped by the person: the hit is about them, whichever platform's
	// identifier each event carried.
	if v, ok := h.Group["raw.person"]; ok && v != "" {
		return telemetry.ID{Issuer: "person", Value: v}
	}
	if len(h.Group) == 0 {
		return telemetry.ID{Issuer: "estate", Value: "everything"}
	}
	var parts []string
	for k, v := range h.Group {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return telemetry.ID{Issuer: "group", Value: strings.Join(parts, ",")}
}

// correlationRun is what one pass found.
type correlationRun struct {
	Rules, Hits, Opened, Late, Dropped int
}

// runCorrelations evaluates every correlation over the recent events and
// folds new hits into the register.
func runCorrelations(root string, sp *spool.Spool, dir string,
	rules []detect.Rule, rings map[string]detect.Placement,
	sups []detect.Suppression, reg *finding.Register,
	cursors map[string]time.Time, now time.Time) (correlationRun, error) {

	var run correlationRun
	corrs, err := correlationsIn(dir)
	if err != nil || len(corrs) == 0 {
		return run, err
	}
	known := map[string]bool{}
	for _, r := range rules {
		known[strings.ToLower(r.ID)] = true
	}
	var engines []*correlate.Engine
	var span time.Duration
	for _, c := range corrs {
		if rings[c.ID].Ring == detect.Off {
			continue
		}
		for _, name := range c.Rules {
			if !known[strings.ToLower(name)] {
				// A correlation over a rule that is not there can never
				// fire, and would sit on the screen looking like cover.
				return run, fmt.Errorf("%s correlates %q, and there is no "+
					"rule called that (or it is switched off)", c.ID, name)
			}
		}
		e, nerr := correlate.New(c)
		if nerr != nil {
			return run, fmt.Errorf("%s: %w", c.ID, nerr)
		}
		engines = append(engines, e)
		if c.Timespan > span {
			span = c.Timespan
		}
	}
	run.Rules = len(engines)
	if len(engines) == 0 {
		return run, nil
	}

	// Complete up to here: everything older has arrived, by the spool's own
	// measurement of how late this estate's events turn up.
	//
	// The spool's watermark is the newest arrival less the observed delay,
	// so it stops moving when a source goes quiet — and a spray followed by
	// silence would sit in a window that never closed. Time passing
	// completes a window as well: once the slowest arrival this store has
	// ever seen would have turned up, it has. Whichever is later. The
	// slowest ever, and not the usual, because closing early loses a
	// detection and closing late only delays one.
	worst := sp.Lateness(1)
	if worst < correlate.Safe {
		worst = correlate.Safe
	}
	watermark := correlate.Watermark(now, worst)
	if w := sp.Watermark(); w.After(watermark) && !w.After(now) {
		watermark = w
	}
	// Back to where the last run had got to, and a little before: every
	// window that run left open is read again whole. Not a fixed distance
	// from now — a store nobody ran this on for six hours would have six
	// hours of windows that were never decided, and nothing would say so.
	// The first run reads everything the store holds.
	var from time.Time
	if prev := cursors[correlateCursor]; !prev.IsZero() {
		from = prev.Add(-2*span - time.Hour)
	}
	err = sp.Range(from, time.Time{}, func(e telemetry.Event) error {
		for _, r := range rules {
			if !r.Matches(e) {
				continue
			}
			hidden := false
			for _, s := range sups {
				hidden = hidden || s.Hides(r.ID, e, now)
			}
			if hidden {
				continue
			}
			for _, eng := range engines {
				if !eng.Watches(r.ID) {
					continue
				}
				// No watermark on the way in: everything is read before
				// anything is closed, so nothing is "late" within a run.
				if oerr := eng.Observe(correlate.Seen{Rule: r.ID, Event: e},
					time.Time{}); oerr != nil {
					return oerr
				}
			}
		}
		return nil
	})
	if err != nil {
		return run, err
	}

	raised := map[string]time.Time{}
	if err := loadJSONFile(correlatedPath(root), &raised); err != nil {
		return run, err
	}
	for _, eng := range engines {
		c := eng.Rule()
		for _, h := range eng.Close(watermark) {
			if !from.IsZero() && h.From.Before(from) {
				// A window that began before this run read back to. Its
				// early events were not read, so its count is short and
				// it is not decided here; the run that saw all of it did.
				continue
			}
			run.Hits++
			entity := hitEntity(h)
			key := fmt.Sprintf("%s|%s|%d", c.ID, entity, h.From.Unix())
			if _, done := raised[key]; done {
				continue
			}
			raised[key] = h.To
			if _, isNew := reg.Record(finding.Finding{
				Kind: finding.FromDetection, Title: c.Title, Source: c.ID,
				Entity: entity, Severity: c.Severity, State: finding.Open,
				Trial: rings[c.ID].Ring == detect.Trial,
				Evidence: []finding.Evidence{{At: h.To, What: h.Why(),
					Source: "correlation", Tainted: true}},
			}, h.To); isNew {
				run.Opened++
			}
		}
		run.Late += eng.Late()
		run.Dropped += eng.Dropped()
	}
	// Forgotten once no run could raise them again.
	for k, to := range raised {
		if now.Sub(to) > 4*span+48*time.Hour {
			delete(raised, k)
		}
	}
	cursors[correlateCursor] = watermark
	return run, saveJSONFile(correlatedPath(root), raised)
}

// quietRulesAreCounted refuses a quiet rule that no correlation names. It
// would match, raise nothing, and be counted by nobody: a detection that
// looks installed and tells no one.
func quietRulesAreCounted(dir string, rules []detect.Rule) error {
	var quiet []string
	for _, r := range rules {
		if r.Quiet {
			quiet = append(quiet, r.ID)
		}
	}
	if len(quiet) == 0 {
		return nil
	}
	corrs, err := correlationsIn(dir)
	if err != nil {
		return err
	}
	named := map[string]bool{}
	for _, c := range corrs {
		for _, id := range c.Rules {
			named[id] = true
		}
	}
	for _, id := range quiet {
		if !named[id] {
			return fmt.Errorf("%s is quiet and no correlation counts it, so "+
				"it would match and tell nobody. Remove \"quiet\", or add "+
				"the correlation it was written for", id)
		}
	}
	return nil
}
