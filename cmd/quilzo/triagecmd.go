// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Running detections over events and ranking what comes out.
//
// The two halves meet here: internal/detect decides what matched, and
// internal/finding decides what to look at first. Neither knows about the
// other, which is deliberate — a rule should not have an opinion about
// queue position, and a register should not care which engine raised a row.
//
// Every finding from a detection is tainted by construction. The event that
// matched is log text, log text is written by whoever can reach the log, and
// on an authentication source that includes whoever is being detected. This
// is not a hedge: the measured attack success rate against models reading
// telemetry is 83-88%, with 8-12% residual after the best layered defences.
// So the output says which sources a person has to check, and nothing here
// acts on its own.

func cmdTriage(root string, args []string) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	rules := fs.String("rules", "detections", "where the rules live")
	top := fs.Int("top", 20, "how many findings to show")
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}

	loaded, err := rulesIn(*rules)
	if err != nil {
		return err
	}
	var usable []detect.Rule
	for _, r := range loaded {
		if verr := r.Validate(); verr != nil {
			// Refused, not skipped quietly. A rule that cannot fire and is
			// silently dropped leaves a triage run that looks clean because
			// nothing was asked, which is the failure internal/detect exists
			// to make impossible.
			return fmt.Errorf("%s cannot be run: %w", r.ID, verr)
		}
		usable = append(usable, r)
	}
	if len(usable) == 0 {
		return fmt.Errorf("no usable rules in %s", *rules)
	}

	in := os.Stdin
	if len(rest) > 0 && rest[0] != "-" {
		f, oerr := os.Open(rest[0])
		if oerr != nil {
			return oerr
		}
		defer f.Close()
		in = f
	}

	reg := finding.NewRegister()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), MaxTelemetryLine)
	var events int
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var e telemetry.Event
		if uerr := json.Unmarshal([]byte(text), &e); uerr != nil {
			return fmt.Errorf("line %d is not an event: %w", line, uerr)
		}
		if verr := e.Validate(); verr != nil {
			return fmt.Errorf("line %d cannot be used: %w", line, verr)
		}
		events++
		for _, r := range usable {
			if !r.Matches(e) {
				continue
			}
			reg.Record(finding.Finding{
				Kind: finding.FromDetection, Title: r.Title,
				Source: r.ID, Entity: e.Actor,
				Severity: r.Severity, State: finding.Open,
				Technique: r.Technique,
				Evidence: []finding.Evidence{{
					At: e.Time, What: e.Message, Source: e.Source,
					// Always. The event is log text and log text is
					// attacker-influenced; a finding that forgot this is one
					// an attacker helped compose.
					Tainted: true,
				}},
			}, e.Time)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading: %w", err)
	}

	at := time.Now().UTC()
	all := reg.All(at)
	if len(all) > *top {
		all = all[:*top]
	}
	if w.JSON(map[string]any{
		"events": events, "rules": len(usable),
		"findings": reg.Len(), "top": all,
	}) {
		return nil
	}

	w.Human("%s%d event(s), %d rule(s), %d finding(s)%s\n",
		bold, events, len(usable), reg.Len(), reset)
	if reg.Len() == 0 {
		w.Human("  %snothing matched%s\n", dim, reset)
		return nil
	}
	for _, f := range all {
		w.Human("\n%s%s%s  %s\n", bold, f.Title, reset, f.Entity.String())
		w.Human("  %s%s · %s%s\n", dim, f.Source, f.Why(at), reset)
		if why := f.NeedsAPerson(); why != "" {
			w.Human("  %s%s%s\n", yellow, why, reset)
		}
	}
	return nil
}
