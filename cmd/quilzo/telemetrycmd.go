// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/quilzo/quilzo/internal/telemetry"
)

// Checking a connector's output before anything depends on it.
//
// Every log source needs a connector, and a connector is a small program that
// maps somebody else's JSON onto the event model. The failures are always the
// same two, and both are silent: an identifier arrives without the system that
// issued it, so it can never be joined against another platform's; or a field
// a detection reads is absent, so the rule converts cleanly, runs, and matches
// nothing forever.
//
// Neither shows up as an error at ingest. They show up months later as a
// correlation that found nothing and a rule nobody noticed had stopped firing.
// So this reads what a connector produces and says which of them is true,
// before it is wired to anything.

// MaxTelemetryLine bounds one event.
//
// A log line is attacker-influenced — whoever can write to the source chooses
// much of its content — so the reader is bounded rather than trusting the
// newline to arrive.
const MaxTelemetryLine = 1 << 20

func cmdTelemetry(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"check"}
	}
	switch args[0] {
	case "check":
		return telemetryCheck(args[1:])
	case "fields":
		return telemetryFields(args[1:])
	default:
		return fmt.Errorf(
			"unknown telemetry command %q; try check or fields", args[0])
	}
}

// telemetryCheck validates newline-delimited events.
func telemetryCheck(args []string) error {
	in := os.Stdin
	if len(args) > 0 && args[0] != "-" {
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), MaxTelemetryLine)

	var checked, bad int
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		checked++
		var e telemetry.Event
		if err := json.Unmarshal([]byte(text), &e); err != nil {
			bad++
			w.Human("  %sline %d%s  not an event: %v\n", bold, line, reset, err)
			continue
		}
		if err := e.Validate(); err != nil {
			bad++
			w.Human("  %sline %d%s  %v\n", bold, line, reset, err)
			continue
		}
		// Valid and still worth a word. Lateness is not an error and is the
		// number a correlation window has to be built around, so a connector
		// author is told it now rather than discovering it from a rule that
		// never fires.
		if d := e.Lateness(); d < 0 {
			w.Human("  %sline %d%s  %sarrived %s before it happened; this "+
				"source's clock is ahead%s\n",
				bold, line, reset, yellow, -d, reset)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading: %w", err)
	}

	if w.JSON(map[string]any{"checked": checked, "refused": bad}) {
		return nil
	}
	if checked == 0 {
		w.Human("nothing to check\n")
		return nil
	}
	if bad == 0 {
		w.Human("%s%d event(s), all usable%s\n", green, checked, reset)
		return nil
	}
	return fmt.Errorf("%d of %d event(s) cannot be used", bad, checked)
}

// telemetryFields prints what a detection may refer to.
//
// The authoring surface, from the model rather than from documentation. A rule
// naming a field that does not exist is a rule that never fires, and the
// cheapest moment to catch that is while somebody is writing it.
func telemetryFields(args []string) error {
	var e telemetry.Event
	if len(args) > 0 && args[0] != "-" {
		body, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		// The first event in the file, so the list reflects what this
		// connector actually emits rather than what the model can hold.
		line, _, _ := strings.Cut(strings.TrimSpace(string(body)), "\n")
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return fmt.Errorf("%s does not start with an event: %w", args[0], err)
		}
	} else {
		e = telemetry.Event{
			Source: "example", Class: telemetry.ClassAuthentication,
			Actor:  telemetry.ID{Issuer: "okta", Value: "u-1"},
			Device: telemetry.ID{Issuer: "kandji", Value: "d-1"},
			Observables: []telemetry.Observable{
				{Kind: telemetry.ObservableIP, Value: "203.0.113.9"},
			},
		}
	}
	names := e.FieldNames()
	if w.JSON(names) {
		return nil
	}
	w.Human("%s%d field(s) a rule may refer to%s\n", bold, len(names), reset)
	f := e.Fields()
	for _, n := range names {
		w.Human("  %-22s %s%s%s\n", n, dim, f[n], reset)
	}
	w.Human("\n  %sa rule naming anything else never fires, and nothing "+
		"reports that%s\n", dim, reset)
	return nil
}
