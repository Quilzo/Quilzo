// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Storing events, saying honestly what the store covers, and deleting on
// purpose rather than as a side effect.
//
// Every other command here reads a file somebody handed it. That is fine for
// writing a detection and useless for running one, because the question a
// detection asks — what else happened around this — needs a store that can
// answer for a period and say which period it can answer for.
//
// Sealing a segment anchors its digest in the audit log. The audit log signs
// with Ed25519 and ML-DSA-65, which is unaffordable per event and perfectly
// affordable per segment: one hash of sixty megabytes of telemetry, signed
// twice, and rewriting any of that telemetry afterwards means forging a
// post-quantum signature.

func spoolDir(root string) string { return filepath.Join(root, "spool") }

func cmdSpool(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"stats"}
	}
	switch args[0] {
	case "add":
		return spoolAdd(root, args[1:])
	case "stats":
		return spoolStats(root, args[1:])
	case "verify":
		return spoolVerify(root)
	case "retain":
		return spoolRetain(root, args[1:])
	case "hold":
		return spoolHold(root, args[1:])
	case "lift":
		return spoolLift(root, args[1:])
	default:
		return fmt.Errorf("unknown spool command %q; try add, stats, "+
			"verify, retain, hold or lift", args[0])
	}
}

func openSpool(root string, o spool.Options) (*spool.Spool, error) {
	return spool.Open(spoolDir(root), o)
}

// spoolAdd ingests events.
func spoolAdd(root string, args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	keep := fs.Duration("keep", spool.DefaultKeep, "how long to retain")
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}

	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}

	s, err := openSpool(root, spool.Options{Keep: *keep})
	if err != nil {
		return err
	}
	before := s.Anchor()

	in := os.Stdin
	if len(rest) > 0 && rest[0] != "-" {
		f, oerr := os.Open(rest[0])
		if oerr != nil {
			return oerr
		}
		defer f.Close()
		in = f
	}

	var stored int
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), MaxTelemetryLine)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var e telemetry.Event
		if uerr := json.Unmarshal([]byte(text), &e); uerr != nil {
			return fmt.Errorf("line %d is not an event: %w", line, uerr)
		}
		// Arrival is stamped by the spool, not taken from the file. A
		// connector replaying yesterday's export is delivering it now, and
		// the clock the store partitions on has to be one the source cannot
		// move.
		e.Received = time.Time{}
		if _, aerr := s.Append(e); aerr != nil {
			return fmt.Errorf("line %d: %w", line, aerr)
		}
		stored++
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading: %w", err)
	}
	if err := s.Seal(); err != nil {
		return err
	}
	anchorSealed(root, caller, before, s.Anchor())

	if w.JSON(map[string]any{
		"stored": stored, "events": s.Events(), "bytes": s.Bytes(),
	}) {
		return nil
	}
	w.Human("%s%d event(s) stored%s\n", bold, stored, reset)
	w.Human("  %sthe spool now holds %d event(s) in %d byte(s)%s\n",
		dim, s.Events(), s.Bytes(), reset)
	return nil
}

// anchorSealed records the digest of every segment sealed by this run.
func anchorSealed(root string, caller *Caller,
	before, after map[string]string) {

	var names []string
	for name := range after {
		if _, had := before[name]; !had {
			names = append(names, name)
		}
	}
	for _, name := range names {
		record(root, audit.Record{
			Action: "spool.sealed", Resource: "/spool/" + name,
			Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
			Verified: caller.Kind != audit.KindUnknown,
			Detail: map[string]string{
				"segment": name, "sha256": after[name],
			},
		})
	}
}

func spoolStats(root string, args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	defer s.Close()

	segs := s.Segments()
	stats := map[string]any{
		"segments": len(segs), "events": s.Events(), "bytes": s.Bytes(),
		"oldest": s.Oldest(), "watermark": s.Watermark(),
		"lateness_p50": s.Lateness(0.5).String(),
		"lateness_p99": s.Lateness(0.99).String(),
		"lateness_max": s.Lateness(1).String(),
		"ahead":        s.Ahead(), "holds": s.Holds(),
	}
	if w.JSON(stats) {
		return nil
	}
	if len(segs) == 0 {
		w.Human("the spool is empty\n")
		return nil
	}
	w.Human("%s%d event(s) in %d segment(s), %d byte(s)%s\n",
		bold, s.Events(), len(segs), s.Bytes(), reset)
	// The honest answer to "how far back can we look", which is not the
	// configured retention.
	w.Human("  %sanswers from %s%s\n",
		dim, s.Oldest().Format(time.RFC3339), reset)
	w.Human("  %sarrival delay: %s median, %s at the 99th, %s worst ever "+
		"seen%s\n", dim, s.Lateness(0.5), s.Lateness(0.99), s.Lateness(1),
		reset)
	w.Human("  %scomplete up to %s — a window ending after that is still "+
		"waiting%s\n", dim, s.Watermark().Format(time.RFC3339), reset)
	if s.Ahead() > 0 {
		w.Human("  %s%d event(s) arrived with a source clock running "+
			"ahead of ours%s\n", yellow, s.Ahead(), reset)
	}
	for _, h := range s.Holds() {
		w.Human("  %shold %s by %s: %s%s\n",
			yellow, h.Name, h.By, h.Why, reset)
	}
	return nil
}

func spoolVerify(root string) error {
	s, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	defer s.Close()
	bad, err := s.Verify()
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"checked": len(s.Anchor()), "bad": bad}) {
		return nil
	}
	if len(bad) == 0 {
		w.Human("%s%d sealed segment(s) match their digests%s\n",
			green, len(s.Anchor()), reset)
		w.Human("  %sthose digests are in the audit log, which is signed; "+
			"rewriting one means forging a signature%s\n", dim, reset)
		return nil
	}
	for _, b := range bad {
		w.Human("%s%s%s\n", red, b, reset)
	}
	return fmt.Errorf("%d segment(s) do not match what was recorded", len(bad))
}

func spoolRetain(root string, args []string) error {
	fs := flag.NewFlagSet("retain", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "carry the plan out")
	keep := fs.Duration("keep", spool.DefaultKeep, "the age limit")
	capBytes := fs.Int64("cap", spool.DefaultCap, "the size limit, in bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	s, err := openSpool(root, spool.Options{Keep: *keep, Cap: *capBytes})
	if err != nil {
		return err
	}
	defer s.Close()

	plan := s.Retain()
	if !*apply {
		if w.JSON(plan) {
			return nil
		}
		w.Human("%s%s%s\n", bold, plan.Why(), reset)
		for _, seg := range plan.Drop {
			w.Human("  %s%s  %d event(s)  %d byte(s)%s\n",
				dim, seg.Name, seg.Events, seg.Bytes, reset)
		}
		if len(plan.Drop) > 0 {
			w.Human("\n  %snothing was deleted. Run again with --apply%s\n",
				dim, reset)
		}
		return nil
	}

	caller := resolveCaller(root, flagToken)
	// Deleting evidence is the same authority as publishing: it is a
	// statement the organisation stands behind, and it cannot be undone.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	gone, err := s.Apply(plan)
	if err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "spool.retained", Resource: "/spool",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Kind != audit.KindUnknown,
		Detail:   detailOfRetention(gone, plan),
	})
	if w.JSON(map[string]any{"dropped": gone, "covers": plan.Covers}) {
		return nil
	}
	w.Human("%s%d segment(s) deleted%s\n", bold, gone, reset)
	if oldest := s.Oldest(); oldest.IsZero() {
		w.Human("  %sthe spool is empty and answers for no period%s\n",
			dim, reset)
	} else {
		w.Human("  %sthe spool answers from %s%s\n",
			dim, oldest.Format(time.RFC3339), reset)
	}
	return nil
}

// detailOfRetention is what the audit log records about a deletion.
//
// "covers: 0001-01-01" is what a zero time formats to, and in the one record
// that says what evidence was destroyed it would read as a date rather than
// as "nothing is left". The audit log is the artefact somebody reads years
// later without any of this context.
func detailOfRetention(gone int, plan spool.Plan) map[string]string {
	covers := "nothing; the spool is empty"
	if !plan.Covers.IsZero() {
		covers = plan.Covers.Format(time.RFC3339)
	}
	return map[string]string{
		"dropped": fmt.Sprint(gone),
		"freed":   fmt.Sprint(plan.Freed),
		"covers":  covers,
	}
}

func spoolHold(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("hold", flag.ContinueOnError)
	why := fs.String("why", "", "why the hold exists")
	until := fs.String("until", "", "when it lifts, as 2026-12-31")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo spool hold NAME --why ... " +
			"[--until 2026-12-31]")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	s, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	defer s.Close()

	h := spool.Hold{Name: pos[0], By: caller.Name, At: time.Now().UTC(),
		Why: strings.TrimSpace(*why)}
	if strings.TrimSpace(*until) != "" {
		parsed, perr := time.Parse("2006-01-02", strings.TrimSpace(*until))
		if perr != nil {
			return fmt.Errorf("--until is a date like 2026-12-31: %w", perr)
		}
		h.Until = parsed.UTC()
	}
	if err := s.Hold(h); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "spool.held", Resource: "/spool/" + h.Name,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Kind != audit.KindUnknown,
		Detail:   map[string]string{"hold": h.Name, "why": h.Why},
	})
	if w.JSON(h) {
		return nil
	}
	w.Human("%s%s%s holds the whole spool against retention\n",
		bold, h.Name, reset)
	w.Human("  %sa hold scoped to a date range is one placed before anybody "+
		"knows when the incident started%s\n", dim, reset)
	return nil
}

func spoolLift(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo spool lift NAME")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	s, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Lift(pos[0]); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "spool.lifted", Resource: "/spool/" + pos[0],
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Kind != audit.KindUnknown,
		Detail:   map[string]string{"hold": pos[0]},
	})
	if w.JSON(map[string]any{"lifted": pos[0]}) {
		return nil
	}
	w.Human("%s%s%s lifted; retention can run again\n", bold, pos[0], reset)
	return nil
}
