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

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/canary"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Planting values nothing legitimate reads, and noticing when they come back.
//
// The register is a file the operator keeps, not a store this program owns,
// and that is a deliberate limitation rather than an unfinished one. A canary
// register is a list of secrets and their hiding places: the single most
// useful file an attacker inside the estate could read. Until it can be kept
// somewhere the running web process cannot reach, keeping it out of the store
// the web process serves is the honest arrangement.
//
// The audit log records that a canary was planted and where. It does not
// record the value — an audit log is the artefact you export to an auditor,
// a customer and a SIEM, and a canary written into it has been handed to
// everyone who will ever read a compliance package.

func cmdCanary(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "mint":
		return canaryMint(args[1:])
	case "plant":
		return canaryPlant(root, args[1:])
	case "watch":
		return canaryWatch(args[1:])
	case "status":
		return canaryStatus(args[1:])
	default:
		return fmt.Errorf(
			"unknown canary command %q; try mint, plant, watch or status",
			args[0])
	}
}

func canaryMint(args []string) error {
	pos, _ := leadingArgs(args, 1)
	kind := canary.AsCredential
	if len(pos) > 0 {
		kind = canary.Kind(pos[0])
	}
	value, err := canary.Mint(kind)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{
		"kind": string(kind), "value": value, "id": canary.Ident(value),
	}) {
		return nil
	}
	w.Human("%s%s%s\n", bold, value, reset)
	w.Human("  %sid %s — the id is a hash, so it can go in a ticket and the "+
		"value cannot%s\n", dim, canary.Ident(value), reset)
	w.Human("  %splant it somewhere nothing reads, then record it with "+
		"quilzo canary plant%s\n", dim, reset)
	return nil
}

func canaryPlant(root string, args []string) error {
	fs := flag.NewFlagSet("plant", flag.ContinueOnError)
	kind := fs.String("kind", string(canary.AsCredential),
		"credential, file, record or address")
	where := fs.String("where", "", "where it is planted, as a person "+
		"would have to be told to find it")
	why := fs.String("why", "", "what a trip would mean, in one line")
	owner := fs.String("owner", "", "who is told when it fires")
	expect := fs.String("expect", "", "comma-separated things permitted to "+
		"touch it without it counting; usually empty")
	value := fs.String("value", "", "an existing value; minted when absent")
	if err := fs.Parse(args); err != nil {
		return err
	}

	v := strings.TrimSpace(*value)
	if v == "" {
		minted, err := canary.Mint(canary.Kind(*kind))
		if err != nil {
			return err
		}
		v = minted
	}
	c := canary.Canary{
		Kind: canary.Kind(*kind), Value: v, ID: canary.Ident(v),
		Where: strings.TrimSpace(*where), Why: strings.TrimSpace(*why),
		Owner: strings.TrimSpace(*owner),
		// Planted now rather than when the operator gets round to putting the
		// file in the bucket. The clock that matters is the one that decides
		// when nobody has confirmed it recently enough to believe it, and
		// starting that clock late is starting it wrong.
		Planted: time.Now().UTC(), State: canary.Armed,
	}
	for _, e := range strings.Split(*expect, ",") {
		if strings.TrimSpace(e) != "" {
			c.Expect = append(c.Expect, strings.TrimSpace(e))
		}
	}
	if err := c.Validate(); err != nil {
		return err
	}

	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	// The id and the placement, never the value. See the file comment.
	record(root, audit.Record{
		Action: "canary.planted", Resource: "/canary/" + c.ID,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Kind != audit.KindUnknown,
		Detail: map[string]string{
			"canary": c.ID, "kind": string(c.Kind), "where": c.Where,
			"why": c.Why,
		},
	})

	line, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if w.JSON(c) {
		return nil
	}
	w.Human("%s%s%s planted at %s\n", bold, c.ID, reset, c.Where)
	w.Human("  %sthe audit log has the id and the placement; the value is "+
		"below and is written down nowhere else%s\n", dim, reset)
	w.Human("\n%s\n\n", line)
	w.Human("  %sappend that to your canary register, then put the value in "+
		"place%s\n", dim, reset)
	if len(c.Expect) > 0 {
		w.Human("  %s%d permitted toucher(s): every one of them is a way "+
			"this stops being evidence%s\n", yellow, len(c.Expect), reset)
	}
	return nil
}

// canaryWatch scans events for planted values.
func canaryWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	register := fs.String("canaries", "canaries.jsonl",
		"the register, one canary per line")
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	set, err := canariesIn(*register)
	if err != nil {
		return err
	}
	if set.Len() == 0 {
		return fmt.Errorf("%s holds no canaries, so this watches nothing",
			*register)
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

	var events, fired, spent int
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
		if verr := e.Validate(); verr != nil {
			return fmt.Errorf("line %d cannot be used: %w", line, verr)
		}
		events++
		for _, c := range set.Match(e) {
			switch c.Touch(canary.Trip{
				At: e.Time, By: e.Actor, From: e.Source, How: e.Message,
			}) {
			case canary.Fired:
				fired++
			case canary.Spent:
				spent++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading: %w", err)
	}

	at := time.Now().UTC()
	found := set.Findings(at)
	if w.JSON(map[string]any{
		"events": events, "canaries": set.Len(),
		"fired": fired, "spent": spent, "findings": found,
	}) {
		return nil
	}
	w.Human("%s%d event(s) against %d canary(ies)%s\n",
		bold, events, set.Len(), reset)
	if fired == 0 && spent == 0 {
		w.Human("  %snothing touched one%s\n", dim, reset)
	}
	reportCanaryFindings(found, at)
	return nil
}

// canaryStatus reports what the register is currently worth.
func canaryStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	register := fs.String("canaries", "canaries.jsonl", "the register")
	if err := fs.Parse(args); err != nil {
		return err
	}
	set, err := canariesIn(*register)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	all := set.All()
	found := set.Findings(at)

	if w.JSON(map[string]any{
		"canaries": all, "findings": found,
	}) {
		return nil
	}
	if len(all) == 0 {
		w.Human("%s holds no canaries\n", *register)
		return nil
	}
	for _, c := range all {
		state := string(c.State)
		colour := green
		if c.State != canary.Armed {
			colour = yellow
		}
		if c.State == canary.Armed && !c.Confident(at) {
			// Not armed and not gone. Nobody has looked, and saying "armed"
			// would be reporting a belief as a fact.
			state, colour = "unconfirmed", yellow
		}
		w.Human("%s%s%s  %s%s%s  %s\n",
			bold, c.ID, reset, colour, state, reset, c.Where)
		w.Human("  %s%s%s\n", dim, c.Why, reset)
	}
	reportCanaryFindings(found, at)
	return nil
}

func reportCanaryFindings(found []finding.Finding, at time.Time) {
	if len(found) == 0 {
		return
	}
	w.Human("\n%s%d thing(s) to do%s\n", bold, len(found), reset)
	for _, f := range found {
		w.Human("\n%s%s%s\n", bold, f.Title, reset)
		w.Human("  %s%s%s\n", dim, f.Why(at), reset)
		if why := f.NeedsAPerson(); why != "" {
			w.Human("  %s%s%s\n", yellow, why, reset)
		}
	}
}

// canariesIn reads a register file.
//
// A missing file is not an error for status — a deployment with no canaries
// is the normal starting state and saying so is more useful than a stack
// trace. A malformed line is an error, because a register that silently
// dropped a canary is a canary nobody is watching for.
func canariesIn(path string) (*canary.Set, error) {
	set := canary.NewSet()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return set, nil
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 8<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var c canary.Canary
		if uerr := json.Unmarshal([]byte(text), &c); uerr != nil {
			return nil, fmt.Errorf("%s line %d is not a canary: %w",
				path, line, uerr)
		}
		if _, perr := set.Plant(c); perr != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, perr)
		}
	}
	return set, sc.Err()
}
