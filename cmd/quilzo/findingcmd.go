// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/finding"
)

// Deciding about a finding, and reading back what was decided.
//
// The decision goes into the audit log and nowhere else. There is no status
// column to update, because a column has no past and the question an auditor
// asks is entirely about the past: who accepted this, when, on what grounds,
// and who reviewed it since. A mutable field answers that with whatever it
// says now, which is exactly as trustworthy as the last person with write
// access.
//
// So `finding decide` appends, `finding story` replays. Rewriting a decision
// means forging a hash chain and two signatures, one of them post-quantum.

func cmdFinding(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"story"}
	}
	switch args[0] {
	case "decide":
		return findingDecide(root, args[1:])
	case "story":
		return findingStory(root, args[1:])
	default:
		return fmt.Errorf("unknown finding command %q; try decide or story",
			args[0])
	}
}

func findingDecide(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("decide", flag.ContinueOnError)
	because := fs.String("because", "", "why, which acceptance requires")
	until := fs.String("until", "",
		"when an acceptance expires, as 2026-12-31")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf(
			"usage: quilzo finding decide ID STATE [--because ... --until ...]\n" +
				"  states: open, triaged, accepted, fixed, stale")
	}

	caller := resolveCaller(root, flagToken)
	d := finding.Decision{
		Finding: pos[0], At: time.Now().UTC(),
		By: caller.Name, Kind: caller.Kind, To: finding.State(pos[1]),
		Because: strings.TrimSpace(*because),
	}
	if strings.TrimSpace(*until) != "" {
		parsed, err := time.Parse("2006-01-02", strings.TrimSpace(*until))
		if err != nil {
			return fmt.Errorf(
				"--until is a date like 2026-12-31: %w", err)
		}
		d.Until = parsed.UTC()
	}
	if err := d.Validate(); err != nil {
		return err
	}
	// Authorised as a publish. Deciding a risk is acceptable is a statement
	// the organisation stands behind, which is the same weight as putting
	// something in front of the public — and a far heavier one than editing
	// a draft.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	// Recorded before anything is printed. record() refuses a detail key
	// that looks like a credential and refuses the whole entry rather than
	// the key, so a decision reported as made and not written down is a
	// failure mode this has to rule out by ordering.
	record(root, d.Record())

	if w.JSON(map[string]any{
		"finding": d.Finding, "to": string(d.To), "by": d.By,
	}) {
		return nil
	}
	w.Human("%s%s%s is %s%s%s\n", bold, d.Finding, reset, green, d.To, reset)
	w.Human("  %srecorded as %s by %s%s\n",
		dim, d.Record().Action, d.By, reset)
	if d.To == finding.Accepted {
		w.Human("  %sexpires %s, and will read as lapsed after that rather "+
			"than as handled%s\n", dim, d.Until.Format("2006-01-02"), reset)
	}
	return nil
}

// findingStory replays what the log says about a finding.
func findingStory(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return err
	}
	decisions := decisionsFrom(events)

	if len(pos) == 0 {
		// Everything anybody has decided about, newest first.
		seen := map[string]bool{}
		var ids []string
		for i := len(decisions) - 1; i >= 0; i-- {
			if seen[decisions[i].Finding] {
				continue
			}
			seen[decisions[i].Finding] = true
			ids = append(ids, decisions[i].Finding)
		}
		if w.JSON(ids) {
			return nil
		}
		if len(ids) == 0 {
			w.Human("nothing has been decided\n")
			return nil
		}
		for _, id := range ids {
			w.Human("%s%s%s  %s\n", bold, id, reset,
				finding.Story(id, decisions))
		}
		return nil
	}

	id := pos[0]
	story := finding.Story(id, decisions)
	if w.JSON(map[string]any{
		"finding": id, "decisions": finding.History(id, decisions),
	}) {
		return nil
	}
	w.Human("%s%s%s\n  %s\n", bold, id, reset, story)
	return nil
}

// decisionsFrom rebuilds decisions out of audit entries.
//
// Read back rather than kept alongside. Two copies of one fact is two things
// that can disagree, and the copy in the chain is the one that can be proved.
func decisionsFrom(events []audit.Event) []finding.Decision {
	var out []finding.Decision
	for _, e := range events {
		to, found := strings.CutPrefix(e.Action, "finding.")
		if !found || e.Detail["finding"] == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.At)
		if err != nil {
			continue
		}
		d := finding.Decision{
			Finding: e.Detail["finding"], At: at, By: e.Principal,
			Kind: e.Kind, To: finding.State(to),
			Because: e.Detail["because"],
		}
		if u := e.Detail["until"]; u != "" {
			if parsed, perr := time.Parse(time.RFC3339, u); perr == nil {
				d.Until = parsed
			}
		}
		out = append(out, d)
	}
	return out
}
