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

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/workforce"
)

// Reconciling people and devices across the systems that each hold a
// different, partial, confident answer.
//
// The input is a file of normalised identities, one per line, the same shape
// every other telemetry surface here takes. Connectors that read an identity
// provider, an MDM or a training platform produce that file; nothing in this
// command knows which system it came from beyond the issuer on each record,
// which is the point.
//
// Links are held in a file of their own rather than in the roster, because a
// link is a human assertion with a name on it and the roster is whatever the
// last export happened to say. Re-exporting the directory must not lose the
// merge somebody confirmed last month.

func workforceDir(root string) string { return filepath.Join(root, "workforce") }

func linksPath(root string) string {
	return filepath.Join(workforceDir(root), "links.jsonl")
}

func expectPath(root string) string {
	return filepath.Join(workforceDir(root), "expect.json")
}

func cmdWorkforce(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"coverage"}
	}
	switch args[0] {
	case "coverage":
		return workforceCoverage(root, args[1:])
	case "propose":
		return workforcePropose(root, args[1:])
	case "link":
		return workforceLink(root, args[1:])
	case "gaps":
		return workforceGaps(root, args[1:])
	case "people":
		return workforcePeople(root, args[1:])
	default:
		return fmt.Errorf("unknown workforce command %q; try coverage, "+
			"propose, link, gaps or people", args[0])
	}
}

// loadRoster reads identities from a file and applies the confirmed links.
func loadRoster(root, path string) (*workforce.Roster, error) {
	r := workforce.New()
	in := os.Stdin
	if path != "" && path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		in = f
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), MaxTelemetryLine)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		var i workforce.Identity
		if err := json.Unmarshal([]byte(text), &i); err != nil {
			return nil, fmt.Errorf("line %d is not an identity: %w", line, err)
		}
		if err := r.Observe(i); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}
	return r, applyLinks(root, r)
}

// applyLinks replays the confirmed merges over a freshly read roster.
//
// A link naming a record this export does not contain is skipped rather than
// refused: somebody who left is gone from the directory, and a merge that was
// right in March should not stop the September reconciliation from running.
func applyLinks(root string, r *workforce.Roster) error {
	b, err := os.ReadFile(linksPath(root))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for n, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var l workforce.Link
		if uerr := json.Unmarshal([]byte(line), &l); uerr != nil {
			return fmt.Errorf("links.jsonl line %d: %w", n+1, uerr)
		}
		if lerr := r.Link(l); lerr != nil &&
			!strings.Contains(lerr.Error(), "has not been observed") {
			return fmt.Errorf("links.jsonl line %d: %w", n+1, lerr)
		}
	}
	return nil
}

func loadExpect(root string) (workforce.Expect, error) {
	var e workforce.Expect
	b, err := os.ReadFile(expectPath(root))
	if os.IsNotExist(err) {
		return e, nil
	}
	if err != nil {
		return e, err
	}
	if uerr := json.Unmarshal(b, &e); uerr != nil {
		return e, fmt.Errorf("workforce/expect.json is unreadable: %w", uerr)
	}
	for _, req := range e.Require {
		if verr := req.Validate(); verr != nil {
			return e, verr
		}
	}
	return e, nil
}

func workforceCoverage(root string, args []string) error {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	r, err := loadRoster(root, first(rest))
	if err != nil {
		return err
	}
	c := r.Coverage()
	orphans := r.Orphans()
	skipped := r.Skipped()

	if w.JSON(map[string]any{
		"coverage": c, "orphans": orphans, "skipped": skipped,
		"proposals": len(r.Propose()),
	}) {
		return nil
	}
	colour := green
	if !c.Trustworthy() {
		colour = red
	}
	w.Human("%s%s%s\n", colour, c.Why(), reset)
	w.Human("  %s%d identity(ies) from %s%s\n",
		dim, r.Len(), strings.Join(c.Issuers, ", "), reset)
	if c.Services > 0 {
		w.Human("  %s%d service account(s), counted apart from people%s\n",
			dim, c.Services, reset)
	}
	if c.Devices > 0 {
		w.Human("  %s%d device(s), %d belonging to nobody%s\n",
			dim, c.Devices, c.Unowned, reset)
	}
	for _, i := range orphans.Alone {
		w.Human("  %s%s is only in %s%s\n",
			yellow, i.ID.String(), i.ID.Issuer, reset)
	}
	for email, why := range skipped {
		w.Human("  %s%s was not joined on: %s%s\n", yellow, email, why, reset)
	}
	if n := len(r.Propose()); n > 0 {
		w.Human("\n  %s%d match(es) to confirm: quilzo workforce propose%s\n",
			dim, n, reset)
	}
	return nil
}

func workforcePropose(root string, args []string) error {
	fs := flag.NewFlagSet("propose", flag.ContinueOnError)
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	r, err := loadRoster(root, first(rest))
	if err != nil {
		return err
	}
	props := r.Propose()
	if w.JSON(props) {
		return nil
	}
	if len(props) == 0 {
		w.Human("nothing to confirm\n")
		return nil
	}
	for _, p := range props {
		w.Human("%s%s%s = %s%s%s\n",
			bold, p.A.String(), reset, bold, p.B.String(), reset)
		w.Human("  %s%s%s\n", dim, p.Because, reset)
		// Every proposal states what would make it wrong, because a
		// suggestion without one is accepted in a batch of forty unread.
		w.Human("  %sit is wrong if: %s%s\n", yellow, p.Doubt, reset)
		w.Human("  %squilzo workforce link %s %s --because \"...\"%s\n",
			dim, p.A.String(), p.B.String(), reset)
	}
	return nil
}

func workforceLink(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("link", flag.ContinueOnError)
	because := fs.String("because", "", "the evidence, in one line")
	rule := fs.String("rule", "", "the automatic rule this came from, if any")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf(
			"usage: quilzo workforce link ISSUER:VALUE ISSUER:VALUE " +
				"--because \"...\"")
	}
	a, err := contactID(pos[0])
	if err != nil {
		return err
	}
	b, err := contactID(pos[1])
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	l := workforce.Link{
		A: a, B: b, At: time.Now().UTC(), By: caller.Name, Kind: caller.Kind,
		Rule:    strings.TrimSpace(*rule),
		Because: strings.TrimSpace(*because),
	}
	if err := l.Validate(); err != nil {
		return err
	}
	// Merging two people's records reports one person's device compliance as
	// another's. The same authority as publishing.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := os.MkdirAll(workforceDir(root), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(l)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(linksPath(root),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	record(root, l.Record())

	if w.JSON(l) {
		return nil
	}
	w.Human("%s%s%s and %s%s%s are one person\n",
		bold, a.String(), reset, bold, b.String(), reset)
	w.Human("  %srecorded in the audit chain; unpicking it means a second "+
		"entry, not an edit%s\n", dim, reset)
	return nil
}

func workforceGaps(root string, args []string) error {
	fs := flag.NewFlagSet("gaps", flag.ContinueOnError)
	top := fs.Int("top", 20, "how many to show")
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	r, err := loadRoster(root, first(rest))
	if err != nil {
		return err
	}
	expect, err := loadExpect(root)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	c := r.Coverage()
	found := r.Findings(expect, at)

	if w.JSON(map[string]any{
		"coverage": c, "trustworthy": c.Trustworthy(), "findings": found,
	}) {
		return nil
	}
	// The coverage line first, always. A list of gaps over a join that did
	// not work is a list about the people the join happened to reach.
	colour := dim
	if !c.Trustworthy() {
		colour = red
	}
	w.Human("%s%s%s\n\n", colour, c.Why(), reset)

	if len(found) == 0 {
		w.Human("nothing that needed two systems to see\n")
		return nil
	}
	shown := found
	if len(shown) > *top {
		shown = shown[:*top]
	}
	for _, f := range shown {
		w.Human("%s%s%s\n", bold, f.Title, reset)
		w.Human("  %s%s%s\n", dim, f.Evidence[0].What, reset)
	}
	if len(found) > len(shown) {
		w.Human("\n  %s%d more%s\n", dim, len(found)-len(shown), reset)
	}
	return nil
}

func workforcePeople(root string, args []string) error {
	fs := flag.NewFlagSet("people", flag.ContinueOnError)
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	r, err := loadRoster(root, first(rest))
	if err != nil {
		return err
	}
	people := r.People()
	if w.JSON(map[string]any{
		"people": people, "services": r.Services(),
	}) {
		return nil
	}
	for _, p := range people {
		gone, said := p.Gone()
		state, colour := "", green
		if gone {
			state, colour = "left, per "+strings.Join(said, " and "), yellow
		}
		w.Human("%s%s%s  %s%s%s  %s%s%s\n", bold, p.Name(), reset,
			dim, strings.Join(p.Issuers(), " "), reset, colour, state, reset)
		for _, d := range p.Devices {
			w.Human("    %s%s last seen %s%s\n", dim, d.ID.String(),
				seenAgo(d.Seen), reset)
		}
	}
	if svc := r.Services(); len(svc) > 0 {
		w.Human("\n%s%d service account(s)%s\n", bold, len(svc), reset)
		for _, s := range svc {
			w.Human("  %s%s%s\n", dim, s.ID.String(), reset)
		}
	}
	return nil
}

func seenAgo(at time.Time) string {
	if at.IsZero() {
		return "never"
	}
	return at.Format("2006-01-02")
}

func first(in []string) string {
	if len(in) == 0 {
		return ""
	}
	return in[0]
}
