// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/review"
	"github.com/quilzo/quilzo/internal/workforce"
)

// Access reviews, closed by the import rather than by the reviewer.
//
// A campaign declares which systems it covers and two dates: when the
// decisions are due and when the changes have to have happened. The second
// is the half of this control that fails and the half no product measures.
//
// `access close` takes a later import and works out which revocations
// actually happened. An account somebody decided to remove three weeks ago
// that is still in the export is the finding; every product reports that
// campaign as complete.

func reviewDir(root string) string {
	return filepath.Join(assuranceDir(root), "reviews")
}

func campaignPath(root, id string) string {
	return filepath.Join(reviewDir(root), id+".json")
}

func decisionsPath(root, id string) string {
	return filepath.Join(reviewDir(root), id+".decisions.jsonl")
}

func cmdAccess(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return accessList(root)
	case "open":
		return accessOpen(root, args[1:])
	case "items":
		return accessItems(root, args[1:])
	case "decide":
		return accessDecide(root, args[1:])
	case "close":
		return accessClose(root, args[1:])
	default:
		return fmt.Errorf("unknown access command %q; try list, open, "+
			"items, decide or close", args[0])
	}
}

type storedCampaign struct {
	Campaign review.Campaign `json:"campaign"`
	Items    []review.Item   `json:"items"`
}

func loadCampaign(root, id string) (storedCampaign, error) {
	var out storedCampaign
	b, err := readFileMaybe(campaignPath(root, id))
	if err != nil {
		return out, err
	}
	if b == nil {
		return out, fmt.Errorf("there is no campaign %q", id)
	}
	return out, json.Unmarshal(b, &out)
}

func loadDecisions(root, id string) ([]review.Decision, error) {
	var out []review.Decision
	err := loadJSONL(decisionsPath(root, id), func(b []byte) error {
		var d review.Decision
		if uerr := json.Unmarshal(b, &d); uerr != nil {
			return uerr
		}
		out = append(out, d)
		return nil
	})
	return out, err
}

func accessList(root string) error {
	names, err := jsonNamesIn(reviewDir(root), ".decisions.json")
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	type row struct {
		ID     string        `json:"id"`
		Name   string        `json:"name"`
		Report review.Report `json:"report"`
		Why    string        `json:"why"`
	}
	var rows []row
	for _, id := range names {
		stored, lerr := loadCampaign(root, id)
		if lerr != nil {
			return lerr
		}
		decisions, derr := loadDecisions(root, id)
		if derr != nil {
			return derr
		}
		out := review.Close(stored.Campaign, stored.Items, decisions, nil, at)
		r := review.Summarise(stored.Campaign, stored.Items, decisions, out,
			nil, at)
		rows = append(rows, row{ID: id, Name: stored.Campaign.Name,
			Report: r, Why: r.Why()})
	}
	if w.JSON(rows) {
		return nil
	}
	if len(rows) == 0 {
		w.Human("no campaigns in %s\n", reviewDir(root))
		return nil
	}
	for _, r := range rows {
		w.Human("%s%s%s  %s\n", bold, r.ID, reset, r.Name)
		w.Human("  %s%s%s\n", dim, r.Why, reset)
		w.Human("  %s%s%s\n", dim, r.Report.Shape.Why(), reset)
	}
	return nil
}

func accessOpen(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	name := fs.String("name", "", "what to call it")
	scope := fs.String("scope", "",
		"comma-separated issuers under review, as okta,github")
	entity := fs.String("entity", "", "which company, where a group exists")
	due := fs.String("due", "", "when the decisions are due, as 2026-10-10")
	remediate := fs.String("remediate", "",
		"when the changes have to have happened")
	opened := fs.String("opened", "",
		"when it started; today otherwise. For recording a campaign that "+
			"already ran somewhere else")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) < 1 {
		return fmt.Errorf(
			"usage: quilzo access open ID [IDENTITIES.jsonl] --scope " +
				"okta,github --due 2026-10-10 --remediate 2026-10-31")
	}
	caller := resolveCaller(root, flagToken)
	c := review.Campaign{
		ID: pos[0], Name: strings.TrimSpace(*name),
		Entity: strings.TrimSpace(*entity),
		Opened: time.Now().UTC(), By: caller.Name, Kind: caller.Kind,
	}
	if c.Name == "" {
		c.Name = pos[0]
	}
	for _, s := range strings.Split(*scope, ",") {
		if strings.TrimSpace(s) != "" {
			c.Scope = append(c.Scope, strings.TrimSpace(s))
		}
	}
	for _, d := range []struct {
		flag  string
		value *string
		into  *time.Time
	}{
		{"--opened", opened, &c.Opened},
		{"--due", due, &c.Due},
		{"--remediate", remediate, &c.Remediate},
	} {
		if strings.TrimSpace(*d.value) == "" {
			continue
		}
		parsed, perr := time.Parse("2006-01-02", strings.TrimSpace(*d.value))
		if perr != nil {
			return fmt.Errorf("%s is a date like 2026-10-10: %w", d.flag,
				perr)
		}
		*d.into = parsed.UTC()
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}

	var identities []workforce.Identity
	if len(pos) == 2 {
		r, lerr := loadRoster(root, pos[1])
		if lerr != nil {
			return lerr
		}
		for _, p := range r.People() {
			for _, id := range p.Identities {
				identities = append(identities, id)
			}
		}
		identities = append(identities, r.Services()...)
	}
	stored := storedCampaign{Campaign: c,
		Items: review.From(c, identities, time.Now().UTC())}
	if err := writeJSON(campaignPath(root, c.ID), stored); err != nil {
		return err
	}
	record(root, c.Record())

	if w.JSON(stored) {
		return nil
	}
	w.Human("%s%s%s opened over %s\n", bold, c.ID, reset,
		strings.Join(c.Scope, ", "))
	w.Human("  %s%d item(s); decisions due %s, changes by %s%s\n",
		dim, len(stored.Items), c.Due.Format("2006-01-02"),
		c.Remediate.Format("2006-01-02"), reset)
	if len(stored.Items) == 0 {
		w.Human("  %snothing to review: pass an identities file, as "+
			"quilzo connect run ... | quilzo access open ID -%s\n",
			yellow, reset)
	}
	return nil
}

func accessItems(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo access items ID")
	}
	stored, err := loadCampaign(root, pos[0])
	if err != nil {
		return err
	}
	decisions, err := loadDecisions(root, pos[0])
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	out := review.Close(stored.Campaign, stored.Items, decisions, nil, at)
	if w.JSON(out) {
		return nil
	}
	for _, o := range out {
		mark := dim
		state := string(o.Standing)
		if o.Standing == review.Undecided {
			mark = yellow
		}
		flags := ""
		if o.Item.Privileged {
			flags += "  privileged"
		}
		if o.Item.Dormant(at, 90*24*time.Hour) {
			flags += "  dormant"
		}
		w.Human("%s%s%s  %s%s%s%s%s%s\n", bold, o.Item.Account.String(),
			reset, mark, state, reset, yellow, flags, reset)
		if o.Item.Person != "" || o.Item.Role != "" {
			w.Human("  %s%s %s%s\n", dim, o.Item.Person, o.Item.Role, reset)
		}
	}
	return nil
}

func accessDecide(root string, args []string) error {
	pos, flags := leadingArgs(args, 3)
	fs := flag.NewFlagSet("decide", flag.ContinueOnError)
	because := fs.String("because", "",
		"why, which keeping privileged access requires")
	took := fs.Duration("took", 0,
		"how long this decision took; recorded so the shape of the "+
			"campaign is visible afterwards")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 3 {
		return fmt.Errorf(
			"usage: quilzo access decide CAMPAIGN ISSUER:VALUE VERDICT " +
				"[--because ...]\n  verdicts: keep, revoke, reduce")
	}
	account, err := contactID(pos[1])
	if err != nil {
		return err
	}
	stored, err := loadCampaign(root, pos[0])
	if err != nil {
		return err
	}
	var privileged, known bool
	for _, item := range stored.Items {
		if item.Account == account {
			known, privileged = true, item.Privileged
		}
	}
	if !known {
		return fmt.Errorf(
			"%s is not in %s. A decision about something the campaign never "+
				"showed anybody is one nothing will ever verify",
			account.String(), pos[0])
	}
	caller := resolveCaller(root, flagToken)
	d := review.Decision{
		Campaign: pos[0], Account: account,
		Verdict: review.Verdict(pos[2]), At: time.Now().UTC(),
		By: caller.Name, Kind: caller.Kind,
		Because: strings.TrimSpace(*because), Took: *took,
	}
	if err := d.Validate(privileged); err != nil {
		return err
	}
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := appendJSONL(decisionsPath(root, pos[0]), d); err != nil {
		return err
	}
	record(root, d.Record())

	if w.JSON(d) {
		return nil
	}
	w.Human("%s%s%s %s%s%s\n", bold, account.String(), reset,
		verdictColour(d.Verdict), d.Verdict, reset)
	if d.Verdict.Changes() {
		w.Human("  %sthis is not done until the account is gone from a "+
			"later import; quilzo access close %s does that%s\n",
			dim, pos[0], reset)
	}
	return nil
}

func verdictColour(v review.Verdict) string {
	if v.Changes() {
		return yellow
	}
	return green
}

func accessClose(root string, args []string) error {
	pos, _ := leadingArgs(args, 2)
	if len(pos) < 1 {
		return fmt.Errorf(
			"usage: quilzo access close CAMPAIGN [IDENTITIES.jsonl]\n" +
				"  the identities are a later import; without one, a " +
				"revocation can only be reported as unverified")
	}
	stored, err := loadCampaign(root, pos[0])
	if err != nil {
		return err
	}
	decisions, err := loadDecisions(root, pos[0])
	if err != nil {
		return err
	}
	var after []workforce.Identity
	if len(pos) == 2 {
		r, lerr := loadRoster(root, pos[1])
		if lerr != nil {
			return lerr
		}
		for _, p := range r.People() {
			for _, id := range p.Identities {
				after = append(after, id)
			}
		}
		after = append(after, r.Services()...)
	}

	at := time.Now().UTC()
	out := review.Close(stored.Campaign, stored.Items, decisions, after, at)
	r := review.Summarise(stored.Campaign, stored.Items, decisions, out,
		after, at)
	found := review.Findings(stored.Campaign, r, out, at)

	if w.JSON(map[string]any{
		"report": r, "outcomes": out, "findings": found,
	}) {
		return nil
	}
	colour := green
	if r.Unremediated > 0 || len(r.Missing) > 0 {
		colour = red
	} else if r.Undecided > 0 || !r.Verified {
		colour = yellow
	}
	w.Human("%s%s%s\n", bold, stored.Campaign.Name, reset)
	w.Human("%s%s%s\n", colour, r.Why(), reset)
	// The shape, always. It is the only part that distinguishes a review
	// from a formality, and it is what an auditor samples for.
	shapeColour := dim
	if r.Shape.RubberStamped() {
		shapeColour = red
	}
	w.Human("  %s%s%s\n", shapeColour, r.Shape.Why(), reset)
	if r.Dormant > 0 {
		w.Human("  %s%d of %d account(s) had not been used in ninety "+
			"days%s\n", dim, r.Dormant, r.Items, reset)
	}
	w.Human("\n")
	for _, o := range out {
		if o.Standing != review.Unremediated {
			continue
		}
		w.Human("%s%s%s  %sstill there%s\n", bold,
			o.Item.Account.String(), reset, red, reset)
		w.Human("  %sdecided %s on %s, due gone by %s%s\n", dim,
			o.Decision.Verdict, o.Decision.At.Format("2006-01-02"),
			stored.Campaign.Remediate.Format("2006-01-02"), reset)
	}
	return nil
}

// readFileMaybe reads a file, returning nil rather than an error when it is
// not there.
func readFileMaybe(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return b, err
}

// writeJSON writes an indented object, creating the directory.
func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// jsonNamesIn lists the .json files in a directory, without a suffix.
func jsonNamesIn(dir, exclude string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, exclude) {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ".json"))
	}
	sort.Strings(out)
	return out, nil
}
