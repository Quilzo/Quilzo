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
	"github.com/quilzo/quilzo/internal/vuln"
)

// A vulnerability queue that is not sorted by severity.
//
// `vuln queue` reads an inventory and a set of advisories, applies whatever
// anybody has assessed, and prints what to work on. The order is attested
// exploitation first, then probability, then reachability, then age — and
// CVSS last, as a tiebreak.
//
// The headline is the expected number of exploitations in the next thirty
// days and how much of it sits in the rows above the fold. That is the sum of
// the probabilities, which is what an expected value is, and it is the
// sentence somebody with a Tuesday afternoon needs: the top twelve carry nine
// tenths of it, and the other three hundred can wait.
//
// Assessments go in the audit chain, not in a status column. A vulnerability
// marked not_affected is a judgement with somebody's name on it, and the
// question an auditor asks is entirely about the past.

func vulnDir(root string) string { return filepath.Join(root, "vuln") }

func assessmentsPath(root string) string {
	return filepath.Join(vulnDir(root), "assessments.jsonl")
}

func cmdVuln(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"queue"}
	}
	switch args[0] {
	case "queue":
		return vulnQueue(root, args[1:])
	case "assess":
		return vulnAssess(root, args[1:])
	case "why":
		return vulnWhy(root, args[1:])
	case "reasons":
		return vulnReasons()
	default:
		return fmt.Errorf("unknown vuln command %q; try queue, assess, "+
			"why or reasons", args[0])
	}
}

// vulnReasons prints the closed list of VEX justifications.
func vulnReasons() error {
	rows := map[vuln.Justification]string{
		vuln.ComponentNotPresent: "the component is not in the product at all",
		vuln.VulnerableCodeNotPresent: "the component is there and the " +
			"vulnerable part of it is not",
		vuln.VulnerableCodeNotInExecutePath: "the vulnerable code is " +
			"present and never reached, given this product's architecture " +
			"and configuration",
		vuln.VulnerableCodeCannotBeControlledByAdversary: "it is reachable " +
			"and no attacker can influence the inputs that would trigger it",
		vuln.InlineMitigationsAlreadyExist: "something already in place " +
			"stops it",
	}
	if w.JSON(rows) {
		return nil
	}
	w.Human("%sthe five reasons a vulnerability may be marked not "+
		"affected%s\n", bold, reset)
	for _, j := range vuln.Justifications() {
		w.Human("\n  %s%s%s\n    %s%s%s\n", bold, j, reset, dim, rows[j],
			reset)
	}
	w.Human("\n  %sthe list is closed, and \"we looked and it is fine\" is "+
		"not on it. OpenVEX's, so an assessment written here is readable by "+
		"whatever the next tool is%s\n", dim, reset)
	return nil
}

// loadJSONL reads a file of one object per line.
func loadJSONL(path string, each func([]byte) error) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), MaxTelemetryLine)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if err := each([]byte(text)); err != nil {
			return fmt.Errorf("%s line %d: %w", path, line, err)
		}
	}
	return sc.Err()
}

func loadAdvisories(path string) ([]vuln.Advisory, error) {
	var out []vuln.Advisory
	err := loadJSONL(path, func(b []byte) error {
		var a vuln.Advisory
		if err := json.Unmarshal(b, &a); err != nil {
			return err
		}
		if err := a.Validate(); err != nil {
			return err
		}
		out = append(out, a)
		return nil
	})
	return out, err
}

func loadInventory(path string) ([]vuln.Component, error) {
	var out []vuln.Component
	err := loadJSONL(path, func(b []byte) error {
		var c vuln.Component
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		if err := c.Validate(); err != nil {
			return err
		}
		out = append(out, c)
		return nil
	})
	return out, err
}

func loadAssessments(root string) ([]vuln.Assessment, error) {
	var out []vuln.Assessment
	err := loadJSONL(assessmentsPath(root), func(b []byte) error {
		var a vuln.Assessment
		if err := json.Unmarshal(b, &a); err != nil {
			return err
		}
		out = append(out, a)
		return nil
	})
	return out, err
}

func vulnQueue(root string, args []string) error {
	fs := flag.NewFlagSet("queue", flag.ContinueOnError)
	advPath := fs.String("advisories", "advisories.jsonl",
		"one advisory per line")
	top := fs.Int("top", 15, "how many to show")
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	invPath := "inventory.jsonl"
	if len(rest) > 0 {
		invPath = rest[0]
	}

	advisories, err := loadAdvisories(*advPath)
	if err != nil {
		return err
	}
	if len(advisories) == 0 {
		return fmt.Errorf("no advisories in %s", *advPath)
	}
	inventory, err := loadInventory(invPath)
	if err != nil {
		return err
	}
	if len(inventory) == 0 {
		return fmt.Errorf(
			"no components in %s. A vulnerability queue over an empty "+
				"inventory is an empty queue, and the two look identical",
			invPath)
	}
	assessments, err := loadAssessments(root)
	if err != nil {
		return err
	}

	at := time.Now().UTC()
	ranked := vuln.Match(advisories, inventory, assessments, at)
	var live []vuln.Exposure
	for _, e := range ranked {
		if !e.Silenced {
			live = append(live, e)
		}
	}
	// Grouped by advisory, because the work is per-advisory and the
	// exposure is per-host. Upgrading one package on forty laptops is one
	// job, and a queue that spends forty rows on it pushes the next
	// vulnerability off the page.
	groups := vuln.Groups(live)
	shown := *top
	if shown > len(groups) {
		shown = len(groups)
	}
	all := vuln.Expected(live, at)
	var share float64
	if all > 0 {
		share = vuln.Expected(vuln.Flatten(groups[:shown]), at) / all
	}

	if w.JSON(map[string]any{
		"advisories": len(advisories), "components": len(inventory),
		"vulnerabilities": len(groups), "exposures": len(live),
		"silenced": len(ranked) - len(live),
		"expected": all, "share": share, "queue": groups[:shown],
	}) {
		return nil
	}

	w.Human("%s%d vulnerability(ies) across %d component(s), %d "+
		"exposure(s)%s\n", bold, len(groups), len(inventory), len(live),
		reset)
	if n := len(ranked) - len(live); n > 0 {
		w.Human("  %s%d exposure(s) assessed away, each with a reason and a "+
			"name%s\n", dim, n, reset)
	}
	// The sentence somebody with a Tuesday afternoon needs.
	if all > 0 {
		w.Human("  %s%.1f of these are expected to be exploited in the next "+
			"thirty days; the top %d carry %.0f%% of that%s\n",
			bold, all, shown, share*100, reset)
	}
	w.Human("\n")

	for i, g := range groups[:shown] {
		colour := dim
		if yes, _ := g.Advisory.Attested(); yes {
			colour = red
		}
		e := g.Worst()
		w.Human("%s%2d.%s %s%s%s  %s%s %s%s on %d asset(s)\n", dim, i+1,
			reset, colour, g.Advisory.ID, reset, bold, e.Component.Name,
			e.Component.Version, reset, g.Assets())
		w.Human("     %s%s%s\n", dim, e.Explain(at), reset)
		w.Human("     %s%s%s\n", dim, g.Where(3), reset)
	}
	if len(groups) > shown {
		rest := vuln.Expected(vuln.Flatten(groups[shown:]), at)
		w.Human("\n  %s%d more vulnerability(ies), carrying %.1f expected "+
			"exploitations between them%s\n", dim, len(groups)-shown, rest,
			reset)
	}
	return nil
}

func vulnWhy(root string, args []string) error {
	fs := flag.NewFlagSet("why", flag.ContinueOnError)
	advPath := fs.String("advisories", "advisories.jsonl", "")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo vuln why CVE-ID")
	}
	advisories, err := loadAdvisories(*advPath)
	if err != nil {
		return err
	}
	assessments, err := loadAssessments(root)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	for _, a := range advisories {
		if !strings.EqualFold(a.ID, pos[0]) {
			continue
		}
		var mine []vuln.Assessment
		for _, as := range assessments {
			if strings.EqualFold(as.Advisory, a.ID) {
				mine = append(mine, as)
			}
		}
		if w.JSON(map[string]any{
			"advisory": a, "assessments": mine, "fresh": a.Fresh(at),
		}) {
			return nil
		}
		w.Human("%s%s%s  %s\n", bold, a.ID, reset, a.Summary)
		yes, who := a.Attested()
		if yes {
			w.Human("  %sexploited, per %s%s\n", red,
				strings.Join(who, " and "), reset)
		} else {
			w.Human("  %snobody has attested to exploitation, which is not "+
				"the same as nobody exploiting it%s\n", dim, reset)
		}
		w.Human("  %sEPSS %.4f (%.2f%% in thirty days)", dim, a.EPSS,
			a.EPSS*100)
		if !a.Fresh(at) {
			w.Human(", measured %s and stale",
				a.EPSSAt.Format("2006-01-02"))
		}
		w.Human("%s\n", reset)
		w.Human("  %sCVSS %.1f — a severity, and the tiebreak here%s\n",
			dim, a.CVSS, reset)
		w.Human("  %sknown to us since %s%s\n", dim,
			a.Known.Format("2006-01-02"), reset)
		for _, as := range mine {
			w.Human("\n  %s%s by %s%s: %s\n", bold, as.Status, as.By, reset,
				as.Because)
			if as.Justification != "" {
				w.Human("    %s%s%s\n", dim, as.Justification, reset)
			}
			if as.Lapsed(at) {
				w.Human("    %slapsed on %s and is back in the queue%s\n",
					yellow, as.Until.Format("2006-01-02"), reset)
			}
		}
		return nil
	}
	return fmt.Errorf("no advisory %s in %s", pos[0], *advPath)
}

func vulnAssess(root string, args []string) error {
	pos, flags := leadingArgs(args, 3)
	fs := flag.NewFlagSet("assess", flag.ContinueOnError)
	because := fs.String("because", "", "the evidence, in one line")
	reason := fs.String("reason", "",
		"for not_affected: one of the five; quilzo vuln reasons lists them")
	where := fs.String("where", "",
		"one asset, issuer:value; empty means every installation")
	until := fs.String("until", "",
		"for under_investigation: when it lapses, as 2026-10-10")
	impact := fs.String("impact", "", "detail alongside the reason")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 3 {
		return fmt.Errorf(
			"usage: quilzo vuln assess CVE-ID ECOSYSTEM:PACKAGE STATUS " +
				"--because \"...\"\n" +
				"  statuses: affected, not_affected, fixed, " +
				"under_investigation")
	}
	caller := resolveCaller(root, flagToken)
	a := vuln.Assessment{
		Advisory: pos[0], Component: strings.ToLower(pos[1]),
		Status: vuln.Status(pos[2]), Where: strings.TrimSpace(*where),
		At: time.Now().UTC(), By: caller.Name, Kind: caller.Kind,
		Because: strings.TrimSpace(*because),
		Impact:  strings.TrimSpace(*impact),
	}
	if strings.TrimSpace(*reason) != "" {
		a.Justification = vuln.Justification(strings.TrimSpace(*reason))
	}
	if strings.TrimSpace(*until) != "" {
		parsed, perr := time.Parse("2006-01-02", strings.TrimSpace(*until))
		if perr != nil {
			return fmt.Errorf("--until is a date like 2026-10-10: %w", perr)
		}
		a.Until = parsed.UTC()
	}
	if err := a.Validate(); err != nil {
		return err
	}
	// Deciding a vulnerability does not apply is a statement the
	// organisation stands behind: the same authority as publishing.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := os.MkdirAll(vulnDir(root), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(a)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(assessmentsPath(root),
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
	record(root, a.Record())

	if w.JSON(a) {
		return nil
	}
	w.Human("%s%s%s in %s is %s%s%s\n", bold, a.Advisory, reset, a.Component,
		green, a.Status, reset)
	if a.Justification != "" {
		w.Human("  %s%s%s\n", dim, a.Justification, reset)
	}
	if a.Status == vuln.UnderInvestigation {
		w.Human("  %slapses %s, and comes back into the queue rather than "+
			"quietly staying out of it%s\n", yellow,
			a.Until.Format("2006-01-02"), reset)
	}
	w.Human("  %srecorded as %s in the audit chain%s\n",
		dim, a.Record().Action, reset)
	return nil
}
