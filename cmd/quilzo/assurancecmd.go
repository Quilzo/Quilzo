// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/auth"
)

// What the evidence shows over a period, and what it does not.
//
// Controls live in a file the operator keeps; evidence is appended, one
// record per line, and every piece of it also goes into the audit chain so
// that the artefact an auditor is shown and the record of it being gathered
// are the same thing.
//
// The output is not a percentage. `assurance report` leads with the controls
// that have no evidence at all for the window, because that is the number a
// compliance score leaves out of its denominator, and then lists the days
// nobody can speak to.

func assuranceDir(root string) string {
	return filepath.Join(root, "assurance")
}

func controlsPath(root string) string {
	return filepath.Join(assuranceDir(root), "controls.json")
}

func evidencePath(root string) string {
	return filepath.Join(assuranceDir(root), "evidence.jsonl")
}

func cmdAssurance(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"report"}
	}
	switch args[0] {
	case "report":
		return assuranceReport(root, args[1:])
	case "show":
		return assuranceShow(root, args[1:])
	case "record":
		return assuranceRecord(root, args[1:])
	case "controls":
		return assuranceControls(root)
	default:
		return fmt.Errorf("unknown assurance command %q; try report, show, "+
			"record or controls", args[0])
	}
}

func loadControls(root string) ([]assurance.Control, error) {
	var out []assurance.Control
	b, err := os.ReadFile(controlsPath(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if uerr := json.Unmarshal(b, &out); uerr != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", controlsPath(root),
			uerr)
	}
	for _, c := range out {
		if verr := c.Validate(); verr != nil {
			return nil, verr
		}
	}
	return out, nil
}

func loadEvidence(root string) ([]assurance.Evidence, error) {
	var out []assurance.Evidence
	err := loadJSONL(evidencePath(root), func(b []byte) error {
		var e assurance.Evidence
		if uerr := json.Unmarshal(b, &e); uerr != nil {
			return uerr
		}
		if verr := e.Validate(); verr != nil {
			return verr
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

// window parses the period a report covers.
//
// Six months by default, because a shorter window contains fewer than two
// cycles of a quarterly control and so gives an auditor nothing to sample
// and no way to test around a gap.
func window(from, to string) (assurance.Period, error) {
	// One reading of the clock, used for both ends.
	//
	// Two calls to time.Now put a few hundred nanoseconds between them, and
	// the period came out fractionally under 182 days — which integer
	// division then turned into one expected quarter instead of two, so a
	// control with a single occurrence read as proven. An off-by-one in a
	// compliance report, caused by asking what time it is twice.
	at := time.Now().UTC()
	p := assurance.Period{To: at, From: at.Add(-182 * 24 * time.Hour)}
	parse := func(s string, into *time.Time) error {
		if strings.TrimSpace(s) == "" {
			return nil
		}
		got, err := time.Parse("2006-01-02", strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("dates are like 2026-04-01: %w", err)
		}
		*into = got.UTC()
		return nil
	}
	if err := parse(from, &p.From); err != nil {
		return p, err
	}
	if err := parse(to, &p.To); err != nil {
		return p, err
	}
	if !p.Valid() {
		return p, fmt.Errorf("%s is not a period", p)
	}
	return p, nil
}

func assuranceControls(root string) error {
	controls, err := loadControls(root)
	if err != nil {
		return err
	}
	if w.JSON(controls) {
		return nil
	}
	if len(controls) == 0 {
		w.Human("no controls in %s\n", controlsPath(root))
		return nil
	}
	for _, c := range controls {
		who := c.Owner
		colour := dim
		if strings.TrimSpace(who) == "" {
			who, colour = "nobody accountable", yellow
		}
		how := "by hand"
		if c.Automated {
			how = "automated"
		}
		w.Human("%s%s%s  %s%s, %s%s  %s%s%s\n", bold, c.ID, reset,
			dim, c.Cadence, how, reset, colour, who, reset)
		w.Human("  %s%s%s\n", dim, c.Name, reset)
		if len(c.Maps) > 0 {
			w.Human("  %s%s%s\n", dim, strings.Join(c.Maps, ", "), reset)
		}
	}
	return nil
}

func assuranceReport(root string, args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	from := fs.String("from", "", "start of the period, as 2026-04-01")
	to := fs.String("to", "", "end of it; today by default")
	top := fs.Int("top", 20, "how many controls to list")
	if err := fs.Parse(args); err != nil {
		return err
	}
	period, err := window(*from, *to)
	if err != nil {
		return err
	}
	controls, err := loadControls(root)
	if err != nil {
		return err
	}
	if len(controls) == 0 {
		return fmt.Errorf("no controls in %s", controlsPath(root))
	}
	evidence, err := loadEvidence(root)
	if err != nil {
		return err
	}

	ready, covs := assurance.Assess(controls, evidence, period)
	if w.JSON(map[string]any{
		"period": period, "readiness": ready, "coverage": covs,
	}) {
		return nil
	}

	w.Human("%s%s%s\n", bold, period, reset)
	// The silent controls first, always.
	colour := green
	if ready.Silent > 0 {
		colour = red
	} else if ready.Partial > 0 {
		colour = yellow
	}
	w.Human("%s%s%s\n", colour, ready.Why(), reset)
	w.Human("  %s%d covered, %d with gaps, %d silent, %d unproven, %d "+
		"untested, %d unowned%s\n", dim, ready.Covered, ready.Partial,
		ready.Silent, ready.Unproven, ready.Untested, ready.Unowned, reset)
	// Deliberately no single figure. See internal/assurance on why a
	// compliance percentage is a statement about scope.
	w.Human("  %sthere is no percentage here: a compliance score is "+
		"controls-passing over controls-in-scope, and scope is chosen by "+
		"whoever wants the number%s\n\n", dim, reset)

	shown := *top
	if shown > len(covs) {
		shown = len(covs)
	}
	for _, cov := range covs[:shown] {
		mark := green
		switch {
		case cov.Observations == 0:
			mark = red
		case !cov.Complete() || !cov.Proven():
			mark = yellow
		}
		w.Human("%s%s%s  %s%.0f%% of the period%s\n",
			bold, cov.Control, reset, mark, cov.Share()*100, reset)
		w.Human("  %s%s%s\n", dim, cov.Why(), reset)
	}
	if len(covs) > shown {
		w.Human("\n  %s%d more%s\n", dim, len(covs)-shown, reset)
	}
	return nil
}

func assuranceShow(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	from := fs.String("from", "", "start of the period")
	to := fs.String("to", "", "end of it")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo assurance show CONTROL")
	}
	period, err := window(*from, *to)
	if err != nil {
		return err
	}
	controls, err := loadControls(root)
	if err != nil {
		return err
	}
	evidence, err := loadEvidence(root)
	if err != nil {
		return err
	}
	for _, c := range controls {
		if c.ID != pos[0] {
			continue
		}
		cov := assurance.Measure(c, evidence, period)
		var mine []assurance.Evidence
		for _, e := range evidence {
			if e.Control == c.ID {
				mine = append(mine, e)
			}
		}
		if w.JSON(map[string]any{
			"control": c, "coverage": cov, "evidence": mine,
		}) {
			return nil
		}
		w.Human("%s%s%s  %s\n", bold, c.ID, reset, c.Name)
		w.Human("  %s%s, %s%s\n", dim, c.Cadence, period, reset)
		w.Human("  %s%s%s\n\n", bold, cov.Why(), reset)
		for _, e := range mine {
			w.Human("  %s%s → %s%s  %s%s%s\n", dim,
				e.From.Format("2006-01-02"), e.To.Format("2006-01-02"),
				reset, outcomeColour(e.Outcome), e.Outcome, reset)
			w.Human("    %s%s — %s (%s)%s\n", dim, e.What, e.Source, e.Ref,
				reset)
		}
		if len(cov.Gaps) > 0 {
			w.Human("\n  %snothing to show for%s\n", yellow, reset)
			for _, g := range cov.Gaps {
				w.Human("    %s%s  (%d day(s))%s\n", yellow, g, g.Days(),
					reset)
			}
		}
		return nil
	}
	return fmt.Errorf("no control %q in %s", pos[0], controlsPath(root))
}

func outcomeColour(o assurance.Outcome) string {
	switch o {
	case assurance.Failed:
		return red
	case assurance.NotObserved:
		return yellow
	default:
		return green
	}
}

func assuranceRecord(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	from := fs.String("from", "", "first day this speaks to, as 2026-04-01")
	to := fs.String("to", "", "last day it speaks to")
	what := fs.String("what", "", "what it shows, in one line")
	source := fs.String("source", "", "what produced it")
	ref := fs.String("ref", "", "where the artefact is")
	entity := fs.String("entity", "",
		"the company this speaks for; the group otherwise")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf(
			"usage: quilzo assurance record CONTROL OUTCOME --from ... " +
				"--to ... --what ... --source ... --ref ...\n" +
				"  outcomes: operated, failed, not-observed")
	}
	period, err := window(*from, *to)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	e := assurance.Evidence{
		Control: pos[0], Outcome: assurance.Outcome(pos[1]),
		From: period.From, To: period.To,
		What: strings.TrimSpace(*what), Source: strings.TrimSpace(*source),
		Ref: strings.TrimSpace(*ref), Entity: strings.TrimSpace(*entity),
		At: time.Now().UTC(), By: caller.Name, Kind: caller.Kind,
	}
	if err := e.Validate(); err != nil {
		return err
	}
	controls, err := loadControls(root)
	if err != nil {
		return err
	}
	var known bool
	for _, c := range controls {
		if c.ID == e.Control {
			known = true
		}
	}
	if !known {
		// Refused rather than accepted quietly. Evidence for a control
		// nobody declared is evidence nothing will ever ask for, and it is
		// usually a typo in an identifier.
		return fmt.Errorf(
			"there is no control called %q in %s. Evidence for a control "+
				"nobody declared is evidence nothing will ever look at",
			e.Control, controlsPath(root))
	}
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	if err := os.MkdirAll(assuranceDir(root), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(evidencePath(root),
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
	// Also in the audit chain, so the artefact an auditor is shown and the
	// record of it being gathered are the same thing.
	record(root, e.Record())

	if w.JSON(e) {
		return nil
	}
	where := ""
	if e.Entity != "" {
		where = " at " + e.Entity
	}
	w.Human("%s%s%s%s %s%s%s for %s\n", bold, e.Control, where, reset,
		outcomeColour(e.Outcome), e.Outcome, reset, period)
	w.Human("  %s%s — %s%s\n", dim, e.What, e.Ref, reset)
	w.Human("  %srecorded as %s in the audit chain%s\n",
		dim, e.Record().Action, reset)
	return nil
}
