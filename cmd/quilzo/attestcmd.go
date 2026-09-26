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
	"github.com/quilzo/quilzo/internal/attest"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/crosswalk"
	"github.com/quilzo/quilzo/internal/finding"
)

// Answering security questionnaires, and refusing to answer them wrongly.
//
// Every product in this category advertises 95% accuracy. The current CAIQ
// has over 260 questions, so that is thirteen wrong answers per
// questionnaire, sent under the company's name into a customer's vendor file
// where they are relied upon.
//
// The reason the figure does not help is that accuracy is measured against
// the text of previous answers. A confident answer about a control that
// stopped working in March matches what was said last time, and last time is
// exactly what is now false.
//
// `attest fill` checks each answer against this organisation's own register
// instead. A claim points at what backs it; an open finding against that
// backing is this organisation's records saying otherwise, and it stops the
// file rather than lowering a score.

func claimsPath(root string) string {
	return filepath.Join(assuranceDir(root), "claims.jsonl")
}

func cmdAttest(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"claims"}
	}
	switch args[0] {
	case "claims":
		return attestClaims(root)
	case "claim":
		return attestClaim(root, args[1:])
	case "fill":
		return attestFill(root, args[1:])
	default:
		return fmt.Errorf("unknown attest command %q; try claims, claim or "+
			"fill", args[0])
	}
}

func loadLibrary(root string) (*attest.Library, error) {
	l := attest.NewLibrary()
	err := loadJSONL(claimsPath(root), func(b []byte) error {
		var c attest.Claim
		if uerr := json.Unmarshal(b, &c); uerr != nil {
			return uerr
		}
		return l.Add(c)
	})
	return l, err
}

func attestClaims(root string) error {
	l, err := loadLibrary(root)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	all := l.All()
	if w.JSON(all) {
		return nil
	}
	if len(all) == 0 {
		w.Human("no claims in %s\n", claimsPath(root))
		w.Human("  %sa claim is what this organisation says about itself, "+
			"keyed on the assertion rather than on how somebody worded the "+
			"question%s\n", dim, reset)
		return nil
	}
	for _, c := range all {
		colour := green
		state := ""
		if c.Stale(at) {
			colour, state = yellow, "  due for review "+
				c.Until.Format("2006-01-02")
		}
		w.Human("%s%s%s  %s%s%s%s%s%s\n", bold, c.ID, reset,
			answerColour(c.Answer), c.Answer, reset, colour, state, reset)
		w.Human("  %s%s%s\n", dim, c.Says, reset)
		if len(c.Backing) > 0 {
			w.Human("  %sbacked by %s%s\n", dim,
				strings.Join(c.Backing, ", "), reset)
		}
	}
	return nil
}

func answerColour(a attest.Answer) string {
	switch a {
	case attest.Yes:
		return green
	case attest.Partly:
		return yellow
	default:
		return dim
	}
}

func attestClaim(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("claim", flag.ContinueOnError)
	says := fs.String("says", "", "the assertion, in one line")
	detail := fs.String("detail", "", "what a reader needs beyond the answer")
	backing := fs.String("backing", "",
		"comma-separated, as control:mfa or requirement:ISO27001:A.8.5")
	until := fs.String("until", "",
		"when this has to be looked at again, as 2027-06-30")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf(
			"usage: quilzo attest claim ID ANSWER --says \"...\" " +
				"--backing control:mfa --until 2027-06-30\n" +
				"  answers: yes, no, partly, not-applicable")
	}
	caller := resolveCaller(root, flagToken)
	c := attest.Claim{
		ID: pos[0], Answer: attest.Answer(pos[1]),
		Says: strings.TrimSpace(*says), Detail: strings.TrimSpace(*detail),
		At: time.Now().UTC(), By: caller.Name, Kind: caller.Kind,
	}
	for _, b := range strings.Split(*backing, ",") {
		if strings.TrimSpace(b) != "" {
			c.Backing = append(c.Backing, strings.TrimSpace(b))
		}
	}
	if strings.TrimSpace(*until) != "" {
		parsed, perr := time.Parse("2006-01-02", strings.TrimSpace(*until))
		if perr != nil {
			return fmt.Errorf("--until is a date like 2027-06-30: %w", perr)
		}
		c.Until = parsed.UTC()
	}
	if err := c.Validate(); err != nil {
		return err
	}
	// An answer on a security questionnaire is a representation made under
	// contract: the same authority as publishing.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := appendJSONL(claimsPath(root), c); err != nil {
		return err
	}
	record(root, c.Record())

	if w.JSON(c) {
		return nil
	}
	w.Human("%s%s%s %s%s%s\n", bold, c.ID, reset, answerColour(c.Answer),
		c.Answer, reset)
	w.Human("  %s%s%s\n", dim, c.Says, reset)
	w.Human("  %sstands until %s%s\n", dim, c.Until.Format("2006-01-02"),
		reset)
	return nil
}

func attestFill(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("fill", flag.ContinueOnError)
	out := fs.String("o", "", "where to write it")
	from := fs.String("from", "", "start of the period the register covers")
	to := fs.String("to", "", "end of it")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo attest fill QUESTIONNAIRE.json [-o FILE]")
	}
	body, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	var q attest.Questionnaire
	if err := json.Unmarshal(body, &q); err != nil {
		return fmt.Errorf("%s is not a questionnaire: %w", pos[0], err)
	}
	l, err := loadLibrary(root)
	if err != nil {
		return err
	}
	register, err := currentRegister(root, *from, *to)
	if err != nil {
		return err
	}

	at := time.Now().UTC()
	f, err := attest.Fill(q, l, register, at)
	if err != nil {
		return err
	}

	if *out != "" {
		rendered, merr := json.MarshalIndent(f, "", "  ")
		if merr != nil {
			return merr
		}
		if !f.Sendable() {
			// Written anyway, and the file says so. Refusing to write it
			// would mean the person fixing the contradictions cannot see
			// them next to the answers.
			w.Human("%s%s%s\n", yellow, f.Why(), reset)
		}
		if werr := os.WriteFile(*out, rendered, 0o600); werr != nil {
			return werr
		}
	}
	if w.JSON(f) {
		return nil
	}

	colour := green
	if !f.Sendable() {
		colour = red
	}
	w.Human("%s%s%s from %s\n", bold, q.Name, reset, q.From)
	w.Human("%s%s%s\n", colour, f.Why(), reset)
	answerable, total := attest.Coverage(q, l)
	w.Human("  %s%d of %d question(s) have a claim behind them%s\n\n",
		dim, answerable, total, reset)

	for _, c := range f.Concerns {
		mark := yellow
		if c.Trouble.Blocking() {
			mark = red
		}
		w.Human("%s%-10s%s %s%s%s\n", mark, c.Trouble, reset,
			bold, c.Question, reset)
		w.Human("  %s%s%s\n", dim, c.What, reset)
	}
	if len(f.Concerns) == 0 {
		w.Human("  %snothing to review%s\n", dim, reset)
	}
	if *out != "" {
		w.Human("\n  %swritten to %s%s\n", dim, *out, reset)
	}
	return nil
}

// currentRegister gathers what is wrong with this organisation right now.
//
// From the sources that produce findings about controls and requirements,
// because those are what a questionnaire answer relies on. It deliberately
// does not include detections or vulnerabilities: a CVE in a dependency does
// not contradict "we run a vulnerability management programme", and a check
// that treated it as one would block every questionnaire for ever.
func currentRegister(root, from, to string) ([]finding.Finding, error) {
	period, err := window(from, to)
	if err != nil {
		return nil, err
	}
	controls, err := loadControls(root)
	if err != nil {
		return nil, err
	}
	evidence, err := loadEvidence(root)
	if err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	out := assurance.Findings(controls, evidence, period, at)

	reqs, err := loadRequirements(root)
	if err != nil {
		return nil, err
	}
	if len(reqs) > 0 {
		maps, merr := loadMappings(root)
		if merr != nil {
			return nil, merr
		}
		_, covs := assurance.Assess(controls, evidence, period)
		seen := map[string]bool{}
		for _, r := range reqs {
			if seen[r.Framework] {
				continue
			}
			seen[r.Framework] = true
			report, standings := crosswalk.Assess(r.Framework, reqs, maps,
				covs, period)
			out = append(out, crosswalk.Findings(report, standings, at)...)
		}
	}
	return out, nil
}
