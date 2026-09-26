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

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/crosswalk"
)

// Where a framework's requirements stand, and what it would cost to adopt
// another one.
//
// The requirements are the operator's file: this ships no framework text,
// because ISO's standards and the AICPA's criteria are copyrighted and a
// bundled copy goes stale.
//
// The answer joins three things that every platform collapses into one
// number — what the framework asks, what anybody has claimed about it, and
// whether the claimed controls actually operated. A requirement is met only
// when a control is equal to it or broader than it *and* that control has
// evidence across the period.

func crosswalkDir(root string) string {
	return filepath.Join(root, "assurance")
}

func requirementsPath(root string) string {
	return filepath.Join(crosswalkDir(root), "requirements.jsonl")
}

func mappingsPath(root string) string {
	return filepath.Join(crosswalkDir(root), "mappings.jsonl")
}

func cmdFramework(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return frameworkList(root)
	case "status":
		return frameworkStatus(root, args[1:])
	case "adopt":
		return frameworkAdopt(root, args[1:])
	case "map":
		return frameworkMap(root, args[1:])
	case "relations":
		return frameworkRelations()
	default:
		return fmt.Errorf("unknown framework command %q; try list, status, "+
			"adopt, map or relations", args[0])
	}
}

func frameworkRelations() error {
	if w.JSON(crosswalk.Relations()) {
		return nil
	}
	w.Human("%sthe five relationships, from NIST IR 8477%s\n", bold, reset)
	for _, r := range crosswalk.Relations() {
		mark := dim
		if r.Satisfies() {
			mark = green
		} else if r.Partial() {
			mark = yellow
		}
		w.Human("\n  %s%s%s\n    %s%s%s\n", mark, r, reset, dim,
			r.Describe(), reset)
	}
	w.Human("\n  %sonly equal and superset-of satisfy a requirement. That "+
		"is the line between this and a row of framework tags read as "+
		"equality%s\n", dim, reset)
	return nil
}

func loadRequirements(root string) ([]crosswalk.Requirement, error) {
	var out []crosswalk.Requirement
	err := loadJSONL(requirementsPath(root), func(b []byte) error {
		var r crosswalk.Requirement
		if uerr := json.Unmarshal(b, &r); uerr != nil {
			return uerr
		}
		if verr := r.Validate(); verr != nil {
			return verr
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

func loadMappings(root string) ([]crosswalk.Mapping, error) {
	var out []crosswalk.Mapping
	err := loadJSONL(mappingsPath(root), func(b []byte) error {
		var m crosswalk.Mapping
		if uerr := json.Unmarshal(b, &m); uerr != nil {
			return uerr
		}
		if verr := m.Validate(); verr != nil {
			return verr
		}
		out = append(out, m)
		return nil
	})
	return out, err
}

// evidenceCoverage measures every control over the period, so a framework
// report can ask whether a mapped control actually operated.
func evidenceCoverage(root string, period assurance.Period) (
	[]assurance.Coverage, error) {

	controls, err := loadControls(root)
	if err != nil {
		return nil, err
	}
	evidence, err := loadEvidence(root)
	if err != nil {
		return nil, err
	}
	_, covs := assurance.Assess(controls, evidence, period)
	return covs, nil
}

func frameworkList(root string) error {
	reqs, err := loadRequirements(root)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, r := range reqs {
		counts[r.Framework]++
	}
	names := make([]string, 0, len(counts))
	for k := range counts {
		names = append(names, k)
	}
	sort.Strings(names)
	if w.JSON(counts) {
		return nil
	}
	if len(names) == 0 {
		w.Human("no frameworks in %s\n", requirementsPath(root))
		w.Human("  %sone requirement per line: framework, id, title. This "+
			"ships no framework text — ISO's standards and the AICPA's "+
			"criteria are copyrighted, and a bundled copy goes stale%s\n",
			dim, reset)
		return nil
	}
	for _, n := range names {
		w.Human("%s%s%s  %d requirement(s)\n", bold, n, reset, counts[n])
	}
	return nil
}

func frameworkStatus(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	from := fs.String("from", "", "start of the period, as 2026-04-01")
	to := fs.String("to", "", "end of it; today by default")
	top := fs.Int("top", 20, "how many requirements to list")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo framework status NAME")
	}
	report, standings, err := frameworkAssess(root, pos[0], *from, *to)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{
		"report": report, "requirements": standings,
	}) {
		return nil
	}

	w.Human("%s%s over %s%s\n", bold, report.Framework, report.Period, reset)
	colour := green
	if report.Unmapped > 0 || report.Unevidenced > 0 {
		colour = red
	} else if report.Partial > 0 {
		colour = yellow
	}
	w.Human("%s%s%s\n", colour, report.Why(), reset)
	w.Human("  %s%d met, %d unevidenced, %d partial, %d declined, %d "+
		"unmapped%s\n\n", dim, report.Met, report.Unevidenced,
		report.Partial, report.Declined, report.Unmapped, reset)

	shown := *top
	if shown > len(standings) {
		shown = len(standings)
	}
	for _, s := range standings[:shown] {
		w.Human("%s%s%s  %s%s%s\n", bold, s.Requirement.Key(), reset,
			stateColour(s.State), s.State, reset)
		w.Human("  %s%s%s\n", dim, s.Requirement.Title, reset)
		w.Human("  %s%s%s\n", dim, s.Why(), reset)
	}
	if len(standings) > shown {
		w.Human("\n  %s%d more%s\n", dim, len(standings)-shown, reset)
	}
	if report.Suspicious() {
		w.Human("\n  %s%.0f%% of the mappings claim exact equality%s\n",
			yellow, report.EqualShare*100, reset)
	}
	return nil
}

func stateColour(s crosswalk.State) string {
	switch s {
	case crosswalk.Met:
		return green
	case crosswalk.Unmapped, crosswalk.Unevidenced:
		return red
	case crosswalk.Partial:
		return yellow
	default:
		return dim
	}
}

func frameworkAdopt(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	from := fs.String("from", "", "start of the period")
	to := fs.String("to", "", "end of it")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo framework adopt NAME")
	}
	report, standings, err := frameworkAssess(root, pos[0], *from, *to)
	if err != nil {
		return err
	}
	advice := crosswalk.Adopting(report, standings)
	if w.JSON(map[string]any{"report": report, "advice": advice}) {
		return nil
	}
	w.Human("%s", advice)
	// The three kinds of work, named separately, because a single
	// percentage would make them look like one queue.
	w.Human("\n  %squilzo framework status %s lists them%s\n",
		dim, report.Framework, reset)
	return nil
}

func frameworkAssess(root, name, from, to string) (crosswalk.Report,
	[]crosswalk.Standing, error) {

	period, err := window(from, to)
	if err != nil {
		return crosswalk.Report{}, nil, err
	}
	reqs, err := loadRequirements(root)
	if err != nil {
		return crosswalk.Report{}, nil, err
	}
	var any bool
	for _, r := range reqs {
		if r.Framework == name {
			any = true
		}
	}
	if !any {
		return crosswalk.Report{}, nil, fmt.Errorf(
			"no requirements for %q in %s", name, requirementsPath(root))
	}
	maps, err := loadMappings(root)
	if err != nil {
		return crosswalk.Report{}, nil, err
	}
	covs, err := evidenceCoverage(root, period)
	if err != nil {
		return crosswalk.Report{}, nil, err
	}
	report, standings := crosswalk.Assess(name, reqs, maps, covs, period)
	return report, standings, nil
}

func frameworkMap(root string, args []string) error {
	pos, flags := leadingArgs(args, 3)
	fs := flag.NewFlagSet("map", flag.ContinueOnError)
	why := fs.String("why", "", "the rationale, which IR 8477 requires")
	remainder := fs.String("remainder", "",
		"for a partial relation: what the control does not cover")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 3 {
		return fmt.Errorf(
			"usage: quilzo framework map CONTROL FRAMEWORK:ID RELATION " +
				"--why \"...\"\n" +
				"  relations: equal, superset-of, subset-of, " +
				"intersects-with, no-relationship\n" +
				"  quilzo framework relations says what each one means")
	}
	caller := resolveCaller(root, flagToken)
	m := crosswalk.Mapping{
		Control: pos[0], Requirement: pos[1],
		Relation:  crosswalk.Relation(pos[2]),
		Rationale: strings.TrimSpace(*why),
		Remainder: strings.TrimSpace(*remainder),
		At:        time.Now().UTC(), By: caller.Name, Kind: caller.Kind,
	}
	if err := m.Validate(); err != nil {
		return err
	}
	// Asserting that a control answers a regulator's clause is a statement
	// the organisation stands behind: the same authority as publishing.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	controls, err := loadControls(root)
	if err != nil {
		return err
	}
	var known bool
	for _, c := range controls {
		if c.ID == m.Control {
			known = true
		}
	}
	if !known {
		return fmt.Errorf(
			"there is no control called %q. A mapping to a control nobody "+
				"declared can never be evidenced, so the requirement it "+
				"claims to satisfy would sit as met with nothing behind it",
			m.Control)
	}
	reqs, err := loadRequirements(root)
	if err != nil {
		return err
	}
	var found bool
	for _, r := range reqs {
		if r.Key() == m.Requirement {
			found = true
		}
	}
	if !found {
		return fmt.Errorf(
			"there is no requirement %q in %s. A mapping to a clause that "+
				"is not in the framework file is one nothing will ever "+
				"report on", m.Requirement, requirementsPath(root))
	}

	if err := os.MkdirAll(crosswalkDir(root), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(m)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(mappingsPath(root),
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
	record(root, m.Record())

	if w.JSON(m) {
		return nil
	}
	w.Human("%s%s%s %s%s%s %s%s%s\n", bold, m.Control, reset,
		stateColourOfRelation(m.Relation), m.Relation, reset,
		bold, m.Requirement, reset)
	w.Human("  %s%s%s\n", dim, m.Relation.Describe(), reset)
	if m.Remainder != "" {
		w.Human("  %snothing here covers: %s%s\n", yellow, m.Remainder, reset)
	}
	if !m.Relation.Satisfies() {
		w.Human("  %sthis does not mark the requirement as met%s\n",
			dim, reset)
	}
	return nil
}

func stateColourOfRelation(r crosswalk.Relation) string {
	switch {
	case r.Satisfies():
		return green
	case r.Partial():
		return yellow
	default:
		return dim
	}
}
