// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/detect"
)

// Detections, as files somebody reviews rather than queries somebody typed.
//
// The reason this is a command and not a screen: a detection is code in every
// sense that matters — it is reviewed, versioned, diffed and tested — and the
// place that happens is a repository. Splunk's contentctl and Elastic's
// detection-rules both arrived at the same shape, and both for the reason
// this program keeps arriving at: a rule nobody can diff is a rule nobody can
// review.
//
// `detect test` is the part that earns its place. Between 13 and 18 percent of
// deployed rules in this industry never fire under any input, and nothing
// about a rule's text says which ones. Running each rule against the events it
// claims to catch, and the benign ones it claims not to, is the only thing
// that answers it — and it needs no SIEM, no index and no network, so it runs
// in CI on every change.

// MaxRuleFile bounds one rule file.
const MaxRuleFile = 1 << 20

func cmdDetect(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"test"}
	}
	switch args[0] {
	case "test":
		return detectTest(args[1:])
	case "list":
		return detectList(args[1:])
	case "fields":
		return detectFields(args[1:])
	default:
		return fmt.Errorf(
			"unknown detect command %q; try test, list or fields", args[0])
	}
}

// rulesIn loads every rule under a directory, or one file.
func rulesIn(path string) ([]detect.Rule, error) {
	if path == "" {
		path = "detections"
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var files []string
	if info.IsDir() {
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
				return err
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			return nil, err
		}
		// Sorted, so a failure list reads the same twice running and a diff of
		// two runs is a diff of the rules rather than of the walk order.
		sort.Strings(files)
	} else {
		files = []string{path}
	}

	var out []detect.Rule
	seen := map[string]string{}
	for _, f := range files {
		fi, serr := os.Stat(f)
		if serr != nil {
			return nil, serr
		}
		if fi.Size() > MaxRuleFile {
			return nil, fmt.Errorf("%s is %d bytes; a rule is not that big",
				f, fi.Size())
		}
		body, rerr := os.ReadFile(f)
		if rerr != nil {
			return nil, rerr
		}
		var r detect.Rule
		if uerr := json.Unmarshal(body, &r); uerr != nil {
			return nil, fmt.Errorf("%s is not a rule: %w", f, uerr)
		}
		if where, dup := seen[r.ID]; dup {
			// Two rules with one id means a finding cannot say which rule
			// produced it, which is the one thing a finding has to say.
			return nil, fmt.Errorf(
				"%s and %s are both called %q", where, f, r.ID)
		}
		seen[r.ID] = f
		out = append(out, r)
	}
	return out, nil
}

func detectTest(args []string) error {
	path := ""
	if len(args) > 0 {
		path = args[0]
	}
	rules, err := rulesIn(path)
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		return fmt.Errorf("no rules found in %s", orDefault(path))
	}

	var refused, failed, checked int
	for _, r := range rules {
		// Validated before it is run. Every check there is a way a rule is
		// silently useless rather than visibly wrong, and a rule that fails
		// one would otherwise deploy and be counted as protection.
		if verr := r.Validate(); verr != nil {
			refused++
			w.Human("  %s%s%s  %v\n", red, r.ID, reset, verr)
			continue
		}
		for _, res := range r.Test() {
			checked++
			if res.OK() {
				continue
			}
			failed++
			w.Human("  %s%s%s  %s\n", red, res.Fixture, reset, res.Why())
		}
	}

	if w.JSON(map[string]any{
		"rules": len(rules), "refused": refused,
		"fixtures": checked, "failed": failed,
	}) {
		return nil
	}
	if refused == 0 && failed == 0 {
		w.Human("%s%d rule(s), %d fixture(s), all agreeing%s\n",
			green, len(rules), checked, reset)
		return nil
	}
	return fmt.Errorf("%d rule(s) refused, %d fixture(s) disagreeing",
		refused, failed)
}

func detectList(args []string) error {
	path := ""
	if len(args) > 0 {
		path = args[0]
	}
	rules, err := rulesIn(path)
	if err != nil {
		return err
	}
	if w.JSON(rules) {
		return nil
	}
	for _, r := range rules {
		state, colour := "ok", green
		if verr := r.Validate(); verr != nil {
			state, colour = "refused", red
		}
		w.Human("%s%-28s%s %s%s%s  %s\n",
			bold, r.ID, reset, colour, state, reset, r.Title)
		w.Human("  %sreads %s from %s%s\n", dim,
			strings.Join(r.Fields(), ", "), strings.Join(r.Sources, ", "), reset)
		if len(r.Technique) > 0 {
			// Navigation, never a score. MITRE's own research arm now states
			// a technique marked covered says nothing about whether the
			// detection catches its variations or resists evasion.
			w.Human("  %sattack %s%s\n", dim, strings.Join(r.Technique, " "), reset)
		}
		if r.Blind != "" {
			w.Human("  %sblind: %s%s\n", yellow, r.Blind, reset)
		}
	}
	return nil
}

// detectFields prints what a rule may refer to and how it may compare.
func detectFields(args []string) error {
	ops := make([]string, 0, len(detect.Ops()))
	for _, o := range detect.Ops() {
		ops = append(ops, string(o))
	}
	if w.JSON(map[string]any{"operators": ops}) {
		return nil
	}
	w.Human("%soperators%s\n", bold, reset)
	for _, o := range ops {
		w.Human("  %s\n", o)
	}
	w.Human("\n  %sfields come from the events themselves: "+
		"quilzo telemetry fields FILE%s\n", dim, reset)
	w.Human("  %sa rule naming anything else is refused at load, because it "+
		"would otherwise run and match nothing forever%s\n", dim, reset)
	return nil
}

func orDefault(p string) string {
	if p == "" {
		return "detections/"
	}
	return p
}
