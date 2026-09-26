// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/boundary"
	"github.com/quilzo/quilzo/internal/source"
)

// What each part of this program holds, and what running two together
// costs.
//
// "Should log analysis be separated from production" has a known answer —
// NIST SP 800-53 AU-9, and PCI DSS 10.3 from the other side. The tempting
// next step is to apply it everywhere, and that is wrong: separating
// everything costs the same as separating the one thing that needs it and
// buys much less.
//
// The SIEM case is two arguments wearing one name. Nothing rewrites its
// own record, which applies to every part and is already answered here
// without separating anything. And the collector holds credentials at
// other people's systems, which applies to one part and is the reason a
// line exists at all.

func cmdBoundary(args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	switch args[0] {
	case "show":
		return boundaryShow(args[1:])
	case "credentials":
		return boundaryCredentials()
	default:
		return fmt.Errorf("unknown boundary command %q; try show or "+
			"credentials", args[0])
	}
}

func boundaryShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	with := fs.String("together", "",
		"two parts, as a/b, to say what running them in one process costs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *with != "" {
		a, b, ok := strings.Cut(*with, "/")
		if !ok {
			return fmt.Errorf("name two parts as a/b")
		}
		why, found := boundary.Together(a, b)
		if !found {
			return fmt.Errorf("no such pair; the parts are %s",
				strings.Join(partNames(), ", "))
		}
		w.Human("%s%s and %s%s\n", bold, a, b, reset)
		w.Human("  %s%s%s\n", dim, wrapAt(why, 66, "  "), reset)
		return nil
	}

	var all []string
	for _, s := range source.Known() {
		all = append(all, s.Issuer+"/"+s.Stream)
	}
	conc := boundary.Across(all)
	if w.JSON(map[string]any{
		"parts": boundary.Sorted(), "concentration": conc,
	}) {
		return nil
	}

	w.Human("%swhat each part holds%s\n\n", bold, reset)
	last := boundary.Side("")
	for _, p := range boundary.Sorted() {
		if p.Side != last {
			colour := dim
			if p.Side.Outward() {
				colour = yellow
			}
			w.Human("  %s%s%s\n", colour, p.Side, reset)
			w.Human("    %s%s%s\n\n", dim, wrapAt(p.Side.Why(), 62,
				"    "), reset)
			last = p.Side
		}
		w.Human("    %s%-14s%s %s\n", bold, p.Name, reset, p.What)
		w.Human("      %sholds: %s%s\n", dim, wrapAt(p.Holds, 56,
			"      "), reset)
		w.Human("      %srecord: %s%s\n\n", dim, wrapAt(p.Tamper, 56,
			"      "), reset)
	}

	w.Human("%sthe line%s\n", bold, reset)
	if why, ok := boundary.Together("collector", "application"); ok {
		w.Human("  %s%s%s\n\n", yellow, wrapAt(why, 64, "  "), reset)
	}
	if why, ok := boundary.Together("detection", "vulnerability"); ok {
		w.Human("  %s%s%s\n\n", dim, wrapAt(why, 64, "  "), reset)
	}
	w.Human("  %s%s%s\n", bold, wrapAt(conc.Why(), 64, "  "), reset)
	return nil
}

func partNames() []string {
	var out []string
	for _, p := range boundary.Parts() {
		out = append(out, p.Name)
	}
	return out
}

func boundaryCredentials() error {
	creds := boundary.Worst()
	if w.JSON(map[string]any{"credentials": creds}) {
		return nil
	}
	w.Human("%swhat collecting each source costs to hold%s\n\n", bold,
		reset)
	last := ""
	for _, c := range creds {
		if string(c.Narrowness) != last {
			colour := dim
			if !c.Narrowness.Acceptable() {
				colour = yellow
			}
			w.Human("  %s%s%s — %s%s%s\n\n", colour, c.Narrowness, reset,
				dim, wrapAt(c.Narrowness.Costs(), 60, "    "), reset)
			last = string(c.Narrowness)
		}
		w.Human("    %s%-24s%s %s\n", bold, c.Source, reset,
			wrapAt(c.Narrowest, 44, "                             "))
		if c.Reach != "" {
			w.Human("      %salso reads: %s%s\n", dim,
				wrapAt(c.Reach, 52, "      "), reset)
		}
		if c.Note != "" {
			w.Human("      %s%s%s\n", dim, wrapAt(c.Note, 56, "      "),
				reset)
		}
		w.Human("\n")
	}
	w.Human("  %sdocumented rather than measured, and each is verified "+
		"against\n  your own tenant. What survives a vendor moving things "+
		"is the\n  narrowness: whether a platform offers a log-only scope "+
		"at all is\n  a property of its permission model, and it decides "+
		"whether the\n  excess can be designed away or has to be "+
		"compensated for%s\n", dim, reset)
	return nil
}
