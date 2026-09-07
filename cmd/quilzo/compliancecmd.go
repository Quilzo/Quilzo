// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/compliance"
	"github.com/quilzo/quilzo/internal/posture"
)

func cmdCompliance(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"summary"}
	}
	switch args[0] {
	case "sbom":
		return complianceSBOM(args[1:])
	case "crypto":
		return complianceCrypto()
	case "controls":
		return complianceControls()
	case "accessibility", "acr":
		return complianceACR(root, args[1:])
	case "summary":
		return complianceSummary(root)
	default:
		return fmt.Errorf("unknown compliance command %q; try sbom, crypto, "+
			"controls, accessibility or summary", args[0])
	}
}

func complianceSBOM(args []string) error {
	s, err := compliance.Generate(time.Now())
	if err != nil {
		return err
	}
	body, err := compliance.Render(s)
	if err != nil {
		return err
	}
	if len(args) == 1 {
		if err := os.WriteFile(args[0], body, 0o644); err != nil {
			return err
		}
		w.Human("wrote %s%s%s\n", bold, args[0], reset)
	} else {
		fmt.Print(string(body))
	}

	third := compliance.ThirdParty(s)
	fmt.Fprintf(os.Stderr, "\n%s%d third-party component(s)%s\n",
		bold, len(third), reset)
	if len(third) == 0 {
		fmt.Fprintf(os.Stderr,
			"  %sno transitive tree to track, nothing that can reach end of "+
				"life\n  unnoticed, and no advisory feed to reconcile against. "+
				"That is the\n  single largest reason the Cyber Resilience Act "+
				"obligations here are cheap.%s\n", dim, reset)
	}
	return nil
}

func complianceCrypto() error {
	inv := compliance.Inventory()
	if w.JSON(map[string]any{
		"algorithms": inv, "concerns": compliance.Concerns(),
	}) {
		return nil
	}

	w.Human("%salgorithms in use%s\n\n", bold, reset)
	for _, a := range inv {
		colour := green
		switch a.Quantum {
		case compliance.Reduced:
			colour = dim
		case compliance.Broken:
			colour = yellow
		}
		w.Human("  %-26s %s%-8s%s %s\n", a.Name, colour, a.Quantum, reset, a.Use)
		w.Human("    %s%s · %s%s\n", dim, a.Purpose, a.Where, reset)
		if a.Note != "" {
			w.Human("    %s%s%s\n", dim, wrapIndent(a.Note, 68, 4), reset)
		}
		w.Human("\n")
	}

	w.Human("%sposture%s\n\n", bold, reset)
	for _, line := range splitLines(compliance.Posture()) {
		w.Human("  %s\n", line)
	}
	return nil
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// complianceControls lists the NIST controls the posture rules cover.
//
// Generated from the rules rather than maintained beside them, so a control
// claimed here is a control something actually checks. A mapping written by
// hand is a list of controls somebody intended to cover.
func complianceControls() error {
	seen := map[string][]string{}
	for _, r := range posture.Rules() {
		for _, c := range r.Controls {
			seen[c] = append(seen[c], r.ID)
		}
	}
	if w.JSON(seen) {
		return nil
	}

	var ids []string
	for c := range seen {
		ids = append(ids, c)
	}
	sort.Strings(ids)

	w.Human("%s%d NIST SP 800-53 control(s) with an automated check%s\n\n",
		bold, len(ids), reset)
	for _, c := range ids {
		w.Human("  %-12s %s%s%s\n", c, dim, strings.Join(seen[c], ", "), reset)
	}
	w.Human("\n  %sgenerated from the rules, so a control listed here is one "+
		"something\n  actually checks — not one somebody intended to cover%s\n",
		dim, reset)
	return nil
}

func complianceSummary(root string) error {
	s, err := compliance.Generate(time.Now())
	if err != nil {
		return err
	}
	third := compliance.ThirdParty(s)

	controls := map[string]bool{}
	for _, r := range posture.Rules() {
		for _, c := range r.Controls {
			controls[c] = true
		}
	}

	if w.JSON(map[string]any{
		"product":                s.Metadata.Component,
		"third_party_components": len(third),
		"controls_checked":       len(controls),
		"quantum_concerns":       compliance.Concerns(),
	}) {
		return nil
	}

	w.Human("%s%s%s  %s\n\n", bold, s.Metadata.Component.Name, reset,
		s.Metadata.Component.Version)

	w.Human("  %-34s %s%d%s\n", "third-party components", green, len(third), reset)
	w.Human("  %-34s %s%d%s\n", "NIST controls with a check", green,
		len(controls), reset)
	w.Human("  %-34s %s%s\n", "quantum-broken, generated here",
		green+"none"+reset, "")
	w.Human("  %-34s %s%d%s\n", "quantum-broken, verified only", dim,
		len(compliance.Concerns()), reset)

	w.Human("\n  %squilzo compliance sbom      CycloneDX 1.6, machine-readable%s\n",
		dim, reset)
	w.Human("  %squilzo compliance crypto    every algorithm and its posture%s\n",
		dim, reset)
	w.Human("  %squilzo compliance controls  what is checked, mapped to 800-53%s\n",
		dim, reset)
	w.Human("  %squilzo posture scan         the current findings%s\n", dim, reset)
	w.Human("  %squilzo auditlog head        a commitment to the record%s\n",
		dim, reset)

	w.Human("\n  %snone of this is a certification. An SBOM is not a SOC 2 "+
		"report and a\n  control mapping is not an assessment — this is the "+
		"evidence somebody\n  needs before any of that is worth starting, "+
		"produced accurately rather\n  than approximately.%s\n", dim, reset)
	return nil
}

// complianceACR prints an accessibility conformance report.
//
// The artefact a government or a large institution asks for before it will
// buy, and almost always a document somebody wrote by hand months after the
// software changed. This one is generated from a scan of the content actually
// in this store, and reports only what was evaluated — see internal/a11y/acr.go
// for why it does not enumerate WCAG.
func complianceACR(root string, args []string) error {
	fs := flag.NewFlagSet("accessibility", flag.ContinueOnError)
	tplDir := fs.String("templates", "templates", "where the layouts live")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := store.Open(root)
	if err != nil {
		return err
	}
	live := s.GetRef(site.RefLive)
	if live == "" {
		return fmt.Errorf(
			"nothing is published, so there is no content to report on. A " +
				"conformance report over an empty site would be a clean " +
				"report about nothing")
	}
	reports, err := checkAccessibility(root, s, live, *tplDir)
	if err != nil {
		return fmt.Errorf(
			"the accessibility check could not run, so this would be a "+
				"report of a check that did not happen: %w", err)
	}

	acr := a11y.BuildACR(reports)
	if w.JSON(acr) {
		return nil
	}

	w.Human("%sAccessibility conformance%s  %d page(s) scanned\n",
		bold, reset, acr.Pages)
	w.Human("\n  %-9s %-19s %s\n", "CRITERION", "RESULT", "CHECKED BY")
	for _, c := range acr.Evaluated {
		checks := strings.Join(c.Checks, "; ")
		if checks == "" {
			checks = "—"
		}
		w.Human("  %-9s %-19s %s\n", c.Number, c.Result, truncate(checks, 44))
		if c.Remarks != "" {
			w.Human("            %s%s%s\n", dim, c.Remarks, reset)
		}
	}

	w.Human("\n  %sNot evaluated — these need a person:%s\n", bold, reset)
	for _, n := range acr.NotEvaluated {
		w.Human("    %s%s%s\n", dim, n, reset)
	}
	w.Human("\n  %s%s%s\n", yellow, acr.Caveat, reset)
	w.Human("\n  %sas JSON, for a procurement pack:%s\n", dim, reset)
	w.Human("    quilzo --json compliance accessibility\n")
	return nil
}
