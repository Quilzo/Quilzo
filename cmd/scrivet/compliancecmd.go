package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/compliance"
	"github.com/rsh1k/scrivet/internal/posture"
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
	case "summary":
		return complianceSummary(root)
	default:
		return fmt.Errorf("unknown compliance command %q; try sbom, crypto, "+
			"controls or summary", args[0])
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

	w.Human("\n  %sscrivet compliance sbom      CycloneDX 1.6, machine-readable%s\n",
		dim, reset)
	w.Human("  %sscrivet compliance crypto    every algorithm and its posture%s\n",
		dim, reset)
	w.Human("  %sscrivet compliance controls  what is checked, mapped to 800-53%s\n",
		dim, reset)
	w.Human("  %sscrivet posture scan         the current findings%s\n", dim, reset)
	w.Human("  %sscrivet auditlog head        a commitment to the record%s\n",
		dim, reset)

	w.Human("\n  %snone of this is a certification. An SBOM is not a SOC 2 "+
		"report and a\n  control mapping is not an assessment — this is the "+
		"evidence somebody\n  needs before any of that is worth starting, "+
		"produced accurately rather\n  than approximately.%s\n", dim, reset)
	return nil
}
