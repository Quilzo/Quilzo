// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/controls"
	"github.com/quilzo/quilzo/internal/fedramp"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/oscal"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/compliance"
	"github.com/quilzo/quilzo/internal/config"
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
	case "site":
		return complianceSite(root, args[1:])
	case "implementation":
		return complianceImplementation(args[1:])
	case "component":
		return complianceComponent(root, args[1:])
	case "pledge":
		return compliancePledge()
	case "ssp":
		return complianceSSP(root, args[1:])
	case "ksi":
		return complianceKSI(root, args[1:])
	case "ai-act", "iso42001", "aibom":
		return complianceAI(root, args[0], args[1:])
	default:
		return fmt.Errorf("unknown compliance command %q; try site, implementation, component, ssp, ksi, pledge, "+
			"sbom, crypto, controls, accessibility, summary, %s", args[0], complianceAIName)
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
	// And the settings that are a control's implementation: what the
	// organisation sets, and its policy can hold (internal/odp).
	setBy := map[string][]string{}
	for _, st := range config.All() {
		for _, c := range st.Controls {
			setBy[c] = append(setBy[c], st.Key)
		}
	}
	if w.JSON(map[string]any{"checked_by": seen, "set_by": setBy}) {
		return nil
	}

	all := map[string]bool{}
	for c := range seen {
		all[c] = true
	}
	for c := range setBy {
		all[c] = true
	}
	var ids []string
	for c := range all {
		ids = append(ids, c)
	}
	sort.Strings(ids)

	w.Human("%s%d NIST SP 800-53 control(s) with an automated check, %d set by a setting%s\n\n",
		bold, len(seen), len(setBy), reset)
	for _, c := range ids {
		if rules := seen[c]; len(rules) > 0 {
			w.Human("  %-12s checked by %s%s%s\n", c, dim, strings.Join(rules, ", "), reset)
		} else {
			w.Human("  %-12s %snot checked automatically%s\n", c, dim, reset)
		}
		if keys := setBy[c]; len(keys) > 0 {
			w.Human("  %-12s set by     %s%s%s\n", "", dim, strings.Join(keys, ", "), reset)
		}
	}
	w.Human("\n  %sgenerated from the rules and the settings, so a control listed here is one "+
		"something\n  actually checks or sets — not one somebody intended to cover. "+
		"quilzo policy shows the organisation's values%s\n",
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
	w.Human("  %s%s%s\n", dim, acr.Standard, reset)
	w.Human("\n  %-9s %-11s %-19s %s\n", "WCAG", "EN 301 549", "RESULT", "CHECKED BY")
	for _, c := range acr.Evaluated {
		checks := strings.Join(c.Checks, "; ")
		if checks == "" {
			checks = "—"
		}
		w.Human("  %-9s %-11s %-19s %s\n", c.Number, c.Clause, c.Result, truncate(checks, 40))
		if c.Remarks != "" {
			w.Human("                        %s%s%s\n", dim, c.Remarks, reset)
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

// complianceImplementation prints how Quilzo implements each control, or
// one control in full (internal/controls).
func complianceImplementation(args []string) error {
	all := controls.All()
	if len(args) == 1 {
		im, ok := controls.Lookup(args[0])
		if !ok {
			return fmt.Errorf("no statement for %s; quilzo compliance implementation lists the %d there are", args[0], len(all))
		}
		if w.JSON(im) {
			return nil
		}
		w.Human("%s%s%s  %s  %s\n\n  %s\n", bold, im.Control, reset, im.Title, responsibilityWords(im.Responsibility), im.Statement)
		if im.Customer != "" {
			w.Human("\n  %sthe customer's part:%s %s\n", bold, reset, im.Customer)
		}
		for _, l := range []struct {
			name string
			vs   []string
		}{{"checked by", im.Rules}, {"set by", im.Settings}, {"parameters", im.Params}, {"where", im.Where}} {
			if len(l.vs) > 0 {
				w.Human("  %s%-11s%s %s\n", dim, l.name, reset, strings.Join(l.vs, ", "))
			}
		}
		return nil
	}
	if w.JSON(all) {
		return nil
	}
	n := controls.Count(all)
	w.Human("%s%d NIST SP 800-53 controls%s: Quilzo %d, shared %d, the customer's %d\n\n", bold, len(all), reset,
		n[controls.Quilzo], n[controls.Shared], n[controls.Customer])
	for _, im := range all {
		w.Human("  %-10s %-9s %s%s%s\n", im.Control, im.Responsibility, dim, im.Title, reset)
	}
	w.Human("\n  %squilzo compliance implementation AC-7   one control in full%s\n", dim, reset)
	w.Human("  %squilzo compliance component            all of it as an OSCAL component definition%s\n", dim, reset)
	return nil
}

func responsibilityWords(r controls.Responsibility) string {
	switch r {
	case controls.Quilzo:
		return "Quilzo implements it"
	case controls.Shared:
		return "shared: Quilzo provides it, the customer runs it"
	}
	return "the customer's"
}

// complianceComponent writes the OSCAL component definition.
func complianceComponent(root string, args []string) error {
	fs := flag.NewFlagSet("compliance component", flag.ContinueOnError)
	out := fs.String("o", "", "write to this file instead of standard output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pol, err := odp.Load(paramsPath(root))
	if err != nil {
		return err
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	cd, err := controls.ComponentDefinition(version, odp.SetParameters(pol, cfg), time.Now())
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(cd, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if *out != "" {
		return atomicfile.Write(*out, body, 0o644)
	}
	_, err = os.Stdout.Write(body)
	return err
}

// compliancePledge prints where Quilzo stands on each goal of CISA's Secure
// by Design pledge.
func compliancePledge() error {
	if w.JSON(controls.Pledge) {
		return nil
	}
	w.Human("%sCISA Secure by Design pledge%s  %s\n\n", bold, reset, controls.PledgeURL)
	colour := map[controls.Standing]string{controls.Met: green, controls.Partly: yellow, controls.NotYet: red}
	for _, g := range controls.Pledge {
		w.Human("  %s%d. %s%s  %s%s%s\n     %s\n\n", bold, g.N, g.Title, reset, colour[g.Standing], g.Standing, reset, g.Position)
	}
	return nil
}

// systemID is this deployment's identifier in its security plan, made once
// and kept, so every revision of the plan names the same system.
func systemID(root string) (string, error) {
	path := filepath.Join(root, "self", "system-id")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	id, err := oscal.NewUUID()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	return id, atomicfile.Write(path, []byte(id+"\n"), 0o600)
}

// failingByControl is, by control in OSCAL form, what the posture scan
// reports against it now.
func failingByControl(root, tplDir string) map[string][]string {
	rep := posture.Scan(Observe(root, tplDir, posture.ServerFacts{}), nil)
	out := map[string][]string{}
	for _, f := range rep.Findings {
		for _, c := range f.Controls {
			id := oscal.ControlID(c)
			out[id] = append(out[id], f.Rule+": "+f.Detail)
		}
	}
	return out
}

// complianceSSP drafts the system security plan.
func complianceSSP(root string, args []string) error {
	fs := flag.NewFlagSet("compliance ssp", flag.ContinueOnError)
	impact := fs.String("impact", "", "the system's FIPS 199 level: low, moderate or high (required)")
	out := fs.String("o", "", "write to this file instead of standard output")
	tplDir := fs.String("templates", "templates", "where the layouts live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *impact == "" {
		return errors.New("say the system's impact level: quilzo compliance ssp --impact low|moderate|high " +
			"(FIPS 199; it chooses the NIST baseline the plan is held to)")
	}
	id, err := systemID(root)
	if err != nil {
		return err
	}
	pol, err := odp.Load(paramsPath(root))
	if err != nil {
		return err
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	plan, err := controls.SystemSecurityPlan(controls.SSPInput{Impact: strings.ToLower(*impact), SystemID: id,
		SystemName: siteName(root), Organisation: organisationOf(root), Version: version, At: time.Now(),
		Params: odp.SetParameters(pol, cfg), Failing: failingByControl(root, *tplDir)})
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if *out != "" {
		return atomicfile.Write(*out, body, 0o644)
	}
	_, err = os.Stdout.Write(body)
	return err
}

// ksiReport is Quilzo's evidence against FedRAMP 20x's Key Security
// Indicators, as written out and as served.
type ksiReport struct {
	Source     fedramp.Source   `json:"fedramp_rules"`
	Generated  string           `json:"generated"`
	System     string           `json:"system"`
	Note       string           `json:"note"`
	Indicators []fedramp.Result `json:"indicators"`
}

func buildKSI(root, tplDir string) (ksiReport, error) {
	src, res, err := fedramp.Assess(failingByControl(root, tplDir))
	if err != nil {
		return ksiReport{}, err
	}
	return ksiReport{Source: src, Generated: time.Now().UTC().Format(time.RFC3339), System: siteName(root),
		Note: "Quilzo is one component of the service being authorised and cannot meet an indicator. For each, " +
			"this says which related SP 800-53 controls Quilzo implements, whether its checks on them pass now, " +
			"and where it has nothing to show and the provider's own process does.",
		Indicators: res}, nil
}

// complianceKSI prints Quilzo's evidence against the FedRAMP 20x Key
// Security Indicators, or writes it as JSON.
func complianceKSI(root string, args []string) error {
	fs := flag.NewFlagSet("compliance ksi", flag.ContinueOnError)
	out := fs.String("o", "", "write the JSON to this file")
	tplDir := fs.String("templates", "templates", "where the layouts live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rep, err := buildKSI(root, *tplDir)
	if err != nil {
		return err
	}
	if *out != "" {
		body, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		return atomicfile.Write(*out, append(body, '\n'), 0o644)
	}
	if w.JSON(rep) {
		return nil
	}
	n := map[fedramp.Standing]int{}
	for _, r := range rep.Indicators {
		n[r.Standing]++
	}
	w.Human("%sFedRAMP 20x Key Security Indicators%s  %s, version %s\n", bold, reset, rep.Source.Title, rep.Source.Version)
	w.Human("  Quilzo contributes to %d, %d with a check failing now, and has nothing to show for %d\n\n",
		n[fedramp.Contributes], n[fedramp.Failing], n[fedramp.Elsewhere])
	colour := map[fedramp.Standing]string{fedramp.Contributes: green, fedramp.Failing: red, fedramp.Elsewhere: dim}
	theme := ""
	for _, r := range rep.Indicators {
		if r.Theme != theme {
			theme = r.Theme
			w.Human("  %s%s%s\n", bold, r.ThemeName, reset)
		}
		w.Human("    %-12s %s%-11s%s %s\n", r.ID, colour[r.Standing], r.Standing, reset, r.Name)
	}
	w.Human("\n  %s%s%s\n  %squilzo compliance ksi -o ksi.json   the evidence, control by control%s\n", dim, rep.Note, reset, dim, reset)
	return nil
}
