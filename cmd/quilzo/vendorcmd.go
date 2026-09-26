// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/vendor"
)

// Third-party risk, tiered by what a vendor can reach rather than by what
// they are paid.
//
// Two directions, kept apart. A vendor this organisation holds a token for is
// one thing; a vendor holding a token in this estate is another, and their
// compromise is our breach. The second is critical whatever an inherent risk
// questionnaire said about them, because what makes it critical is not a
// judgement — it is a token.
//
// `vendor reconcile` compares the register against the connectors actually
// configured. A register is a list somebody typed in and every list somebody
// typed in is behind; internal/connector holds facts.

func vendorsPath(root string) string {
	return filepath.Join(assuranceDir(root), "vendors.jsonl")
}

func cmdVendor(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return vendorList(root)
	case "show":
		return vendorShow(root, args[1:])
	case "reconcile":
		return vendorReconcile(root)
	case "review":
		return vendorReview(root, args[1:])
	default:
		return fmt.Errorf("unknown vendor command %q; try list, show, "+
			"reconcile or review", args[0])
	}
}

func loadVendors(root string) (*vendor.Register, error) {
	r := vendor.NewRegister()
	err := loadJSONL(vendorsPath(root), func(b []byte) error {
		var v vendor.Vendor
		if uerr := json.Unmarshal(b, &v); uerr != nil {
			return uerr
		}
		return r.Add(v)
	})
	return r, err
}

func tierColour(t vendor.Tier) string {
	switch t {
	case vendor.Critical:
		return red
	case vendor.High:
		return yellow
	case vendor.Elevated:
		return dim
	default:
		return dim
	}
}

func vendorList(root string) error {
	r, err := loadVendors(root)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	all := r.All()
	if w.JSON(all) {
		return nil
	}
	if len(all) == 0 {
		w.Human("no vendors in %s\n", vendorsPath(root))
		w.Human("  %squilzo vendor reconcile finds the ones a connector "+
			"already holds a credential to%s\n", dim, reset)
		return nil
	}
	for _, v := range all {
		tier, _ := v.Tier()
		state := ""
		if v.Status != vendor.Active {
			state = "  " + string(v.Status)
		}
		w.Human("%s%s%s  %s%s%s%s%s%s\n", bold, v.ID, reset,
			tierColour(tier), tier, reset, yellow, state, reset)
		w.Human("  %s%s — %s%s\n", dim, v.Name, v.Purpose, reset)
		w.Human("  %s%s%s\n", dim, v.Why(at), reset)
	}
	return nil
}

func vendorShow(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo vendor show ID")
	}
	r, err := loadVendors(root)
	if err != nil {
		return err
	}
	v, ok := r.Get(pos[0])
	if !ok {
		return fmt.Errorf("there is no vendor %q", pos[0])
	}
	at := time.Now().UTC()
	tier, because := v.Tier()
	if w.JSON(map[string]any{
		"vendor": v, "tier": tier.String(), "because": because,
		"due": v.Due(), "overdue": v.Overdue(at),
	}) {
		return nil
	}
	w.Human("%s%s%s  %s\n", bold, v.Name, reset, v.Purpose)
	w.Human("  %s%s%s — %s\n", tierColour(tier), tier, reset, because)
	w.Human("  %s%s%s\n", dim, v.Why(at), reset)
	if len(v.Access) > 0 {
		w.Human("\n  %saccess%s\n", bold, reset)
		for _, a := range v.Access {
			mark := dim
			if a.Reach.Inbound() {
				mark = red
			}
			w.Human("    %s%-14s%s %s\n", mark, a.Reach, reset, a.What)
			w.Human("      %s%s%s\n", dim, a.Reach.Describe(), reset)
			if len(a.Scopes) > 0 {
				w.Human("      %s%s%s\n", dim,
					strings.Join(a.Scopes, ", "), reset)
			}
		}
	}
	if len(v.Data) > 0 {
		w.Human("\n  %sdata%s\n", bold, reset)
		for _, d := range v.Data {
			w.Human("    %s%s%s\n", dim, d, reset)
		}
	}
	w.Human("\n  %ssubprocessors%s\n", bold, reset)
	switch {
	case len(v.Subprocessors) > 0:
		for _, s := range v.Subprocessors {
			w.Human("    %s%s  %s %s%s\n", dim, s.Name, s.For, s.Region,
				reset)
		}
	case v.Asked.IsZero():
		w.Human("    %snobody has asked. An empty list is not the same as "+
			"a vendor with no subprocessors%s\n", yellow, reset)
	default:
		w.Human("    %sasked %s and told there are none%s\n", dim,
			v.Asked.Format("2006-01-02"), reset)
	}
	return nil
}

func vendorReconcile(root string) error {
	r, err := loadVendors(root)
	if err != nil {
		return err
	}
	all, err := manifests(root)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	rec := vendor.Reconcile(r, all, at)
	found := vendor.Findings(r, rec, at)

	if w.JSON(map[string]any{
		"reconciliation": rec, "findings": found,
	}) {
		return nil
	}
	colour := green
	if !rec.Clean() {
		colour = red
	}
	w.Human("%s%s%s\n", colour, rec.Why(), reset)
	w.Human("  %s%d vendor(s), %d connector(s)%s\n\n", dim, r.Len(),
		rec.Checked, reset)

	for _, group := range []struct {
		label  string
		gaps   []vendor.Gap
		colour string
	}{
		{"still has access after the relationship ended", rec.Lingering, red},
		{"holds a credential and is not in the register", rec.Unregistered,
			red},
		{"has access the register does not mention", rec.Undeclared, yellow},
	} {
		for _, g := range group.gaps {
			w.Human("%s%s%s  %s%s%s\n", bold, g.Vendor, reset,
				group.colour, group.label, reset)
			w.Human("  %s%s%s\n", dim, g.What, reset)
		}
	}
	// Only what the gaps above did not already say. A "besides" list that
	// repeats the three lines directly over it teaches a reader to skip
	// both.
	shown := map[string]bool{}
	for _, list := range [][]vendor.Gap{rec.Lingering, rec.Unregistered,
		rec.Undeclared} {
		for _, g := range list {
			shown[g.Vendor] = true
		}
	}
	var rest []string
	for _, f := range found {
		if shown[f.Entity.Value] && isGapFinding(f.Title) {
			continue
		}
		rest = append(rest, f.Title)
	}
	if len(rest) > 0 {
		w.Human("\n%s%d thing(s) besides%s\n", bold, len(rest), reset)
		for _, title := range rest {
			w.Human("  %s%s%s\n", dim, title, reset)
		}
	}
	return nil
}

// isGapFinding reports whether a finding's title is one the reconciliation
// has already printed above.
func isGapFinding(title string) bool {
	for _, phrase := range []string{
		"after the relationship ended", "not in the register",
		"access the register does not mention",
	} {
		if strings.Contains(title, phrase) {
			return true
		}
	}
	return false
}

func vendorReview(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	asked := fs.Bool("asked-subprocessors", false,
		"record that they were asked who their processors are")
	note := fs.String("note", "", "what the review found")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo vendor review ID [--note \"...\"]")
	}
	r, err := loadVendors(root)
	if err != nil {
		return err
	}
	v, ok := r.Get(pos[0])
	if !ok {
		return fmt.Errorf("there is no vendor %q", pos[0])
	}
	caller := resolveCaller(root, flagToken)
	// Signing off a third party's access is a statement the organisation
	// stands behind: the same authority as publishing.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	at := time.Now().UTC()
	v.Reviewed = at
	if *asked {
		v.Asked = at
	}
	if strings.TrimSpace(*note) != "" {
		v.Note = strings.TrimSpace(*note)
	}
	if err := v.Validate(); err != nil {
		return err
	}
	// Appended, not edited. The register is read newest-wins, so a review
	// is a new line and the old one stays where an auditor can see it.
	if err := appendJSONL(vendorsPath(root), v); err != nil {
		return err
	}
	record(root, v.Record(caller.Name, caller.Kind))

	tier, because := v.Tier()
	if w.JSON(map[string]any{
		"vendor": v.ID, "tier": tier.String(), "due": v.Due(),
	}) {
		return nil
	}
	w.Human("%s%s%s reviewed\n", bold, v.Name, reset)
	w.Human("  %s%s%s — %s\n", tierColour(tier), tier, reset, because)
	w.Human("  %snext due %s%s\n", dim, v.Due().Format("2006-01-02"), reset)
	if v.Asked.IsZero() && tier >= vendor.High {
		w.Human("  %snobody has asked them who their processors are; "+
			"--asked-subprocessors records that%s\n", yellow, reset)
	}
	return nil
}
