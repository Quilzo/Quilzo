// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/oscal"
)

// The organisation's policy, as NIST organisation-defined parameters
// (internal/odp). `quilzo policy` shows it, proposes changes for a second
// administrator, approves them, imports an OSCAL document and exports one.

// paramsPath is where the declared parameters are kept. Not policy.json,
// which is who may do what (auth).
func paramsPath(root string) string { return filepath.Join(root, "parameters.json") }

// floorsFor is the organisation's policy as floors under the settings. A
// policy that cannot be read puts a broken floor under every setting it
// could bind, so nothing it governs is changed until it is repaired.
func floorsFor(root string) map[string][]config.Floor {
	pol, err := odp.Load(paramsPath(root))
	if err == nil {
		return odp.Floors(pol)
	}
	out := map[string][]config.Floor{}
	for _, p := range odp.Params {
		if p.How != odp.Set {
			continue
		}
		keys := []string{p.Setting}
		if p.Kind == odp.Choice {
			keys = []string{"auth.throttle", "auth.lockout.hard", "auth.lockout.alert"}
		}
		for _, k := range keys {
			out[k] = append(out[k], config.Floor{Param: p.ID, Broken: err.Error()})
		}
	}
	return out
}

// withPolicy changes the policy under its lock.
func withPolicy(root string, change func(*odp.Policy) error) error {
	return odp.Update(paramsPath(root), change)
}

// enforcePolicy brings every setting up to the policy, as the policy now
// stands: the step that makes an approval take effect, and the one upkeep
// takes when the configuration was edited below it by hand.
func enforcePolicy(root, by string) ([]string, error) {
	pol, err := odp.Load(paramsPath(root))
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return nil, err
	}
	raised, err := odp.Raise(pol, cfg, by)
	if err != nil {
		return nil, err
	}
	if len(raised) == 0 {
		return nil, nil
	}
	if err := saveConfig(root, cfg); err != nil {
		return nil, err
	}
	var keys []string
	for _, r := range raised {
		keys = append(keys, r.Key)
		record(root, audit.Record{Action: "policy.enforced", Resource: "/settings", Outcome: audit.Success,
			Principal: "quilzo", Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"setting": r.Key, "from": r.From, "to": r.To, "param": r.Param, "after": by}})
	}
	return keys, nil
}

func cmdPolicy(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	switch args[0] {
	case "show":
		return policyShow(root)
	case "params":
		return policyParams()
	case "propose":
		return policyPropose(root, args[1:])
	case "approve", "decline":
		return policyDecide(root, args[0], args[1:])
	case "withdraw":
		return policyWithdraw(root, args[1:])
	case "import":
		return policyImport(root, args[1:])
	case "export":
		return policyExport(root, args[1:])
	}
	return fmt.Errorf("unknown policy command %q; try show, params, propose, approve, decline, withdraw, import or export", args[0])
}

// policyRow is one parameter as `policy show` and the admin present it.
type policyRow struct {
	Param     odp.Param     `json:"-"`
	ID        string        `json:"param"`
	Control   string        `json:"control"`
	Label     string        `json:"label"`
	How       string        `json:"how"`
	Declared  *odp.Declared `json:"declared,omitempty"`
	Effective string        `json:"effective"`
	Met       bool          `json:"met"`
}

// policyRows is every parameter with its declaration, its effect and
// whether the first is met by the second.
func policyRows(pol *odp.Policy, cfg *config.Config) []policyRow {
	var out []policyRow
	for _, p := range odp.Params {
		r := policyRow{Param: p, ID: p.ID, Control: p.Control, Label: p.Label, How: string(p.How),
			Effective: odp.Effective(p, cfg), Met: true}
		if d, ok := pol.Find(p.ID); ok {
			d := d
			r.Declared = &d
			r.Met = odp.Met(d, cfg)
		}
		out = append(out, r)
	}
	return out
}

func policyShow(root string) error {
	pol, err := odp.Load(paramsPath(root))
	if err != nil {
		return fmt.Errorf("%w\n  every setting it governs is refusing changes until it is readable; restore %s from a backup",
			err, paramsPath(root))
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	rows := policyRows(pol, cfg)
	pending := pol.Pending(time.Now())
	if w.JSON(map[string]any{"parameters": rows, "pending": pending}) {
		return nil
	}
	w.Human("%sOrganisation policy%s  NIST SP 800-53 organisation-defined parameters\n\n", bold, reset)
	for _, r := range rows {
		status := dim + "not declared" + reset
		if r.Declared != nil {
			status = green + "declared, met" + reset
			if !r.Met {
				status = red + "declared, NOT met" + reset
			}
		}
		w.Human("  %s%-13s%s %-8s %s\n", bold, r.ID, reset, r.Control, status)
		if r.Declared != nil {
			who := "approved by " + r.Declared.ApprovedBy
			if r.Declared.Alone {
				who = "approved alone by " + r.Declared.ApprovedBy
			}
			w.Human("                declared  %s  %s(proposed by %s, %s)%s\n", inline(r.Declared.Value), dim, r.Declared.By, who, reset)
		}
		w.Human("                here      %s\n", inline(r.Effective))
	}
	if len(pending) > 0 {
		w.Human("\n  %sWaiting for a second administrator%s\n", bold, reset)
		for _, p := range pending {
			w.Human("    %s  %s, by %s: %q\n", p.ID, changesText(p.Changes), p.By, p.Reason)
			w.Human("      %squilzo policy approve %s   or   quilzo policy decline %s%s\n", dim, p.ID, p.ID, reset)
		}
	}
	w.Human("\n  %squilzo policy params   what can be declared, and how each is kept%s\n", dim, reset)
	return nil
}

// inline puts a selection's choices on one line.
func inline(s string) string { return strings.ReplaceAll(s, "\n", "; ") }

func changesText(cs []odp.Change) string {
	var out []string
	for _, c := range cs {
		if c.Value == "" {
			out = append(out, c.Param+" taken away")
		} else {
			out = append(out, c.Param+" = "+inline(c.Value))
		}
	}
	return strings.Join(out, ", ")
}

func policyParams() error {
	if w.JSON(odp.Params) {
		return nil
	}
	w.Human("%sParameters this program answers for%s\n\n", bold, reset)
	for _, p := range odp.Params {
		how := map[odp.How]string{odp.Set: "declare it; it becomes a floor under " + p.Setting,
			odp.Fixed:     "declare it; accepted when the program's behaviour meets it",
			odp.Described: "exported only; the program describes it"}[p.How]
		if p.How == odp.Set && p.Kind == odp.Choice {
			how = "declare one or more, separated by ;"
		}
		w.Human("  %s%-13s%s %-8s %s\n                %s\n                %s%s%s\n", bold, p.ID, reset, p.Control, p.Label, p.Means, dim, how, reset)
	}
	return nil
}

// parseChanges reads PARAM=VALUE arguments; PARAM= takes one away.
func parseChanges(args []string) ([]odp.Change, error) {
	var out []odp.Change
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not PARAM=VALUE (for example ac-07_odp.01=5, or ac-12_odp= to take it away)", a)
		}
		out = append(out, odp.Change{Param: strings.TrimSpace(k), Value: v})
	}
	return out, nil
}

func policyPropose(root string, args []string) error {
	fs := flag.NewFlagSet("policy propose", flag.ContinueOnError)
	reason := fs.String("reason", "", "why (required; the second administrator reads it)")
	if err := fs.Parse(reorder(args, map[string]bool{"reason": true})); err != nil {
		return err
	}
	changes, err := parseChanges(fs.Args())
	if err != nil {
		return err
	}
	c := resolveCaller(root, flagToken)
	var pr odp.Proposal
	if err := withPolicy(root, func(pol *odp.Policy) error {
		var perr error
		pr, perr = pol.Propose(changes, *reason, c.Name, "", time.Now())
		return perr
	}); err != nil {
		return err
	}
	record(root, c.auditRecord("policy.proposed", "/settings", audit.Success,
		map[string]string{"proposal": pr.ID, "changes": changesText(pr.Changes), "reason": pr.Reason}))
	if w.JSON(pr) {
		return nil
	}
	w.Human("%sproposed%s %s: %s\n  another administrator approves it with quilzo policy approve %s, within a week\n",
		green, reset, pr.ID, changesText(pr.Changes), pr.ID)
	if onlyAdministrator(root, c.Name) {
		w.Human("  %syou are the only administrator, so you may approve it yourself; the policy will say it was approved alone%s\n", yellow, reset)
	}
	return nil
}

func policyDecide(root, verb string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo policy %s ID", verb)
	}
	c := resolveCaller(root, flagToken)
	alone := onlyAdministrator(root, c.Name)
	var pr odp.Proposal
	if err := withPolicy(root, func(pol *odp.Policy) error {
		var derr error
		pr, derr = pol.Decide(args[0], c.Name, verb == "approve", alone, time.Now())
		return derr
	}); err != nil {
		if errors.Is(err, odp.ErrSameAdministrator) {
			record(root, c.auditRecord("policy.refused", "/settings", audit.Denied,
				map[string]string{"proposal": args[0], "reason": "proposer approving"}))
		}
		return err
	}
	action := "policy.declined"
	if verb == "approve" {
		action = "policy.approved"
	}
	detail := map[string]string{"proposal": pr.ID, "changes": changesText(pr.Changes), "proposed_by": pr.By}
	if verb == "approve" && pr.By == c.Name {
		detail["alone"] = "true"
	}
	record(root, c.auditRecord(action, "/settings", audit.Success, detail))
	if verb == "decline" {
		w.Human("%sdeclined%s %s\n", yellow, reset, pr.ID)
		return nil
	}
	changed, err := enforcePolicy(root, c.Name)
	if err != nil {
		return fmt.Errorf("approved, and the settings could not be brought up to it: %w\n  upkeep will retry", err)
	}
	w.Human("%sapproved%s %s: %s\n", green, reset, pr.ID, changesText(pr.Changes))
	for _, k := range changed {
		w.Human("  %s%s raised to meet it%s\n", dim, k, reset)
	}
	return nil
}

func policyWithdraw(root string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: quilzo policy withdraw ID")
	}
	c := resolveCaller(root, flagToken)
	var pr odp.Proposal
	if err := withPolicy(root, func(pol *odp.Policy) error {
		var werr error
		pr, werr = pol.Withdraw(args[0], c.Name)
		return werr
	}); err != nil {
		return err
	}
	record(root, c.auditRecord("policy.withdrawn", "/settings", audit.Success, map[string]string{"proposal": pr.ID}))
	w.Human("%swithdrawn%s %s\n", yellow, reset, pr.ID)
	return nil
}

func policyImport(root string, args []string) error {
	fs := flag.NewFlagSet("policy import", flag.ContinueOnError)
	reason := fs.String("reason", "", "why (required)")
	if err := fs.Parse(reorder(args, map[string]bool{"reason": true})); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: quilzo policy import FILE.json --reason \"why\" (an OSCAL profile, system security plan or component definition)")
	}
	body, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	c := resolveCaller(root, flagToken)
	var im odp.Imported
	var pr odp.Proposal
	if err := withPolicy(root, func(pol *odp.Policy) error {
		var ierr error
		if im, ierr = odp.FromOSCAL(body, pol); ierr != nil {
			return ierr
		}
		if len(im.Changes) == 0 {
			return nil
		}
		pr, ierr = pol.Propose(im.Changes, *reason, c.Name, "import "+filepath.Base(fs.Arg(0)), time.Now())
		return ierr
	}); err != nil {
		return err
	}
	if pr.ID != "" {
		record(root, c.auditRecord("policy.proposed", "/settings", audit.Success,
			map[string]string{"proposal": pr.ID, "changes": changesText(pr.Changes), "reason": pr.Reason, "source": pr.Source}))
	}
	if w.JSON(map[string]any{"imported": im, "proposal": pr}) {
		return nil
	}
	w.Human("read a %s\n", im.Kind)
	if pr.ID != "" {
		w.Human("  %sproposed%s %s: %s\n  another administrator approves it with quilzo policy approve %s\n", green, reset, pr.ID, changesText(pr.Changes), pr.ID)
	} else {
		w.Human("  nothing to change\n")
	}
	if len(im.Unchanged) > 0 {
		w.Human("  %salready declared as given: %s%s\n", dim, strings.Join(im.Unchanged, ", "), reset)
	}
	for _, r := range im.Refused {
		w.Human("  %scannot keep%s %s\n", red, reset, r)
	}
	if len(im.NotOurs) > 0 {
		w.Human("  %s%d parameter(s) are about the organisation's people and processes or other systems, and are left to them%s\n",
			dim, len(im.NotOurs), reset)
	}
	if len(im.Refused) > 0 {
		return fmt.Errorf("%d parameter(s) in that document cannot be kept by this program; the rest were proposed", len(im.Refused))
	}
	return nil
}

func policyExport(root string, args []string) error {
	fs := flag.NewFlagSet("policy export", flag.ContinueOnError)
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
	title := "Organisation-defined parameters"
	if org := organisationOf(root); org != "" {
		title = org + ": organisation-defined parameters"
	}
	prof, err := oscal.ParameterProfile(title, version, time.Now(), odp.SetParameters(pol, cfg))
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(prof, "", "  ")
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
