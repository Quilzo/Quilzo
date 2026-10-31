// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

func envsPath(root string) string { return filepath.Join(root, "environments.json") }

// loadEnvs reads the environment set, defaulting to production alone.
//
// A store that has never heard of environments keeps working exactly as it
// did, because the default set names the ref that already exists rather than
// introducing a new one.
func loadEnvs(root string) (*site.Envs, error) {
	body, err := os.ReadFile(envsPath(root))
	if os.IsNotExist(err) {
		return site.DefaultEnvs(), nil
	}
	if err != nil {
		return nil, err
	}
	var e site.Envs
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("%s: %w", envsPath(root), err)
	}
	if err := e.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", envsPath(root), err)
	}
	return &e, nil
}

func saveEnvs(root string, e *site.Envs) error {
	if err := e.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(envsPath(root), append(body, '\n'), 0o600)
}

func cmdEnv(root string, args []string) error {
	if len(args) == 0 {
		return envStatus(root)
	}
	switch args[0] {
	case "list", "status":
		return envStatus(root)
	case "add":
		return envAdd(root, args[1:])
	case "remove":
		return envRemove(root, args[1:])
	case "promote":
		return envPromote(root, args[1:])
	case "diff":
		return envDiff(root, args[1:])
	default:
		return fmt.Errorf("unknown env command %q; try list, add, remove, "+
			"promote or diff", args[0])
	}
}

func envStatus(root string) error {
	e, err := loadEnvs(root)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	st, err := site.Status(s, e)
	if err != nil {
		return err
	}
	if w.JSON(st) {
		return nil
	}

	draft := s.GetRef(site.RefDraft)
	w.Human("  %-14s %-14s %s\n", "draft", short(draft), dim+"where work happens"+reset)
	for _, b := range st {
		mark, note := " ", ""
		switch {
		case b.Empty:
			mark, note = "!", yellow+"nothing promoted here yet"+reset
		case b.Ahead:
			mark, note = " ", dim+"ahead of "+prevName(st, b.Env.Name)+
				", which holds nothing"+reset
		case b.Same:
			note = green + "up to date" + reset
		default:
			mark = "→"
			note = yellow + fmt.Sprintf("%d change(s) waiting", b.Pending) + reset
		}
		label := b.Env.Name
		if b.Env.Production {
			label += " *"
		}
		w.Human("%s %-14s %-14s %s\n", mark, label, short(b.Commit), note)
	}
	w.Human("\n  %s* is what the public sees. Promotion moves a pointer to an "+
		"object that%s\n", dim, reset)
	w.Human("  %salready exists, so production gets the bytes that were "+
		"checked — not a copy%s\n", dim, reset)
	if len(st) == 1 {
		w.Human("\n  %squilzo env add staging --before production%s\n", dim, reset)
	}
	return nil
}

// prevName is the environment before this one in the sequence, for the message.
func prevName(states []site.Behind, name string) string {
	for i, b := range states {
		if b.Env.Name == name && i > 0 {
			return states[i-1].Env.Name
		}
	}
	return "the draft"
}

func envAdd(root string, args []string) error {
	var name, before, desc string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--before":
			if i+1 < len(args) {
				before = args[i+1]
				i++
			}
		case "--description":
			if i+1 < len(args) {
				desc = args[i+1]
				i++
			}
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) != 1 {
		return fmt.Errorf("usage: quilzo env add <name> [--before production]")
	}
	name = rest[0]

	e, err := loadEnvs(root)
	if err != nil {
		return err
	}
	order := 50
	if before != "" {
		target, ok := e.Lookup(before)
		if !ok {
			return fmt.Errorf("there is no environment called %q", before)
		}
		// Placed midway between the previous one and the target, so several
		// environments can be inserted without renumbering anything.
		low := 0
		if prev, has := e.Previous(target.Name); has {
			low = prev.Order
		}
		order = (low + target.Order) / 2
		if order == low || order == target.Order {
			return fmt.Errorf(
				"there is no room between %s and %s to insert another "+
					"environment; renumber them by hand in %s",
				before, target.Name, envsPath(root))
		}
	}

	e.Environments = append(e.Environments, site.Env{
		Name: name, Ref: "env-" + name, Order: order, Description: desc,
	})
	if err := saveEnvs(root, e); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("env.add", "/",
		audit.Success, map[string]string{"environment": name,
			"order": strconv.Itoa(order)}))

	w.Human("added %s%s%s\n", bold, name, reset)
	for _, env := range e.Sorted() {
		arrow := "  "
		if env.Name == name {
			arrow = "→ "
		}
		w.Human("  %s%s\n", arrow, env.Name)
	}
	w.Human("\n  %squilzo publish --to %s%s\n", dim, name, reset)
	return nil
}

func envRemove(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo env remove <name>")
	}
	e, err := loadEnvs(root)
	if err != nil {
		return err
	}
	target, ok := e.Lookup(args[0])
	if !ok {
		return fmt.Errorf("there is no environment called %q", args[0])
	}
	if target.Production {
		return fmt.Errorf(
			"%s is the production environment; removing it would leave "+
				"nothing serving the public", target.Name)
	}
	kept := e.Environments[:0]
	for _, env := range e.Environments {
		if env.Name != target.Name {
			kept = append(kept, env)
		}
	}
	e.Environments = kept
	if err := saveEnvs(root, e); err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("env.remove", "/",
		audit.Success, map[string]string{"environment": args[0]}))
	// The ref is deliberately left alone. Removing the environment removes a
	// name from a list; deleting the ref would discard the record of what that
	// environment was serving, which is the thing somebody asks about
	// afterwards.
	w.Human("removed %s\n", args[0])
	w.Human("  %sits ref is left in place, so what it was serving is still "+
		"recoverable%s\n", dim, reset)
	return nil
}

func envPromote(root string, args []string) error {
	skip := false
	// Where the pages are rendered from for the accessibility check, as
	// quilzo publish takes it and with the same default.
	tplDir := "templates"
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--skip" || a == "-skip":
			skip = true
		case a == "--templates" || a == "-templates":
			if i+1 == len(args) {
				return fmt.Errorf("--templates needs the folder the site's templates are in")
			}
			i++
			tplDir = args[i]
		case strings.HasPrefix(a, "--templates=") || strings.HasPrefix(a, "-templates="):
			_, tplDir, _ = strings.Cut(a, "=")
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) != 2 {
		return fmt.Errorf("usage: quilzo env promote <from> <to> [--skip] [--templates DIR]")
	}

	e, err := loadEnvs(root)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := refuseWhileFrozen(root); err != nil {
		return err
	}

	// Promoting to production is publishing, so the commit that moves is
	// asked what `quilzo publish` asks: whether the caller may publish each
	// page it changes, every check about the content, whether each page says
	// who or what wrote it, whether it renders accessibly, and the approvals
	// its bytes need. It was asked none of them, which made `env promote
	// draft production` the way to put up a draft the publish command
	// refuses, a model's included.
	//
	// None of them is waived here. A publish takes a written reason for an
	// unmarked page or an inaccessible one, and --no-a11y-check for a store
	// that is not what renders its pages; a pipeline step promoting what an
	// earlier step checked has nowhere to give either, so a commit that
	// needs one is published with `quilzo publish`, which records it.
	unchecked, refusal := "", ""
	p, err := site.PromoteChecked(s, e, rest[0], rest[1], skip, func(commit string) error {
		if err := mayPublishChanges(root, s, caller, commit); err != nil {
			// The record says why as a publish's does, without the
			// sentence, which names the caller: the record carries
			// people under keys of their own.
			refusal = "authorisation"
			return err
		}
		refused, advice, gerr := contentGates(root, s, commit).Run()
		for _, f := range advice {
			w.Human("  %s%s%s\n", dim, f.String(), reset)
		}
		if gerr != nil {
			return errBlocked{gerr}
		}
		if refused != nil {
			for _, f := range refused.Findings {
				w.Human("  %s%s%s\n", yellow, f.String(), reset)
			}
			return errBlocked{fmt.Errorf("%s", refused.Check.Refusal(len(refused.Findings)))}
		}
		unmarked, uerr := unmarkedAt(root, s, commit)
		if uerr != nil {
			return errBlocked{fmt.Errorf("the provenance check could not run, so "+
				"promoting would claim a check that did not happen: %v", uerr)}
		}
		if len(unmarked) > 0 {
			return errBlocked{fmt.Errorf("%d page(s) have no provenance and cannot "+
				"go to production: %s\n"+
				"  say who or what wrote each: quilzo provenance set PAGE --source humanEdits --author WHO\n"+
				"  a promotion takes no override; quilzo publish --force-unmarked --reason \"...\" records one",
				len(unmarked), strings.Join(unmarked, ", "))}
		}
		why, err := promotionAccessible(root, s, commit, tplDir)
		if err != nil {
			return err
		}
		unchecked = why
		if err := promotionApproved(root, s, commit); err != nil {
			// Likewise: an approval's reason can name the author.
			refusal = "dual-authorization"
			return err
		}
		return nil
	})
	if err != nil {
		if refusal == "" {
			refusal = err.Error()
		}
		record(root, caller.auditRecord("env.promote", "/", audit.Denied,
			map[string]string{"from": rest[0], "to": rest[1],
				"reason": refusal}))
		return err
	}
	detail := map[string]string{
		"from": p.From, "to": p.To, "commit": short(p.Commit),
		"was": short(p.Previous),
	}
	if skip {
		detail["skipped"] = "an environment was bypassed deliberately"
	}
	// Recorded as a publish records it: a configured skip is still a skip.
	if unchecked != "" {
		detail["a11y"] = "not checked"
		detail["why"] = unchecked
	}
	record(root, caller.auditRecord("env.promote", "/", audit.Success, detail))

	if w.JSON(p) {
		return nil
	}
	if p.Identical {
		w.Human("%s already holds %s; nothing moved\n", p.To, short(p.Commit))
		return nil
	}
	w.Human("%s → %s  %s  (%d change(s))\n", p.From, p.To, short(p.Commit),
		len(p.Changes))
	w.Human("  %sthe same objects, not a copy: %s is serving the bytes %s "+
		"was checked with%s\n", dim, p.To, p.From, reset)
	if p.Previous != "" {
		w.Human("  %sit was %s, which is still stored%s\n", dim,
			short(p.Previous), reset)
	}
	return nil
}

func envDiff(root string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: quilzo env diff <a> <b>")
	}
	e, err := loadEnvs(root)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	refA, err := e.RefFor(args[0])
	if err != nil {
		return err
	}
	refB, err := e.RefFor(args[1])
	if err != nil {
		return err
	}
	changes, err := site.Diff(s, s.GetRef(refA), s.GetRef(refB))
	if err != nil {
		return err
	}
	if w.JSON(changes) {
		return nil
	}
	if len(changes) == 0 {
		w.Human("%s and %s are identical\n", args[0], args[1])
		return nil
	}
	for _, c := range changes {
		w.Human("  %-9s %s\n", c.Kind, c.Path)
	}
	w.Human("\n  %d change(s) between %s and %s\n", len(changes), args[0], args[1])
	return nil
}

var _ = strings.TrimSpace

// promotionAccessible is the accessibility check a publish makes, made of
// the commit going into production: rendered through the templates in
// tplDir, as the site serves it, and refused on a blocking failure or a
// check that could not run. publish.require_a11y turned off is the one way
// past it, as it is for a publish, and what comes back then is why it was
// not checked, for the audit record.
func promotionAccessible(root string, s *store.Store, commit, tplDir string) (string, error) {
	if cfg, err := loadConfig(root); err == nil && cfg != nil && !cfg.Bool("publish.require_a11y") {
		w.Human("  %saccessibility not checked: publish.require_a11y is off%s\n", yellow, reset)
		return "publish.require_a11y is off", nil
	}
	reports, err := checkAccessibility(root, s, commit, tplDir)
	if err != nil {
		return "", errBlocked{fmt.Errorf("the accessibility check could not run, so "+
			"promoting would claim a check that did not happen: %v\n"+
			"  point --templates at the site's templates; a store that is not what "+
			"renders its pages is published with quilzo publish --no-a11y-check", err)}
	}
	if n := a11y.BlockingCount(reports); n > 0 {
		if w.Mode != out.JSON {
			printA11y(reports)
		}
		return "", errBlocked{fmt.Errorf("%d blocking accessibility failure(s); this "+
			"content is unusable for someone.\n"+
			"  fix them; a promotion takes no override, and quilzo publish "+
			"--force-inaccessible --reason \"...\" records one", n)}
	}
	return "", nil
}

// promotionApproved is dual authorisation for a commit going into
// production: the approvals given to those bytes, under the policy a
// publish is held to. A policy or a proposal that cannot be read refuses
// the promotion, since approvals nobody could count are not approvals.
func promotionApproved(root string, s *store.Store, commit string) error {
	pol, err := loadApprovalPolicy(root)
	if err != nil {
		return errBlocked{fmt.Errorf("the approval policy could not be read, so "+
			"promoting would claim approvals nobody counted: %w", err)}
	}
	if pol.Required <= 0 && !pol.RequireHumanForAI {
		return nil
	}
	prop, _, err := proposalFor(root, s, commit)
	if err != nil {
		return errBlocked{fmt.Errorf("the approvals for %s could not be read, so "+
			"promoting would claim approvals nobody counted: %w", short(commit), err)}
	}
	if d := pol.Evaluate(*prop, kindOfPrincipal(root), time.Now()); !d.Allowed {
		return errBlocked{fmt.Errorf("%s\n  quilzo review status", d.Reason)}
	}
	return nil
}
