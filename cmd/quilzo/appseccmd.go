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

	"github.com/quilzo/quilzo/internal/appsec"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// What a code scanner found, and the part it left undone.
//
// This reads the output of whatever the organisation already runs and does
// four things: identifies a finding so it survives a rename, separates what
// this change introduced from what the codebase already carried, groups four
// hundred alerts for one bad pattern into one piece of work, and refuses to
// close a secret because somebody deleted the line.
//
// The numbers are why. OX Security's 2026 benchmark puts the average
// enterprise at 865,398 alerts a year, of which 795 are critical after
// exploitability analysis. Nothing here reduces that: it separates the part
// that is new, which is the only gate a team sustains.

func appsecDir(root string) string {
	return filepath.Join(root, "appsec")
}

func baselinePath(root, repo string) string {
	return filepath.Join(appsecDir(root), safeName(repo)+".baseline.jsonl")
}

// lastPath is the previous run, which is not the baseline.
//
// The baseline is the debt this organisation decided to stop reporting and
// deliberately holds no secrets. The previous run is what the scanner last
// saw, secrets included, and it is the only thing that knows a secret used to
// be there.
func lastPath(root, repo string) string {
	return filepath.Join(appsecDir(root), safeName(repo)+".last.jsonl")
}

func rotationsPath(root string) string {
	return filepath.Join(appsecDir(root), "rotations.jsonl")
}

func safeName(s string) string {
	if strings.TrimSpace(s) == "" {
		return "default"
	}
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", "..", "_").
		Replace(s)
}

func cmdAppsec(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"triage"}
	}
	switch args[0] {
	case "triage":
		return appsecTriage(root, args[1:])
	case "gate":
		return appsecGate(root, args[1:])
	case "accept":
		return appsecAccept(root, args[1:])
	case "rotated":
		return appsecRotated(root, args[1:])
	default:
		return fmt.Errorf("unknown appsec command %q; try triage, gate, "+
			"accept or rotated", args[0])
	}
}

func loadAlerts(path string) ([]appsec.Alert, error) {
	var out []appsec.Alert
	err := loadJSONL(path, func(b []byte) error {
		var a appsec.Alert
		if uerr := json.Unmarshal(b, &a); uerr != nil {
			return uerr
		}
		if verr := a.Validate(); verr != nil {
			return verr
		}
		out = append(out, a)
		return nil
	})
	return out, err
}

func loadRotations(root string) ([]appsec.Rotation, error) {
	var out []appsec.Rotation
	err := loadJSONL(rotationsPath(root), func(b []byte) error {
		var r appsec.Rotation
		if uerr := json.Unmarshal(b, &r); uerr != nil {
			return uerr
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

// compare reads a run and the stored baseline and works out the difference.
func compare(root, path, repo string) (appsec.Triage, []appsec.Alert,
	[]appsec.Alert, error) {

	run, err := loadAlerts(path)
	if err != nil {
		return appsec.Triage{}, nil, nil, err
	}
	accepted, err := loadAlerts(baselinePath(root, repo))
	if err != nil {
		return appsec.Triage{}, nil, nil, err
	}
	previous, err := loadAlerts(lastPath(root, repo))
	if err != nil {
		return appsec.Triage{}, nil, nil, err
	}
	rotations, err := loadRotations(root)
	if err != nil {
		return appsec.Triage{}, nil, nil, err
	}
	at := time.Now().UTC()
	t := appsec.Compare(run, accepted, previous, appsec.From(rotations), at)
	return t, run, previous, nil
}

// remember writes this run as the previous one.
//
// Redacted, always. The file exists so that a secret disappearing can be told
// from a secret being rotated, and a copy of every credential the scanner
// found would be a worse problem than the one it solves.
//
// Secrets that have gone from the tree and have not been rotated are carried
// forward. Without that they are reported once and then forgotten on the next
// run — which is the same outcome as every other scanner, arrived at by a
// different route.
func remember(root, repo string, run []appsec.Alert) error {
	if err := os.MkdirAll(appsecDir(root), 0o700); err != nil {
		return err
	}
	previous, err := loadAlerts(lastPath(root, repo))
	if err != nil {
		return err
	}
	rotations, err := loadRotations(root)
	if err != nil {
		return err
	}
	done := appsec.From(rotations)
	here := map[string]bool{}
	for _, a := range run {
		here[a.Fingerprint()] = true
	}
	keep := append([]appsec.Alert(nil), run...)
	for _, a := range previous {
		f := a.Fingerprint()
		if a.Kind != appsec.Secret || here[f] {
			continue
		}
		if _, rotated := done[f]; rotated {
			continue
		}
		keep = append(keep, a)
	}

	f, err := os.Create(lastPath(root, repo))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, a := range keep {
		if err := enc.Encode(a.Redact()); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

func appsecTriage(root string, args []string) error {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	repo := fs.String("repo", "", "which repository, when several are scanned")
	top := fs.Int("top", 15, "how many rules to show")
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("usage: quilzo appsec triage ALERTS.jsonl [--repo R]")
	}
	t, run, previous, err := compare(root, rest[0], *repo)
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	groups := appsec.Groups(t.Introduced)
	found := appsec.Findings(t, previous, at)
	// Remembered after the comparison, so this run becomes what the next
	// one is measured against.
	if err := remember(root, *repo, run); err != nil {
		return err
	}

	if w.JSON(map[string]any{
		"alerts": len(run), "triage": t, "new": groups, "findings": found,
	}) {
		return nil
	}
	colour := green
	if len(t.Vanished) > 0 || len(t.Introduced) > 0 {
		colour = red
	}
	w.Human("%s%d alert(s) in this run%s\n", bold, len(run), reset)
	w.Human("%s%s%s\n", colour, t.Why(), reset)
	if t.Churned > 0 {
		w.Human("  %s%d are identified by their path, so a rename will "+
			"close them and open them again%s\n", yellow, t.Churned, reset)
	}
	w.Human("\n")

	for _, f := range found {
		if strings.Contains(f.Title, "has not been rotated") {
			w.Human("%s%s%s\n", red, f.Title, reset)
			w.Human("  %s%s%s\n", dim, f.Evidence[0].What, reset)
		}
	}
	shown := *top
	if shown > len(groups) {
		shown = len(groups)
	}
	for _, g := range groups[:shown] {
		mark := dim
		if g.Kind == appsec.Secret {
			mark = red
		}
		w.Human("%s%s%s  %s%s%s  in %d place(s)\n", bold, g.Rule, reset,
			mark, g.Kind, reset, g.Count())
		w.Human("  %s%s%s\n", dim, g.Where(3), reset)
	}
	if len(groups) > shown {
		w.Human("\n  %s%d more rule(s)%s\n", dim, len(groups)-shown, reset)
	}
	return nil
}

func appsecGate(root string, args []string) error {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	repo := fs.String("repo", "", "which repository")
	at := fs.Int("at", int(telemetry.SeverityHigh),
		"block new alerts at this severity or above (1 info … 5 critical)")
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("usage: quilzo appsec gate ALERTS.jsonl [--at 4]")
	}
	t, _, _, err := compare(root, rest[0], *repo)
	if err != nil {
		return err
	}
	threshold := telemetry.Severity(*at)
	g := appsec.Check(t, threshold)

	if w.JSON(map[string]any{
		"passes": g.Passes(), "gate": g, "why": g.Why(threshold),
	}) {
		return nil
	}
	colour := green
	if !g.Passes() {
		colour = red
	}
	w.Human("%s%s%s\n", colour, g.Why(threshold), reset)
	for _, a := range g.Secrets {
		r := a.Redact()
		w.Human("  %s%s%s  %s:%d\n", red, r.Rule, reset, r.Path, r.Line)
	}
	for _, a := range g.Blocked {
		w.Human("  %s%s%s  %s:%d\n", yellow, a.Rule, reset, a.Path, a.Line)
	}
	if !g.Passes() {
		return errBlocked{fmt.Errorf("%d new alert(s) block this change",
			len(g.Blocked)+len(g.Secrets))}
	}
	return nil
}

// appsecAccept records a run as the baseline.
//
// Deliberately a separate command rather than something triage does. A
// baseline that updates itself on every run is one where nothing is ever new,
// and the whole value here is the difference.
func appsecAccept(root string, args []string) error {
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	repo := fs.String("repo", "", "which repository")
	rest, err := eventFileArgs(fs, args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return fmt.Errorf("usage: quilzo appsec accept ALERTS.jsonl [--repo R]")
	}
	run, err := loadAlerts(rest[0])
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Taking a codebase's existing debt as the baseline is a decision about
	// what this organisation will stop reporting: the same authority as
	// publishing.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := os.MkdirAll(appsecDir(root), 0o700); err != nil {
		return err
	}
	var secrets int
	f, err := os.Create(baselinePath(root, *repo))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, a := range run {
		if a.Kind == appsec.Secret {
			// A secret is never baselined away. Accepting one as existing
			// debt is deciding not to rotate a credential that is in the
			// history, which is not a decision a baseline should be able to
			// make quietly.
			secrets++
			continue
		}
		if err := enc.Encode(a.Redact()); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	record(root, caller.auditRecord("appsec.baseline",
		"/appsec/"+safeName(*repo), audit.Success, map[string]string{
			"alerts": fmt.Sprint(len(run) - secrets),
			"repo":   safeName(*repo),
		}))

	if w.JSON(map[string]any{
		"baselined": len(run) - secrets, "secrets_kept": secrets,
	}) {
		return nil
	}
	w.Human("%s%d alert(s)%s taken as the baseline for %s\n",
		bold, len(run)-secrets, reset, safeName(*repo))
	if secrets > 0 {
		w.Human("  %s%d secret(s) were not baselined. Accepting one as "+
			"existing debt is deciding not to rotate a credential that is "+
			"in the history%s\n", yellow, secrets, reset)
	}
	w.Human("  %sfrom now on, triage reports what is new against this%s\n",
		dim, reset)
	return nil
}

func appsecRotated(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("rotated", flag.ContinueOnError)
	where := fs.String("where", "", "what was rotated, in words")
	because := fs.String("because", "", "what was done")
	purged := fs.Bool("purged", false, "the history was rewritten as well")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf(
			"usage: quilzo appsec rotated FINGERPRINT --where \"...\" " +
				"--because \"...\"")
	}
	caller := resolveCaller(root, flagToken)
	r := appsec.Rotation{
		Secret: pos[0], Where: strings.TrimSpace(*where),
		At: time.Now().UTC(), By: caller.Name, Kind: caller.Kind,
		Because: strings.TrimSpace(*because), Purged: *purged,
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	if err := appendJSONL(rotationsPath(root), r); err != nil {
		return err
	}
	record(root, r.Record())

	if w.JSON(r) {
		return nil
	}
	w.Human("%s%s%s rotated: %s\n", bold, r.Secret, reset, r.Where)
	if !r.Purged {
		w.Human("  %sthe commit is still in the history, which is fine: "+
			"the credential is dead and rewriting history breaks every "+
			"clone%s\n", dim, reset)
	}
	return nil
}
