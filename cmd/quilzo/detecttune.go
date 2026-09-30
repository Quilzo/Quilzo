// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/detect"
)

// Tuning the detections: what each rule has been worth, which ring it is
// in, and what is suppressed.
//
// The rules themselves stay files in a repository, reviewed and diffed like
// code. What lives in the store is what changes faster than a release and
// belongs to the people on call: which ring a rule is in and what is
// suppressed — each written with who, when and why, each in the audit log,
// and neither writable by a model.

func detectDir(root string) string { return filepath.Join(root, "detect") }

func ringsPath(root string) string { return filepath.Join(detectDir(root), "rings.json") }

func suppressionsPath(root string) string {
	return filepath.Join(detectDir(root), "suppressions.json")
}

// hitsPath counts what each suppression hid, so one that hides a great deal
// — or nothing — is visible.
func hitsPath(root string) string { return filepath.Join(detectDir(root), "suppressed.json") }

// rulesDir is where the rules are: a directory given, the store's own
// detections directory, or ./detections as the command line always took.
func rulesDir(root, given string) string {
	if given != "" {
		return given
	}
	if in := filepath.Join(root, "detections"); dirExists(in) {
		return in
	}
	return "detections"
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func loadJSONFile(path string, into any) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, into); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func saveJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

func loadRings(root string) (map[string]detect.Placement, error) {
	out := map[string]detect.Placement{}
	return out, loadJSONFile(ringsPath(root), &out)
}

func loadDetectSuppressions(root string) ([]detect.Suppression, error) {
	var out []detect.Suppression
	return out, loadJSONFile(suppressionsPath(root), &out)
}

func loadHits(root string) (map[string]int, error) {
	out := map[string]int{}
	return out, loadJSONFile(hitsPath(root), &out)
}

// tuning is everything the tuning screens and commands read.
type tuning struct {
	Rules        []detect.Rule
	Stats        []detect.Stats
	Proposals    []detect.Proposal
	Suppressions []detect.Suppression
	Hits         map[string]int
	Rings        map[string]detect.Placement
}

func loadTuning(root, dir string, now time.Time) (tuning, error) {
	var t tuning
	var err error
	if t.Rules, err = rulesIn(rulesDir(root, dir)); err != nil {
		return t, err
	}
	// Correlations sit beside the rules they are over: same rings, same
	// verdicts, same screen.
	corrs, err := correlationsIn(rulesDir(root, dir))
	if err != nil {
		return t, err
	}
	for _, c := range corrs {
		t.Rules = append(t.Rules, asRule(c))
	}
	if t.Rings, err = loadRings(root); err != nil {
		return t, err
	}
	if t.Suppressions, err = loadDetectSuppressions(root); err != nil {
		return t, err
	}
	if t.Hits, err = loadHits(root); err != nil {
		return t, err
	}
	findings, err := loadQueue(root, now)
	if err != nil {
		return t, err
	}
	t.Stats = detect.Measure(t.Rules, findings, t.Rings, t.Hits, t.Suppressions)
	t.Proposals = detect.Propose(t.Stats, t.Suppressions, t.Hits, now)
	return t, nil
}

func knownRule(rules []detect.Rule, id string) bool {
	for _, r := range rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

// setRing moves a rule. The caller has been authorised already.
func setRing(root, dir, rule string, ring detect.Ring, because, by string,
	kind audit.Kind) error {

	rules, err := rulesIn(rulesDir(root, dir))
	if err != nil {
		return err
	}
	corrs, err := correlationsIn(rulesDir(root, dir))
	if err != nil {
		return err
	}
	for _, c := range corrs {
		rules = append(rules, asRule(c))
	}
	if !knownRule(rules, rule) {
		return fmt.Errorf("there is no rule called %q; a ring set for a name "+
			"nothing answers to would sit there until a rule is given it",
			rule)
	}
	p := detect.Placement{Ring: ring, By: by, At: time.Now().UTC(),
		Because: strings.TrimSpace(because)}
	if err := p.Validate(kind); err != nil {
		return err
	}
	rings, err := loadRings(root)
	if err != nil {
		return err
	}
	from := detect.Live
	if old, ok := rings[rule]; ok {
		from = old.Ring
	}
	if ring == detect.Live {
		delete(rings, rule)
	} else {
		rings[rule] = p
	}
	if err := saveJSONFile(ringsPath(root), rings); err != nil {
		return err
	}
	return recordE(root, audit.Record{
		Action: "detect.ring", Resource: "/detections/" + rule,
		Outcome: audit.Success, Principal: by, Kind: kind,
		Verified: kind != audit.KindUnknown,
		Detail: map[string]string{"rule": rule, "from": string(from),
			"to": string(ring), "because": p.Because},
	})
}

// addSuppression records one. The caller has been authorised already.
func addSuppression(root, dir string, s detect.Suppression) (detect.Suppression,
	error) {

	rules, err := rulesIn(rulesDir(root, dir))
	if err != nil {
		return s, err
	}
	if !knownRule(rules, s.Rule) {
		return s, fmt.Errorf("there is no rule called %q", s.Rule)
	}
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return s, err
	}
	s.ID = hex.EncodeToString(raw)
	s.At = time.Now().UTC()
	if err := s.Validate(s.At); err != nil {
		return s, err
	}
	all, err := loadDetectSuppressions(root)
	if err != nil {
		return s, err
	}
	for _, old := range all {
		if old.Rule == s.Rule && old.Field == s.Field &&
			strings.EqualFold(old.Value, s.Value) && old.Active(s.At) {
			return s, fmt.Errorf("%s is already suppressed for %s until %s "+
				"(%s)", s.Rule, s.Value, old.Until.Format("2 Jan 2006"),
				old.ID)
		}
	}
	all = append(all, s)
	if err := saveJSONFile(suppressionsPath(root), all); err != nil {
		return s, err
	}
	return s, recordE(root, audit.Record{
		Action: "detect.suppress", Resource: "/detections/" + s.Rule,
		Outcome: audit.Success, Principal: s.By, Kind: s.Kind,
		Verified: s.Kind != audit.KindUnknown,
		Detail: map[string]string{"rule": s.Rule, "field": s.Field,
			"value": s.Value, "owner": s.Owner, "because": s.Because,
			"until": s.Until.Format(time.RFC3339), "suppression": s.ID},
	})
}

func removeSuppression(root, id, by string, kind audit.Kind) error {
	if kind == audit.KindAI {
		return fmt.Errorf("a model may not change what is suppressed")
	}
	all, err := loadDetectSuppressions(root)
	if err != nil {
		return err
	}
	var kept []detect.Suppression
	var gone *detect.Suppression
	for i := range all {
		if all[i].ID == id {
			gone = &all[i]
			continue
		}
		kept = append(kept, all[i])
	}
	if gone == nil {
		return fmt.Errorf("there is no suppression %q", id)
	}
	if err := saveJSONFile(suppressionsPath(root), kept); err != nil {
		return err
	}
	return recordE(root, audit.Record{
		Action: "detect.unsuppress", Resource: "/detections/" + gone.Rule,
		Outcome: audit.Success, Principal: by, Kind: kind,
		Verified: kind != audit.KindUnknown,
		Detail: map[string]string{"rule": gone.Rule, "value": gone.Value,
			"suppression": id},
	})
}

func detectStats(root string, args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	dir := fs.String("rules", "", "where the rules live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	t, err := loadTuning(root, *dir, time.Now().UTC())
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"rules": t.Stats, "proposals": t.Proposals,
		"suppressions": t.Suppressions}) {
		return nil
	}
	for _, s := range t.Stats {
		ring := ""
		if s.Ring != detect.Live {
			ring = "  " + yellow + string(s.Ring) + reset
		}
		w.Human("%s%s%s%s\n", bold, s.Rule, reset, ring)
		switch {
		case s.Findings == 0:
			w.Human("  %shas never fired. Either nothing it looks for has "+
				"happened, or it cannot fire on this estate's events%s\n",
				yellow, reset)
		default:
			w.Human("  %d finding(s), fired %d time(s), last %s\n", s.Findings,
				s.Fired, s.Last.Format("2 Jan 2006"))
			w.Human("  %d real, %d false, %d benign, %d undecided\n", s.Real,
				s.False, s.Benign, s.Undecided)
			if rate, low, high, enough := s.Useful(); enough {
				w.Human("  %.0f%% of verdicts were real (likely %.0f–%.0f%%)\n",
					rate*100, low*100, high*100)
			} else {
				w.Human("  %stoo few verdicts to say how good it is: %d of "+
					"the %d needed%s\n", dim, s.Decided(), detect.MinVerdicts,
					reset)
			}
		}
		if s.Suppressed > 0 {
			w.Human("  %s%d event(s) hidden by suppressions%s\n", dim,
				s.Suppressed, reset)
		}
	}
	if len(t.Proposals) > 0 {
		w.Human("\n%sworth considering%s\n", bold, reset)
		for _, p := range t.Proposals {
			w.Human("  %s: %s\n", p.What, p.Why)
		}
	}
	return nil
}

func detectRing(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("ring", flag.ContinueOnError)
	because := fs.String("because", "", "why (needed to leave the live ring)")
	dir := fs.String("rules", "", "where the rules live")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo detect ring RULE live|trial|off " +
			"--because \"…\"")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	if err := setRing(root, *dir, pos[0], detect.Ring(pos[1]), *because,
		caller.Name, caller.Kind); err != nil {
		return err
	}
	w.Human("%s is in the %s ring\n", pos[0], pos[1])
	return nil
}

func detectSuppress(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("suppress", flag.ContinueOnError)
	owner := fs.String("owner", "", "who is asked whether it is still true")
	until := fs.String("until", "", "when it stops, as 2026-12-31")
	because := fs.String("because", "", "why")
	dir := fs.String("rules", "", "where the rules live")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	field, value, ok := "", "", false
	if len(pos) == 2 {
		field, value, ok = strings.Cut(pos[1], "=")
	}
	if !ok {
		return fmt.Errorf("usage: quilzo detect suppress RULE FIELD=VALUE " +
			"--owner WHO --until 2026-12-31 --because \"…\"\n" +
			"  for example: actor=okta:svc-backup")
	}
	end, err := time.Parse("2006-01-02", *until)
	if err != nil {
		return fmt.Errorf("--until is a date like 2026-12-31; a suppression " +
			"always has one")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	s, err := addSuppression(root, *dir, detect.Suppression{Rule: pos[0],
		Field: field, Value: value, Owner: *owner, Because: *because,
		By: caller.Name, Kind: caller.Kind,
		// The end of the named day.
		Until: end.Add(24*time.Hour - time.Second)})
	if err != nil {
		return err
	}
	if w.JSON(s) {
		return nil
	}
	w.Human("%s will not raise findings where %s is %s, until %s  %s(%s)%s\n",
		s.Rule, s.Field, s.Value, s.Until.Format("2 Jan 2006"), dim, s.ID, reset)
	return nil
}

func detectUnsuppress(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo detect unsuppress ID")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	if err := removeSuppression(root, pos[0], caller.Name, caller.Kind); err != nil {
		return err
	}
	w.Human("removed\n")
	return nil
}

func detectSuppressions(root string) error {
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	sups, err := loadDetectSuppressions(root)
	if err != nil {
		return err
	}
	hits, err := loadHits(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"suppressions": sups, "hidden": hits}) {
		return nil
	}
	if len(sups) == 0 {
		w.Human("nothing is suppressed\n")
		return nil
	}
	now := time.Now().UTC()
	sort.Slice(sups, func(i, j int) bool { return sups[i].Until.Before(sups[j].Until) })
	for _, s := range sups {
		state := "until " + s.Until.Format("2 Jan 2006")
		if !s.Active(now) {
			state = red + "expired " + s.Until.Format("2 Jan 2006") + reset
		}
		w.Human("%s%s%s  %s where %s is %s  %s\n", bold, s.ID, reset, s.Rule,
			s.Field, s.Value, state)
		w.Human("  %s%s; owned by %s; has hidden %d event(s)%s\n", dim,
			s.Because, s.Owner, hits[s.ID], reset)
	}
	return nil
}
