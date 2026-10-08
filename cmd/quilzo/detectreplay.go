// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// The corpus: events people have already ruled on, replayed against every
// rule on every change.
//
// `detect replay` needs no store and no network, like `detect test`, so it
// runs in CI beside it. `detect learn` is how the corpus grows: it takes a
// finding somebody closed and copies the event behind it out of the event
// store, labelled by the verdict.
//
// The corpus lives with the rules, in corpus.jsonl, and is reviewed like
// them. It holds real events — real account names — so it belongs in the
// same repository the rules are in and nowhere more public.

// MaxCorpusLine bounds one entry.
const MaxCorpusLine = 256 << 10

func corpusPath(root, dir, given string) string {
	if given != "" {
		return given
	}
	return filepath.Join(rulesDir(root, dir), "corpus.jsonl")
}

func loadCorpus(path string) ([]detect.Labelled, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []detect.Labelled
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), MaxCorpusLine)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var l detect.Labelled
		if uerr := json.Unmarshal([]byte(line), &l); uerr != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, n, uerr)
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

func detectReplay(root string, args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	dir := fs.String("rules", "", "where the rules live")
	corpusAt := fs.String("corpus", "", "the corpus (default: corpus.jsonl beside the rules)")
	strict := fs.Bool("strict", false,
		"also fail on a false positive that is known and not yet fixed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rules, err := rulesIn(rulesDir(root, *dir))
	if err != nil {
		return err
	}
	for _, r := range rules {
		if verr := r.Validate(); verr != nil {
			return fmt.Errorf("%s cannot be replayed: %w", r.ID, verr)
		}
	}
	path := corpusPath(root, *dir, *corpusAt)
	corpus, err := loadCorpus(path)
	if err != nil {
		return err
	}
	if len(corpus) == 0 {
		return fmt.Errorf("%s holds nothing, so a replay would pass by "+
			"checking nothing. quilzo detect learn FINDING adds the event "+
			"behind a finding somebody has closed", path)
	}
	outs, err := detect.Replay(rules, corpus)
	if err != nil {
		return err
	}
	var wrong, missed, known, mended int
	for _, o := range outs {
		wrong += len(o.Wrong)
		missed += len(o.Missed)
		known += len(o.Known)
		mended += len(o.Mended)
	}
	failed := wrong+missed > 0 || (*strict && known > 0)
	if w.JSON(map[string]any{"rules": len(rules), "entries": len(corpus),
		"outcomes": outs, "ok": !failed}) {
		if failed {
			return fmt.Errorf("the rules do not agree with the corpus")
		}
		return nil
	}
	for _, o := range outs {
		for _, n := range o.Wrong {
			w.Human("  %s%s%s  raised on %q, which was closed as a false "+
				"positive\n", red, o.Rule, reset, n)
		}
		for _, n := range o.Missed {
			w.Human("  %s%s%s  did not fire on %q, which was real\n", red,
				o.Rule, reset, n)
		}
		for _, n := range o.Known {
			w.Human("  %s%s%s  still raises on %q (known, not yet fixed)\n",
				yellow, o.Rule, reset, n)
		}
		for _, n := range o.Mended {
			w.Human("  %s%s%s  no longer raises on %q: take the pending "+
				"mark off it in %s, and it guards against coming back\n",
				green, o.Rule, reset, n, path)
		}
	}
	if failed {
		return fmt.Errorf("%d rule(s) over %d entr(ies): %d wrongly raised, "+
			"%d missed, %d known and not fixed", len(rules), len(corpus),
			wrong, missed, known)
	}
	w.Human("%s%d rule(s) over %d entr(ies), all agreeing%s", bold,
		len(rules), len(corpus), reset)
	if known > 0 {
		w.Human("  %s(%d known false positive(s) not yet fixed)%s", dim, known,
			reset)
	}
	w.Human("\n")
	return nil
}

// detectLearn copies the event behind a decided finding into the corpus.
func detectLearn(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("learn", flag.ContinueOnError)
	dir := fs.String("rules", "", "where the rules live")
	corpusAt := fs.String("corpus", "", "the corpus to add to")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo detect learn FINDING-ID")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("a model may not add to the corpus: the corpus " +
			"decides what the rules are allowed to stop catching")
	}
	now := time.Now().UTC()
	q, err := loadQueue(root, now)
	if err != nil {
		return err
	}
	var f *finding.Finding
	for i := range q {
		if q[i].ID == pos[0] {
			f = &q[i]
		}
	}
	if f == nil {
		return fmt.Errorf("there is no finding %q", pos[0])
	}
	if f.Kind != finding.FromDetection {
		return fmt.Errorf("%s was not raised by a detection rule", f.ID)
	}
	entry := detect.Labelled{}
	switch f.State {
	case finding.FalsePositive:
		// Known to be wrong, and the rule still fires on it today.
		entry.Pending = true
	case finding.Triaged, finding.Fixed, finding.Accepted, finding.Benign:
		// Real — and benign is real too: the rule was right. What quietens
		// a benign match is a suppression, not a rule that stops seeing it.
		entry.Expect = []string{f.Source}
	default:
		return fmt.Errorf("%s is %s: nobody has ruled on it yet, so there "+
			"is no verdict to learn from", f.ID, f.State)
	}
	rules, err := rulesIn(rulesDir(root, *dir))
	if err != nil {
		return err
	}
	var rule *detect.Rule
	for i := range rules {
		if rules[i].ID == f.Source {
			rule = &rules[i]
		}
	}
	if rule == nil {
		return fmt.Errorf("the rule %s that raised it is not in %s", f.Source,
			rulesDir(root, *dir))
	}

	// The event itself, from the event store: the first one this rule
	// matched for this entity around when the finding was seen.
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	defer sp.Close()
	var found *telemetry.Event
	err = sp.Range(f.First.Add(-48*time.Hour), f.Last.Add(48*time.Hour),
		func(e telemetry.Event) error {
			if found == nil && e.Actor == f.Entity && rule.Matches(e) {
				ev := e
				found = &ev
			}
			return nil
		})
	if err != nil {
		return err
	}
	if found == nil {
		return fmt.Errorf("the event behind %s is no longer in the event "+
			"store, so there is nothing to copy. It may have aged out", f.ID)
	}
	entry.Event = *found
	entry.Name = fmt.Sprintf("%s %s, closed %s", f.Entity, found.Time.UTC().
		Format("2006-01-02"), f.State)
	entry.From = fmt.Sprintf("finding %s, rule %s, closed %s", f.ID, f.Source,
		f.State)

	path := corpusPath(root, *dir, *corpusAt)
	existing, err := loadCorpus(path)
	if err != nil {
		return err
	}
	for _, l := range existing {
		if l.From == entry.From {
			return fmt.Errorf("%s is already in the corpus", f.ID)
		}
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := out.Write(append(line, '\n')); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "detect.learn", Resource: "/detections/" + f.Source,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified,
		Detail: map[string]string{"finding": f.ID, "rule": f.Source,
			"verdict": string(f.State)},
	})
	if w.JSON(entry) {
		return nil
	}
	if entry.Pending {
		w.Human("added to %s as a known false positive. %s still raises on "+
			"it; when the rule is fixed, quilzo detect replay says so\n", path,
			f.Source)
	} else {
		w.Human("added to %s: %s must keep firing on it\n", path, f.Source)
	}
	w.Human("  %sthe corpus holds real events and real account names; keep "+
		"it where the rules are kept%s\n", dim, reset)
	return nil
}
