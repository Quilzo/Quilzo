// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/indicator"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Indicators: what somebody else has said is bad, looked for in what is
// already held and in what arrives.
//
// `intel import` reads a STIX bundle or a plain list from a file. It opens
// no connection: the feed is fetched by whatever the operator trusts to
// fetch things. What it took, what it refused and why are all printed,
// because an import that dropped the private addresses silently looks the
// same as a feed that had none.
//
// The first thing done with a new indicator is to read the events already
// stored for it. That is the retro-hunt, and it is not a separate step
// somebody has to remember: a report published today is about a campaign
// that ran last month.
//
// Afterwards `detect run` checks each new event against everything still
// believed. The two never read the same event for the same indicator, so a
// finding's count is how many events carried it.

// MaxIndicators bounds how many are held.
const MaxIndicators = 500_000

// intelCursor is how far arriving events have been checked.
const intelCursor = "intel"

func intelPath(root string) string {
	return filepath.Join(root, "intel", "indicators.jsonl")
}

func loadIndicators(root string) (*indicator.Set, error) {
	var all []indicator.Indicator
	err := loadJSONL(intelPath(root), func(b []byte) error {
		var i indicator.Indicator
		if err := json.Unmarshal(b, &i); err != nil {
			return err
		}
		all = append(all, i)
		return nil
	})
	return indicator.NewSet(all), err
}

func saveIndicators(root string, s *indicator.Set) error {
	return writeJSONL(intelPath(root), s.All())
}

// intelSource is the source a finding from an indicator carries.
func intelSource(id string) string { return "intel/" + id }

// intelFinding is one event carrying one indicator, as a finding.
func intelFinding(h indicator.Hit, e telemetry.Event) finding.Finding {
	about := e.Actor
	if about.Zero() {
		about = e.Device
	}
	sev := telemetry.SeverityMedium
	if len(h.Indicator.Sources) > 1 {
		// Two feeds saying so independently is more than one saying it.
		sev = telemetry.SeverityHigh
	}
	title := fmt.Sprintf("%s %s seen, which %s lists as bad",
		h.Indicator.Kind, h.Indicator.Value,
		strings.Join(h.Indicator.Sources, " and "))
	if len(title) > 300 {
		title = title[:300]
	}
	return finding.Finding{Kind: finding.FromDetection, Title: title,
		Source: intelSource(h.Indicator.ID), Entity: about, Severity: sev,
		State: finding.Open,
		Evidence: []finding.Evidence{{At: e.Time, What: e.Message,
			Source: e.Source, Ref: h.Indicator.ID,
			// Always: log text is written by whoever can reach the log.
			Tainted: true}}}
}

// intelSweep reads events for a set of indicators and records what it
// finds. from and to bound arrival; zero to means no upper bound. It
// returns events read, hits, findings opened and the latest arrival seen.
func intelSweep(sp *spool.Spool, set *indicator.Set, reg *finding.Register,
	from, to time.Time) (events, hits, opened int, through time.Time,
	err error) {

	err = sp.Range(from, to, func(e telemetry.Event) error {
		events++
		if e.Received.After(through) {
			through = e.Received
		}
		for _, h := range set.Match(e) {
			hits++
			if _, isNew := reg.Record(intelFinding(h, e), e.Time); isNew {
				opened++
			}
		}
		return nil
	})
	return
}

// live is the part of a set still believed.
func liveIndicators(s *indicator.Set, now time.Time) *indicator.Set {
	var keep []indicator.Indicator
	for _, i := range s.All() {
		if i.Live(now) {
			keep = append(keep, i)
		}
	}
	return indicator.NewSet(keep)
}

// intelCatchUp checks events that arrived since the last check against
// everything still believed, and moves the cursor. Called with the
// register locked and loaded.
func intelCatchUp(sp *spool.Spool, set *indicator.Set, reg *finding.Register,
	cursors map[string]time.Time, now time.Time) (events, hits, opened int,
	err error) {

	from := cursors[intelCursor]
	if !from.IsZero() {
		from = from.Add(time.Nanosecond)
	}
	var through time.Time
	events, hits, opened, through, err = intelSweep(sp, liveIndicators(set, now),
		reg, from, time.Time{})
	if err == nil && !through.IsZero() {
		cursors[intelCursor] = through
	}
	return
}

// intelResult is what adding indicators did.
type intelResult struct {
	indicator.Report
	// Events is how many stored events were read for the new ones, Hits how
	// many carried one, and Opened the findings that made.
	Events int `json:"events_read"`
	Hits   int `json:"hits"`
	Opened int `json:"findings_opened"`
	// Held is how many indicators are held afterwards.
	Held int `json:"held"`
	// NoEvents says nothing has ever been stored to look through.
	NoEvents bool `json:"no_events,omitempty"`
}

// takeIndicators stores new indicators and looks back through the events
// for them. The one place indicators are added, from a file or a form.
func takeIndicators(root string, caller *Caller, in []indicator.Indicator,
	rep indicator.Report, now time.Time) (intelResult, error) {

	res := intelResult{Report: rep}
	if caller.Kind == audit.KindAI {
		return res, fmt.Errorf("an indicator is added by a person. A model " +
			"that could add one could raise a finding about anybody, by " +
			"listing whatever they connect to")
	}
	path := findingsPath(root)
	unlock, err := finding.Lock(path)
	if err != nil {
		return res, err
	}
	defer unlock()
	set, err := loadIndicators(root)
	if err != nil {
		return res, err
	}
	var fresh []indicator.Indicator
	for _, i := range in {
		if set.Add(i) {
			fresh = append(fresh, i)
			res.Taken++
		} else {
			res.Known++
		}
	}
	if set.Len() > MaxIndicators {
		return res, fmt.Errorf("that would hold %d indicators; the most "+
			"held is %d. Remove the ones that have lapsed", set.Len(),
			MaxIndicators)
	}
	res.Held = set.Len()

	reg, cursors, err := finding.Load(path)
	if err != nil {
		return res, err
	}
	if _, serr := os.Stat(spoolDir(root)); serr != nil {
		res.NoEvents = true
	} else if len(fresh) > 0 {
		sp, oerr := openSpool(root, spool.Options{})
		if oerr != nil {
			return res, oerr
		}
		defer sp.Close()
		// First bring the forward check up to now with what was already
		// held, so the look back below and the next run do not both read
		// the same event for the same indicator.
		old := indicator.NewSet(nil)
		known := map[string]bool{}
		for _, i := range fresh {
			known[i.ID] = true
		}
		for _, i := range set.All() {
			if !known[i.ID] {
				old.Add(i)
			}
		}
		if _, _, _, err := intelCatchUp(sp, old, reg, cursors, now); err != nil {
			return res, err
		}
		upTo := cursors[intelCursor]
		if !upTo.IsZero() {
			upTo = upTo.Add(time.Nanosecond)
		}
		res.Events, res.Hits, res.Opened, _, err = intelSweep(sp,
			indicator.NewSet(fresh), reg, time.Time{}, upTo)
		if err != nil {
			return res, err
		}
	}
	// The indicators before the findings: a finding whose indicator was
	// not stored could never be explained.
	if err := saveIndicators(root, set); err != nil {
		return res, err
	}
	if err := finding.Save(path, reg, cursors); err != nil {
		return res, err
	}
	return res, recordE(root, audit.Record{Action: "intel.added",
		Resource: "/intel", Outcome: audit.Success, Principal: caller.Name,
		Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"taken": fmt.Sprint(res.Taken),
			"known": fmt.Sprint(res.Known), "refused": fmt.Sprint(rep.Never()),
			"unread": fmt.Sprint(rep.Unread), "hits": fmt.Sprint(res.Hits),
			"opened": fmt.Sprint(res.Opened)}})
}

func removeIndicator(root string, caller *Caller, id string) error {
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("an indicator is removed by a person")
	}
	unlock, err := finding.Lock(findingsPath(root))
	if err != nil {
		return err
	}
	defer unlock()
	set, err := loadIndicators(root)
	if err != nil {
		return err
	}
	if !set.Remove(id) {
		return fmt.Errorf("there is no indicator %s", id)
	}
	if err := saveIndicators(root, set); err != nil {
		return err
	}
	return recordE(root, audit.Record{Action: "intel.removed",
		Resource: "/intel/" + id, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified})
}

func cmdIntel(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "import":
		return intelImport(root, args[1:])
	case "add":
		return intelAdd(root, args[1:])
	case "list":
		return intelList(root, args[1:])
	case "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: quilzo intel remove ID")
		}
		caller := resolveCaller(root, flagToken)
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return err
		}
		if err := removeIndicator(root, caller, args[1]); err != nil {
			return err
		}
		if !w.JSON(map[string]any{"removed": args[1]}) {
			w.Human("removed. Findings it already raised stay in the queue\n")
		}
		return nil
	default:
		return fmt.Errorf("unknown intel command %q; try import, add, list "+
			"or remove", args[0])
	}
}

func printIntelResult(res intelResult) {
	w.Human("%s%d indicator(s) read%s: %d new, %d already held\n", bold,
		res.Read, reset, res.Taken, res.Known)
	if n := res.Never(); n > 0 {
		w.Human("  %s%d refused as things that are never indicators:%s\n",
			yellow, n, reset)
		var reasons []string
		for r := range res.Refused {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		for _, r := range reasons {
			w.Human("    %s%d × %s%s\n", dim, res.Refused[r], r, reset)
		}
		for _, ex := range res.Examples {
			w.Human("    %s%s%s\n", dim, ex, reset)
		}
	}
	if res.Unread > 0 {
		w.Human("  %s%d pattern(s) say more than \"this value\" — AND, a "+
			"sequence, a range, another pattern language — and were not "+
			"read. They are not covered%s\n", yellow, res.Unread, reset)
	}
	if res.Lapsed > 0 {
		w.Human("  %s%d had lapsed or been revoked by the feed%s\n", dim,
			res.Lapsed, reset)
	}
	switch {
	case res.NoEvents:
		w.Human("  %sno events are stored, so there was nothing to look "+
			"back through%s\n", dim, reset)
	case res.Taken > 0:
		colour := dim
		if res.Hits > 0 {
			colour = red
		}
		w.Human("  %slooked back through %d stored event(s): %d carried "+
			"one, %d new finding(s)%s\n", colour, res.Events, res.Hits,
			res.Opened, reset)
	}
}

func intelImport(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	source := fs.String("source", "", "who says these are bad")
	format := fs.String("format", "", "stix or list; worked out from the "+
		"file when not given")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo intel import FILE --source NAME")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	raw, err := readBounded(pos[0], MaxVulnFile)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	kind := *format
	if kind == "" {
		kind = "list"
		if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
			kind = "stix"
		}
	}
	var in []indicator.Indicator
	var rep indicator.Report
	switch kind {
	case "stix":
		in, rep, err = indicator.ReadSTIX(raw, *source, now)
	case "list":
		in, rep, err = indicator.ReadList(raw, *source, now)
	default:
		return fmt.Errorf("the formats are stix and list")
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(*source) == "" {
		return fmt.Errorf("say whose list this is with --source. An " +
			"indicator is somebody's claim, and one nobody made cannot be " +
			"weighed or withdrawn")
	}
	if len(in) == 0 {
		if w.JSON(intelResult{Report: rep}) {
			return nil
		}
		printIntelResult(intelResult{Report: rep})
		return fmt.Errorf("nothing in %s could be taken", pos[0])
	}
	res, err := takeIndicators(root, caller, in, rep, now)
	if err != nil {
		return err
	}
	if w.JSON(res) {
		return nil
	}
	printIntelResult(res)
	return nil
}

func intelAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	source := fs.String("source", "", "who says it is bad")
	kind := fs.String("kind", "", "ip, domain, url, hash or email; worked "+
		"out from the value when not given")
	until := fs.String("until", "", "when it stops being believed, as 2026-12-31")
	note := fs.String("note", "", "what it is said to be")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo intel add VALUE --source NAME")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	now := time.Now().UTC()
	i, err := makeIndicator(*kind, pos[0], *source, *note, *until, now)
	if err != nil {
		return err
	}
	res, err := takeIndicators(root, caller, []indicator.Indicator{i},
		indicator.Report{Read: 1}, now)
	if err != nil {
		return err
	}
	if w.JSON(res) {
		return nil
	}
	printIntelResult(res)
	return nil
}

// makeIndicator builds one from what a person typed.
func makeIndicator(kind, value, source, note, until string,
	now time.Time) (indicator.Indicator, error) {

	k := indicator.Kind(strings.TrimSpace(kind))
	if k == "" {
		guessed, ok := indicator.Guess(value)
		if !ok {
			return indicator.Indicator{}, fmt.Errorf("%q is not an "+
				"address, a domain, a URL, a digest or an email address",
				value)
		}
		k = guessed
	}
	var end time.Time
	if strings.TrimSpace(until) != "" {
		d, err := time.Parse("2006-01-02", strings.TrimSpace(until))
		if err != nil {
			return indicator.Indicator{}, fmt.Errorf("the end is a date " +
				"like 2026-12-31")
		}
		end = d.UTC().Add(24*time.Hour - time.Second)
	}
	return indicator.New(k, value, source, note, time.Time{}, end, now)
}

// intelHits counts, per indicator, the findings it raised and what people
// made of them.
type intelHits struct {
	Findings, Real, False int
	Last                  time.Time
}

func countIntelHits(q []finding.Finding) map[string]intelHits {
	out := map[string]intelHits{}
	for _, f := range q {
		id, ok := strings.CutPrefix(f.Source, "intel/")
		if !ok || f.Kind != finding.FromDetection {
			continue
		}
		h := out[id]
		h.Findings++
		switch f.State {
		case finding.FalsePositive, finding.Benign:
			h.False++
		case finding.Triaged, finding.Accepted, finding.Fixed:
			h.Real++
		}
		if f.Last.After(h.Last) {
			h.Last = f.Last
		}
		out[id] = h
	}
	return out
}

func intelList(root string, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	top := fs.Int("top", 50, "how many to show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	set, err := loadIndicators(root)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	all := set.All()
	q, err := loadQueue(root, now)
	if err != nil {
		return err
	}
	hits := countIntelHits(q)
	lapsed := 0
	for _, i := range all {
		if !i.Live(now) {
			lapsed++
		}
	}
	shown := all
	if len(shown) > *top {
		shown = shown[:*top]
	}
	if w.JSON(map[string]any{"held": len(all), "lapsed": lapsed,
		"indicators": shown}) {
		return nil
	}
	if len(all) == 0 {
		w.Human("No indicators are held. quilzo intel import FILE --source NAME\n")
		return nil
	}
	w.Human("%s%d indicator(s)%s, %d lapsed and matching nothing\n\n", bold,
		len(all), reset, lapsed)
	for _, i := range shown {
		state := "until " + i.Until.Format("2006-01-02")
		if !i.Live(now) {
			state = "lapsed " + i.Until.Format("2006-01-02")
		}
		w.Human("  %s%s%s  %-6s %s  %s%s, %s%s\n", dim, i.ID, reset, i.Kind,
			i.Value, dim, strings.Join(i.Sources, "+"), state, reset)
		if h := hits[i.ID]; h.Findings > 0 {
			w.Human("      %s%d finding(s), %d ruled false%s\n", yellow,
				h.Findings, h.False, reset)
		}
	}
	if len(all) > len(shown) {
		w.Human("\n  %s%d more%s\n", dim, len(all)-len(shown), reset)
	}
	return nil
}
