// SPDX-FileCopyrightText: 2026 rsh1k
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

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/estate"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/workforce"
)

// The estate: what the company's tools say about its people and machines,
// joined, and where two of them disagree.
//
// `connect run NAME --save` keeps the latest read of each tool in estate/,
// one file of records and one saying which endpoints were read to the end.
// Only the latest: a copy of every staff list ever read is a second HR
// system nobody chose to run, and the history this needs later is of scores
// and findings, not of people's records. `estate build` joins them and puts
// what disagrees in the findings register, beside the detections.

func estateDir(root string) string { return filepath.Join(root, "estate") }

func snapshotPaths(root, source string) (records, meta string) {
	dir := estateDir(root)
	return filepath.Join(dir, source+".jsonl"), filepath.Join(dir, source+".json")
}

// saveSnapshot writes one tool's latest read.
func saveSnapshot(root string, m connector.Manifest,
	reads []connector.Read, at time.Time) error {

	snap := estate.Snapshot{Source: m.Name, At: at,
		Endpoints: map[string]estate.EndpointInfo{}}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range reads {
		e, _ := m.Endpoint(r.Endpoint)
		info := estate.EndpointInfo{Produces: estate.Kind(e.Produces),
			Complete: r.Err == nil && r.Result.Complete(),
			Records:  len(r.Result.Records)}
		if e.Each != nil {
			info.Of = e.Each.Of
		}
		snap.Endpoints[e.Name] = info
		if r.Err != nil {
			continue
		}
		for _, rec := range r.Result.Records {
			line := map[string]string{"_source": m.Name, "_endpoint": e.Name,
				"_produces": string(e.Produces)}
			for k, v := range rec {
				line[k] = v
			}
			if err := enc.Encode(line); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(estateDir(root), 0o700); err != nil {
		return err
	}
	records, meta := snapshotPaths(root, m.Name)
	// Personal data: owner-only, like the credentials beside it.
	if err := atomicfile.Write(records, buf.Bytes(), 0o600); err != nil {
		return err
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(meta, b, 0o600)
}

// loadSnapshots reads every tool's latest read.
func loadSnapshots(root string) ([]estate.Snapshot, error) {
	entries, err := os.ReadDir(estateDir(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []estate.Snapshot
	for _, en := range entries {
		name := en.Name()
		if en.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		source := strings.TrimSuffix(name, ".json")
		records, meta := snapshotPaths(root, source)
		b, rerr := os.ReadFile(meta)
		if rerr != nil {
			return nil, rerr
		}
		var s estate.Snapshot
		if uerr := json.Unmarshal(b, &s); uerr != nil {
			return nil, fmt.Errorf("%s: %w", meta, uerr)
		}
		if s.Source != source {
			return nil, fmt.Errorf("%s describes %q", meta, s.Source)
		}
		f, oerr := os.Open(records)
		if oerr != nil {
			return nil, oerr
		}
		s.Lines, err = estate.ReadLines(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", records, err)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out, nil
}

// confirmedLinks reads the merges people have confirmed.
func confirmedLinks(root string) ([]workforce.Link, error) {
	b, err := os.ReadFile(linksPath(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []workforce.Link
	for n, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var l workforce.Link
		if uerr := json.Unmarshal([]byte(line), &l); uerr != nil {
			return nil, fmt.Errorf("links.jsonl line %d: %w", n+1, uerr)
		}
		if verr := l.Validate(); verr != nil {
			return nil, fmt.Errorf("links.jsonl line %d: %w", n+1, verr)
		}
		out = append(out, l)
	}
	return out, nil
}

func cmdEstate(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	switch args[0] {
	case "show":
		return estateShow(root)
	case "build":
		return estateBuild(root, args[1:])
	default:
		return fmt.Errorf("unknown estate command %q; try show or build",
			args[0])
	}
}

// buildEstate is the shared first half of show and build.
func buildEstate(root string, now time.Time) (*estate.Estate,
	estate.Outcome, error) {

	snaps, err := loadSnapshots(root)
	if err != nil {
		return nil, estate.Outcome{}, err
	}
	if len(snaps) == 0 {
		return nil, estate.Outcome{}, fmt.Errorf(
			"no tool has been read into this site yet; quilzo connect run " +
				"NAME --save reads one")
	}
	links, err := confirmedLinks(root)
	if err != nil {
		return nil, estate.Outcome{}, err
	}
	e := estate.Build(snaps, links, now)
	return e, estate.Evaluate(e, now), nil
}

// estateSummary is what show and build report.
type estateSummary struct {
	Sources  map[string]string `json:"sources"`
	People   int               `json:"people"`
	Joined   int               `json:"joined"`
	Machines int               `json:"machines"`
	BySerial int               `json:"joined_by_serial"`
	Unplaced estate.Unplaced   `json:"unplaced"`
	Notes    []string          `json:"notes,omitempty"`
	Ran      []string          `json:"ran"`
	Skipped  map[string]string `json:"skipped,omitempty"`
	Found    int               `json:"found"`
	Opened   int               `json:"opened,omitempty"`
	Staled   int               `json:"staled,omitempty"`
}

func summariseEstate(e *estate.Estate, o estate.Outcome) estateSummary {
	s := estateSummary{Sources: map[string]string{}, Unplaced: e.Unplaced,
		Notes: e.Notes, Ran: o.Ran, Skipped: o.Skipped,
		Found: len(o.Findings), People: len(e.People),
		Machines: len(e.Machines)}
	for name, snap := range e.Sources {
		var partial []string
		for ep, info := range snap.Endpoints {
			if !info.Complete {
				partial = append(partial, ep)
			}
		}
		sort.Strings(partial)
		state := "read " + snap.At.Format("2006-01-02 15:04 UTC")
		if len(partial) > 0 {
			state += ", incomplete: " + strings.Join(partial, ", ")
		}
		s.Sources[name] = state
	}
	for _, p := range e.People {
		if len(p.Sources) > 1 {
			s.Joined++
		}
	}
	for _, m := range e.Machines {
		if len(m.Sources) > 1 {
			s.BySerial++
		}
	}
	return s
}

func printSummary(s estateSummary, wrote bool) {
	for _, name := range sortedKeysOf(s.Sources) {
		colour := green
		if strings.Contains(s.Sources[name], "incomplete") {
			colour = yellow
		}
		w.Human("%s%s%s  %s%s%s\n", bold, name, reset, colour, s.Sources[name],
			reset)
	}
	w.Human("\n%d people, %d of them known to more than one tool\n", s.People,
		s.Joined)
	w.Human("%d machines, %d of them known to more than one tool by serial\n",
		s.Machines, s.BySerial)
	u := s.Unplaced
	if u.Training+u.Phishing+u.Software+u.Vulns+u.Posture > 0 {
		w.Human("%snot attached to anyone or anything: %d training, %d "+
			"phishing, %d software, %d vulnerability, %d posture record(s)%s\n",
			yellow, u.Training, u.Phishing, u.Software, u.Vulns, u.Posture,
			reset)
	}
	for _, n := range s.Notes {
		w.Human("  %s%s%s\n", dim, n, reset)
	}
	w.Human("\nchecked: %s\n", strings.Join(s.Ran, ", "))
	for _, id := range sortedKeysOf(s.Skipped) {
		w.Human("  %snot checked, %s: %s%s\n", yellow, id, s.Skipped[id], reset)
	}
	if wrote {
		w.Human("\n%d finding(s), %d new, %d no longer reported (stale)\n",
			s.Found, s.Opened, s.Staled)
	} else {
		w.Human("\n%d finding(s) would be raised; quilzo estate build records "+
			"them\n", s.Found)
	}
}

func sortedKeysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func estateShow(root string) error {
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	e, o, err := buildEstate(root, time.Now().UTC())
	if err != nil {
		return err
	}
	s := summariseEstate(e, o)
	if w.JSON(s) {
		return nil
	}
	printSummary(s, false)
	return nil
}

func estateBuild(root string, args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	now := time.Now().UTC()
	e, o, err := buildEstate(root, now)
	if err != nil {
		return err
	}

	path := findingsPath(root)
	unlock, err := finding.Lock(path)
	if err != nil {
		return err
	}
	defer unlock()
	reg, cursors, err := finding.Load(path)
	if err != nil {
		return err
	}
	s := summariseEstate(e, o)
	reported := map[string]bool{}
	for _, f := range o.Findings {
		reported[f.ID] = true
		if _, isNew := reg.Record(f, now); isNew {
			s.Opened++
		}
	}
	ran := map[string]bool{}
	for _, id := range o.Ran {
		ran["estate/"+id] = true
	}
	// Stale only what this round could see: its check ran, and every tool
	// the finding rested on was read to the end this time.
	staled := reg.Unreported(func(f finding.Finding) bool {
		if !ran[f.Source] {
			return false
		}
		tools := []string{f.Entity.Issuer}
		if len(f.Evidence) > 0 {
			tools = append(tools, strings.Split(f.Evidence[0].Source, ",")...)
		}
		for _, t := range tools {
			snap, ok := e.Sources[t]
			if !ok {
				return false
			}
			for _, info := range snap.Endpoints {
				if !info.Complete {
					return false
				}
			}
		}
		return true
	}, reported)
	s.Staled = len(staled)
	if err := finding.Save(path, reg, cursors); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "estate.build", Resource: "/findings", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"sources":  strings.Join(sortedKeysOf(s.Sources), ","),
			"people":   fmt.Sprint(s.People),
			"machines": fmt.Sprint(s.Machines),
			"found":    fmt.Sprint(s.Found), "opened": fmt.Sprint(s.Opened),
			"staled":  fmt.Sprint(s.Staled),
			"skipped": strings.Join(sortedKeysOf(s.Skipped), ","),
		},
	})
	if w.JSON(s) {
		return nil
	}
	printSummary(s, true)
	return nil
}
