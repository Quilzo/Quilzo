// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"crypto/sha256"
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
	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/source"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/telemetry"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// Collection: the part between a platform's log and the event store.
//
// There were two halves and nothing joining them. internal/connector could
// fetch records from a tool, incrementally and within its rate limits.
// internal/source could turn a platform's record into an event and say
// which field went missing when a vendor renamed one. Nothing fetched a log
// and mapped it, so the event store held whatever somebody had exported and
// added by hand, and a detection across Okta and GitHub had nothing from
// either to read.
//
// `collect run` is the join. For every installed connector endpoint that
// produces events, it finds the mapping of the same name, reads what is new
// since the last read, maps each record, and stores what mapped. What did
// not map is counted and the field that was missing is named: a source
// whose events stopped mapping is a source that went quiet, and the two
// must not look alike.
//
// `collect file` is the same for logs that arrive as files — a cloud trail
// delivered to a bucket, an application's own log — and `source add` is how
// an application of yours gets a mapping.

// collectStatus is what the last read of one source did.
type collectStatus struct {
	Source string    `json:"source"`
	At     time.Time `json:"at"`
	// Records is how many the tool returned, Stored how many became events,
	// Known how many were already stored, and Missed how many did not map.
	Records int `json:"records"`
	Stored  int `json:"stored"`
	Known   int `json:"known"`
	Missed  int `json:"missed"`
	// Field is what was most often missing, when anything was.
	Field string `json:"field,omitempty"`
	// Gap says the read may not have seen everything, and why.
	Gap string `json:"gap,omitempty"`
	// Error is why the read failed, when it did.
	Error string `json:"error,omitempty"`
	// Seen is the digests of the most recent records, so one returned
	// again on the next read is not stored twice.
	Seen []string `json:"seen,omitempty"`
	// learned says the read taught the alias table something.
	learned bool
}

// maxSeen is how many recent record digests are remembered per source.
const maxSeen = 5000

func collectDir(root string) string { return filepath.Join(root, "collect") }

func collectStatusPath(root string) string {
	return filepath.Join(collectDir(root), "status.json")
}

func loadCollectStatus(root string) (map[string]collectStatus, error) {
	out := map[string]collectStatus{}
	b, err := os.ReadFile(collectStatusPath(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return out, json.Unmarshal(b, &out)
}

func saveCollectStatus(root string, s map[string]collectStatus) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(collectDir(root), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(collectStatusPath(root), b, 0o600)
}

// ---- mappings ---------------------------------------------------------------

func sourcesDir(root string) string { return filepath.Join(root, "sources") }

// allSources is the built-in mappings and the store's own. One of the
// store's that does not validate, or that takes a built-in's name, is an
// error: a mapping quietly ignored is a source quietly not collected.
func allSources(root string) ([]source.Source, error) {
	out := source.Known()
	taken := map[string]bool{}
	for _, s := range out {
		taken[strings.ToLower(s.Issuer+"/"+s.Stream)] = true
	}
	entries, err := os.ReadDir(sourcesDir(root))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := readBounded(filepath.Join(sourcesDir(root), e.Name()), 256<<10)
		if err != nil {
			return nil, err
		}
		var s source.Source
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if err := s.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		key := strings.ToLower(s.Issuer + "/" + s.Stream)
		if taken[key] {
			return nil, fmt.Errorf("%s defines %s, which already has a "+
				"mapping", e.Name(), key)
		}
		taken[key] = true
		out = append(out, s)
	}
	return out, nil
}

func findSource(root, name string) (source.Source, error) {
	all, err := allSources(root)
	if err != nil {
		return source.Source{}, err
	}
	for _, s := range all {
		if strings.EqualFold(s.Issuer+"/"+s.Stream, name) {
			return s, nil
		}
	}
	return source.Source{}, fmt.Errorf("there is no mapping for %q; "+
		"quilzo source list shows them", name)
}

var sourceFileName = func(s source.Source) string {
	return strings.ToLower(s.Issuer) + "-" + strings.ToLower(s.Stream) + ".json"
}

// sourceAdd installs a mapping for an application of the organisation's
// own, after showing it can map the records it is given.
func sourceAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	sample := fs.String("sample", "", "real records the mapping must map")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || *sample == "" {
		return fmt.Errorf("usage: quilzo source add MAPPING.json --sample " +
			"RECORDS.json\n  a mapping is only installed once it has " +
			"mapped real records")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	b, err := readBounded(pos[0], 256<<10)
	if err != nil {
		return err
	}
	var s source.Source
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("this is not a mapping: %w", err)
	}
	if err := s.Validate(); err != nil {
		return err
	}
	for _, part := range []string{s.Issuer, s.Stream} {
		if !nameShape(part) {
			return fmt.Errorf("%q: an issuer and a stream are lower-case "+
				"letters, digits and hyphens", part)
		}
	}
	if _, clash := source.Find(s.Issuer, s.Stream); clash {
		return fmt.Errorf("%s/%s is a built-in mapping", s.Issuer, s.Stream)
	}
	docs, err := readRecords(*sample)
	if err != nil {
		return err
	}
	batch, err := source.Check(s, docs)
	if err != nil {
		return err
	}
	if batch.Mapped == 0 {
		field, n := batch.Worst()
		return fmt.Errorf("the mapping mapped none of %d record(s); %s was "+
			"missing from %d. A mapping that maps nothing collects nothing, "+
			"and looks like a quiet source", batch.Records, field, n)
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sourcesDir(root), 0o700); err != nil {
		return err
	}
	if err := atomicfile.Write(filepath.Join(sourcesDir(root),
		sourceFileName(s)), out, 0o600); err != nil {
		return err
	}
	record(root, audit.Record{Action: "source.added",
		Resource: "/sources/" + s.Issuer + "/" + s.Stream,
		Outcome:  audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified})
	if !w.JSON(map[string]any{"source": s.Issuer + "/" + s.Stream,
		"mapped": batch.Mapped, "records": batch.Records}) {
		w.Human("%s%s/%s%s is installed: it mapped %d of %d sample "+
			"record(s)\n", bold, s.Issuer, s.Stream, reset, batch.Mapped,
			batch.Records)
		w.Human("  %sstore its events with quilzo collect file %s/%s FILE%s\n",
			dim, s.Issuer, s.Stream, reset)
	}
	return nil
}

func nameShape(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// readRecords reads raw records from a file: a JSON array, one object per
// line, or an object with the array under Records or records or items,
// which is how cloud trails and several APIs deliver a page.
func readRecords(path string) ([]any, error) {
	b, err := readBounded(path, MaxVulnFile)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(b))
	if strings.HasPrefix(trimmed, "[") {
		var out []any
		return out, json.Unmarshal(b, &out)
	}
	if strings.HasPrefix(trimmed, "{") {
		var doc map[string]any
		if json.Unmarshal(b, &doc) == nil {
			for _, k := range []string{"Records", "records", "items", "value"} {
				if list, ok := doc[k].([]any); ok {
					return list, nil
				}
			}
			if !strings.Contains(trimmed, "\n{") {
				return []any{doc}, nil
			}
		}
	}
	var out []any
	err = loadJSONL(path, func(line []byte) error {
		var v any
		if err := json.Unmarshal(line, &v); err != nil {
			return err
		}
		out = append(out, v)
		return nil
	})
	return out, err
}

// ---- the join ---------------------------------------------------------------

// unflatten turns a connector's mapped record — flat, with dotted names —
// back into the nested shape a mapping's paths walk.
func unflatten(rec map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range rec {
		if strings.HasPrefix(k, "_") || v == "" {
			continue
		}
		at := out
		parts := strings.Split(k, ".")
		for i, p := range parts {
			if i == len(parts)-1 {
				at[p] = v
				break
			}
			next, ok := at[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				at[p] = next
			}
			at = next
		}
	}
	return out
}

func digestOf(doc any) string {
	b, _ := json.Marshal(doc)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:10])
}

// storeRecords maps raw records and appends what maps, leaving out what was
// already stored. It fills the counts of st.
func storeRecords(sp *spool.Spool, s source.Source, docs []any,
	st *collectStatus, aliases map[string]alias, now time.Time) error {

	for _, e := range mapRecords(s, docs, st, aliases, now) {
		if _, err := sp.Append(e); err != nil {
			return err
		}
		st.Stored++
	}
	return nil
}

// mapRecords is storeRecords without the store: the events that are new and
// map, with st's counts and remembered digests brought up to date.
func mapRecords(s source.Source, docs []any, st *collectStatus,
	aliases map[string]alias, now time.Time) []telemetry.Event {

	seen := map[string]bool{}
	for _, d := range st.Seen {
		seen[d] = true
	}
	missing := map[string]int{}
	var out []telemetry.Event
	for _, doc := range docs {
		st.Records++
		d := digestOf(doc)
		if seen[d] {
			st.Known++
			continue
		}
		e, missed := s.Map(doc)
		if len(missed) > 0 {
			st.Missed++
			for _, m := range missed {
				missing[m.Path]++
			}
			continue
		}
		e.Received = now
		if personOf(&e, aliases, now) {
			st.learned = true
		}
		if err := e.Validate(); err != nil {
			st.Missed++
			missing["(not a usable event)"]++
			continue
		}
		out = append(out, e)
		seen[d] = true
		st.Seen = append(st.Seen, d)
	}
	if len(st.Seen) > maxSeen {
		st.Seen = st.Seen[len(st.Seen)-maxSeen:]
	}
	for f, n := range missing {
		if n > missing[st.Field] || st.Field == "" {
			st.Field = f
		}
	}
	return out
}

// firstRead is how far back a source is read the first time.
const firstRead = 24 * time.Hour

// collectable is one connector endpoint and the mapping it feeds.
type collectable struct {
	M connector.Manifest
	E connector.Endpoint
	S source.Source
}

func (c collectable) name() string { return c.S.Issuer + "/" + c.S.Stream }

// collectables pairs every installed event endpoint with its mapping.
func collectables(root string) ([]collectable, []string, error) {
	ms, err := manifests(root)
	if err != nil {
		return nil, nil, err
	}
	all, err := allSources(root)
	if err != nil {
		return nil, nil, err
	}
	var out []collectable
	var unmapped []string
	for _, m := range ms {
		for _, e := range m.Endpoints {
			if e.Produces != connector.Events {
				continue
			}
			found := false
			for _, s := range all {
				if strings.EqualFold(s.Issuer, m.Name) &&
					strings.EqualFold(s.Stream, e.Name) {
					out = append(out, collectable{m, e, s})
					found = true
				}
			}
			if !found {
				unmapped = append(unmapped, m.Name+"/"+e.Name)
			}
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].name() < out[b].name() })
	return out, unmapped, nil
}

// collectOne reads one source and stores what is new.
func collectOne(root string, c collectable, sp *spool.Spool,
	prev collectStatus, aliases map[string]alias, caller *Caller,
	now time.Time) collectStatus {

	st := collectStatus{Source: c.name(), At: now, Seen: prev.Seen}
	// The first read of an incremental source starts a day back, not at
	// the beginning of the tool's history.
	if c.E.Since != "" {
		states, err := loadStates(root)
		if err != nil {
			st.Error = err.Error()
			return st
		}
		key := c.M.Name + "/" + c.E.Name
		if states[key].Watermark == "" {
			start := now.Add(-firstRead).UTC()
			mark := start.Format(time.RFC3339)
			if c.E.WatermarkLayout == "epoch-ms" {
				mark = fmt.Sprint(start.UnixMilli())
			}
			states[key] = connector.State{Watermark: mark, At: now}
			if err := saveStates(root, states); err != nil {
				st.Error = err.Error()
				return st
			}
		}
	}
	out, failed, err := runConnector(root, c.M, []string{c.E.Name}, false,
		false, caller)
	if err == nil {
		err = failed
	}
	if err != nil {
		st.Error = err.Error()
		return st
	}
	var docs []any
	for _, rec := range out.Records {
		docs = append(docs, unflatten(rec))
	}
	if err := storeRecords(sp, c.S, docs, &st, aliases, now); err != nil {
		st.Error = err.Error()
		return st
	}
	for _, run := range out.Runs {
		if t, _ := run["truncated"].(string); t != "" {
			st.Gap = "the read stopped at a limit: " + t
		}
	}
	// A source with no way to ask "since when" returns its newest page. If
	// every record on it was new, there may have been more before it.
	if c.E.Since == "" && st.Records > 0 && st.Known == 0 && len(prev.Seen) > 0 {
		st.Gap = "every record returned was new, so there may have been " +
			"more than one page since the last read"
	}
	return st
}

// collectAll reads every source, or the ones named.
//
// sp is the event store to write to; nil opens one for the call. The server
// passes the one it shares between everything that writes there.
func collectAll(root string, names []string, caller *Caller,
	now time.Time, sp *spool.Spool) ([]collectStatus, []string, error) {

	todo, unmapped, err := collectables(root)
	if err != nil {
		return nil, nil, err
	}
	if len(names) > 0 {
		want := map[string]bool{}
		for _, n := range names {
			want[strings.ToLower(n)] = true
		}
		kept := todo[:0:0]
		for _, c := range todo {
			if want[strings.ToLower(c.name())] {
				kept = append(kept, c)
				delete(want, strings.ToLower(c.name()))
			}
		}
		for n := range want {
			return nil, unmapped, fmt.Errorf("%s is not a source a "+
				"connector is installed for; quilzo collect status lists "+
				"them", n)
		}
		todo = kept
	}
	if len(todo) == 0 {
		return nil, unmapped, nil
	}
	status, err := loadCollectStatus(root)
	if err != nil {
		return nil, unmapped, err
	}
	if sp == nil {
		own, err := openSpool(root, spool.Options{})
		if err != nil {
			return nil, unmapped, err
		}
		defer own.Close()
		sp = own
	}
	aliases, err := loadAliases(root)
	if err != nil {
		return nil, unmapped, err
	}
	learned := false
	var out []collectStatus
	for _, c := range todo {
		st := collectOne(root, c, sp, status[c.name()], aliases, caller, now)
		learned = learned || st.learned
		status[c.name()] = st
		out = append(out, st)
		outcome := audit.Success
		if st.Error != "" {
			outcome = audit.Failure
		}
		record(root, audit.Record{Action: "collect.run",
			Resource: "/collect/" + c.name(), Outcome: outcome,
			Principal: caller.Name, Kind: caller.Kind,
			Verified: caller.Kind != audit.KindUnknown,
			Detail: map[string]string{"records": fmt.Sprint(st.Records),
				"stored": fmt.Sprint(st.Stored), "missed": fmt.Sprint(st.Missed),
				"known": fmt.Sprint(st.Known)}})
	}
	if learned {
		if err := saveAliases(root, aliases); err != nil {
			return out, unmapped, err
		}
	}
	return out, unmapped, saveCollectStatus(root, status)
}

func printCollect(sts []collectStatus) {
	for _, st := range sts {
		switch {
		case st.Error != "":
			w.Human("  %s%-22s%s %snot read: %s%s\n", bold, st.Source, reset,
				red, st.Error, reset)
			continue
		default:
			w.Human("  %s%-22s%s %d stored of %d returned", bold, st.Source,
				reset, st.Stored, st.Records)
			if st.Known > 0 {
				w.Human(", %d already held", st.Known)
			}
			w.Human("\n")
		}
		if st.Missed > 0 {
			w.Human("      %s%d did not map: %s was missing. A vendor "+
				"renaming a field looks like this%s\n", red, st.Missed,
				st.Field, reset)
		}
		if st.Gap != "" {
			w.Human("      %s%s%s\n", yellow, st.Gap, reset)
		}
	}
}

func cmdCollect(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "run":
		caller := resolveCaller(root, flagToken)
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return err
		}
		sts, unmapped, err := collectAll(root, args[1:], caller, time.Now().UTC(), nil)
		if err != nil {
			return err
		}
		if w.JSON(map[string]any{"sources": statusWithoutDigests(sts),
			"unmapped": unmapped}) {
			return nil
		}
		if len(sts) == 0 {
			w.Human("No connector that produces events is installed. " +
				"quilzo connect catalogue lists them; okta, entra, github " +
				"and evm read logs.\n")
		}
		printCollect(sts)
		for _, u := range unmapped {
			w.Human("  %s%s produces events and has no mapping, so nothing "+
				"of it is stored%s\n", yellow, u, reset)
		}
		return nil
	case "file":
		return collectFile(root, args[1:])
	case "status":
		return collectShow(root)
	case "auto":
		return collectAuto(root, args[1:])
	default:
		return fmt.Errorf("unknown collect command %q; try run, file, "+
			"status or auto", args[0])
	}
}

func statusWithoutDigests(in []collectStatus) []collectStatus {
	out := append([]collectStatus(nil), in...)
	for i := range out {
		out[i].Seen = nil
	}
	return out
}

func collectFile(root string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: quilzo collect file ISSUER/STREAM FILE")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	s, err := findSource(root, args[0])
	if err != nil {
		return err
	}
	docs, err := readRecords(args[1])
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return fmt.Errorf("%s holds no records", args[1])
	}
	status, err := loadCollectStatus(root)
	if err != nil {
		return err
	}
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	defer sp.Close()
	name := s.Issuer + "/" + s.Stream
	now := time.Now().UTC()
	st := collectStatus{Source: name, At: now, Seen: status[name].Seen}
	aliases, err := loadAliases(root)
	if err != nil {
		return err
	}
	if err := storeRecords(sp, s, docs, &st, aliases, now); err != nil {
		return err
	}
	if st.learned {
		if err := saveAliases(root, aliases); err != nil {
			return err
		}
	}
	status[name] = st
	if err := saveCollectStatus(root, status); err != nil {
		return err
	}
	record(root, audit.Record{Action: "collect.file",
		Resource: "/collect/" + name, Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"records": fmt.Sprint(st.Records),
			"stored": fmt.Sprint(st.Stored), "missed": fmt.Sprint(st.Missed)}})
	if w.JSON(statusWithoutDigests([]collectStatus{st})[0]) {
		return nil
	}
	printCollect([]collectStatus{st})
	if st.Stored == 0 && st.Missed > 0 {
		return fmt.Errorf("nothing in %s mapped", args[1])
	}
	return nil
}

func collectShow(root string) error {
	todo, unmapped, err := collectables(root)
	if err != nil {
		return err
	}
	status, err := loadCollectStatus(root)
	if err != nil {
		return err
	}
	sched, err := loadCollectSchedule(root)
	if err != nil {
		return err
	}
	var rows []collectStatus
	have := map[string]bool{}
	for _, c := range todo {
		have[c.name()] = true
		st, read := status[c.name()]
		if !read {
			st = collectStatus{Source: c.name()}
		}
		rows = append(rows, st)
	}
	for name, st := range status {
		if !have[name] {
			rows = append(rows, st)
		}
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].Source < rows[b].Source })
	if w.JSON(map[string]any{"sources": statusWithoutDigests(rows),
		"unmapped": unmapped, "every": sched.Every.String()}) {
		return nil
	}
	if len(rows) == 0 {
		w.Human("Nothing is collected. Install a connector that reads a " +
			"log (quilzo connect add okta|entra|github|evm), or store a " +
			"file with quilzo collect file.\n")
		return nil
	}
	now := time.Now().UTC()
	for _, st := range rows {
		if st.At.IsZero() {
			w.Human("  %s%-22s%s %snever read%s\n", bold, st.Source, reset,
				yellow, reset)
			continue
		}
		w.Human("  %s%-22s%s read %s ago\n", bold, st.Source, reset,
			plainClockSpan(now.Sub(st.At)))
	}
	printCollect(rows)
	if sched.Every > 0 {
		w.Human("\n  %sread every %s while the server runs%s\n", dim,
			sched.Every, reset)
	} else {
		w.Human("\n  %snot scheduled: quilzo collect auto 15m%s\n", dim, reset)
	}
	return nil
}

// ---- the schedule -----------------------------------------------------------

type collectSchedule struct {
	Every time.Duration `json:"every"`
	By    string        `json:"by"`
	At    time.Time     `json:"at"`
}

func collectSchedulePath(root string) string {
	return filepath.Join(collectDir(root), "schedule.json")
}

func loadCollectSchedule(root string) (collectSchedule, error) {
	var s collectSchedule
	b, err := os.ReadFile(collectSchedulePath(root))
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

func collectAuto(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo collect auto 15m|1h|off")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	var every time.Duration
	if args[0] != "off" {
		d, err := time.ParseDuration(args[0])
		if err != nil || d < upkeep.Every || d > 24*time.Hour {
			return fmt.Errorf("the interval is between %s and 24h, or off. "+
				"The server looks every %s, so nothing shorter would be kept",
				upkeep.Every, upkeep.Every)
		}
		every = d
	}
	b, _ := json.Marshal(collectSchedule{Every: every, By: caller.Name,
		At: time.Now().UTC()})
	if err := os.MkdirAll(collectDir(root), 0o700); err != nil {
		return err
	}
	if err := atomicfile.Write(collectSchedulePath(root), b, 0o600); err != nil {
		return err
	}
	record(root, audit.Record{Action: "collect.schedule", Resource: "/collect",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified,
		Detail:   map[string]string{"every": every.String()}})
	if !w.JSON(map[string]any{"every": every.String()}) {
		if every == 0 {
			w.Human("collection is not scheduled\n")
		} else {
			w.Human("every source is read every %s while the server runs\n", every)
		}
	}
	return nil
}

// collectJob reads every source on the schedule.
func collectJob(root string) upkeep.Job {
	return upkeep.Job{
		Name: "collect",
		Do: func(now time.Time) (int, error) {
			s, err := loadCollectSchedule(root)
			if err != nil || s.Every <= 0 {
				return 0, err
			}
			status, err := loadCollectStatus(root)
			if err != nil {
				return 0, err
			}
			var last time.Time
			for _, st := range status {
				if st.At.After(last) {
					last = st.At
				}
			}
			if !last.IsZero() && now.Sub(last) < s.Every {
				return 0, nil
			}
			stored := 0
			err = withSpool(root, func(sp *spool.Spool) error {
				sts, _, cerr := collectAll(root, nil, &Caller{
					Name: "collect-schedule:" + s.By, Kind: audit.KindService,
					Verified: true}, now.UTC(), sp)
				for _, st := range sts {
					stored += st.Stored
				}
				// What was collected is read by the rules now, not when
				// somebody next remembers to run them.
				if stored > 0 {
					detectInServer(root, sp)
				}
				return cerr
			})
			return stored, err
		},
	}
}
