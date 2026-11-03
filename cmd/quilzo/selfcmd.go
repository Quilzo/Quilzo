// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/selfvuln"
	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// Quilzo checking itself: this binary, against the Go vulnerability
// database, decided by what is linked into it and which features reach it
// (internal/selfvuln). The admin's upkeep runs it every hour and tells the
// shield; `quilzo self` runs it on the machine.

// self is what this process knows about its own binary, read once.
var self struct {
	once      sync.Once
	linked    selfvuln.Linked
	linkedErr error
	started   string
}

// selfBinary reads the running binary's linked functions and its hash, the
// first time it is asked: the hash is what the binary was when this process
// began, against which a replacement on disk is noticed.
func selfBinary() (selfvuln.Linked, string, error) {
	self.once.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			self.linkedErr = err
			return
		}
		self.linked, self.linkedErr = selfvuln.ReadLinked(exe)
		self.started, _ = selfvuln.Hash(exe)
	})
	return self.linked, self.started, self.linkedErr
}

// kevPath is where the advisories known to be exploited are kept: the CVE
// ids of CISA's Known Exploited Vulnerabilities catalogue, as an operator
// last gave it (quilzo self kev).
func kevPath(root string) string { return filepath.Join(root, "self", "kev.json") }

// kevKept is CISA's catalogue as kept here: the date it was released, as
// the catalogue gives it, and its CVE ids.
type kevKept struct {
	Released string   `json:"released"`
	IDs      []string `json:"ids"`
}

// kevStatus is whether the catalogue is kept and of when. Without it, a
// flaw in this build that is being exploited is never contained at once,
// so self check and the posture say so (self.kev-missing).
type kevStatus struct {
	Kept bool `json:"kept"`
	// Of is the date the catalogue was released, or when it was kept here
	// when that date cannot be read.
	Of    time.Time `json:"of,omitzero"`
	Count int       `json:"count,omitempty"`
	// Problem says why a kept catalogue cannot be read.
	Problem string `json:"problem,omitempty"`
}

// loadKEV is the catalogue kept, and how it stands.
func loadKEV(root string) (kevKept, kevStatus) {
	var k kevKept
	b, err := os.ReadFile(kevPath(root))
	if errors.Is(err, os.ErrNotExist) {
		return k, kevStatus{}
	}
	if err != nil {
		return k, kevStatus{Problem: err.Error()}
	}
	if err := json.Unmarshal(b, &k); err != nil || len(k.IDs) == 0 {
		return kevKept{}, kevStatus{Problem: "self/kev.json names no vulnerability; give the catalogue again"}
	}
	st := kevStatus{Kept: true, Count: len(k.IDs)}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(k.Released)); err == nil {
		st.Of = t
	} else if t, err := time.Parse(time.DateOnly, strings.TrimSpace(k.Released)); err == nil {
		st.Of = t
	} else if fi, err := os.Stat(kevPath(root)); err == nil {
		st.Of = fi.ModTime()
	}
	return k, st
}

// exploitedIDs is which advisory ids are known to be exploited.
func exploitedIDs(root string) func(ids []string) bool {
	known := map[string]bool{}
	kept, _ := loadKEV(root)
	for _, id := range kept.IDs {
		known[strings.ToUpper(id)] = true
	}
	return func(ids []string) bool {
		for _, id := range ids {
			if known[strings.ToUpper(id)] {
				return true
			}
		}
		return false
	}
}

// selfKEV keeps the CVE ids of CISA's catalogue of vulnerabilities known to
// be exploited, so a flaw in this build that is being exploited is
// contained at once (the shield turns off the features it reaches through)
// rather than waiting for a person. Read from a file the operator fetched;
// nothing is fetched here.
func selfKEV(root string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: quilzo self kev known_exploited_vulnerabilities.json " +
			"(from https://www.cisa.gov/known-exploited-vulnerabilities-catalog; read here, nothing is fetched)")
	}
	b, err := readBounded(args[0], 64<<20)
	if err != nil {
		return err
	}
	var cat struct {
		DateReleased    string `json:"dateReleased"`
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &cat); err != nil {
		return fmt.Errorf("%s is not CISA's catalogue: %w", args[0], err)
	}
	var ids []string
	for _, v := range cat.Vulnerabilities {
		if id := strings.ToUpper(strings.TrimSpace(v.CVE)); strings.HasPrefix(id, "CVE-") {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return fmt.Errorf("%s names no vulnerability; it is not the catalogue, or it is empty", args[0])
	}
	sort.Strings(ids)
	out, err := json.Marshal(map[string]any{"released": cat.DateReleased, "ids": ids})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(kevPath(root)), 0o700); err != nil {
		return err
	}
	if err := atomicfile.Write(kevPath(root), out, 0o600); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	record(root, caller.auditRecord("self.kev-updated", "/security/inventory", audit.Success,
		map[string]string{"vulnerabilities": fmt.Sprint(len(ids)), "released": cat.DateReleased}))
	w.Human("%skept%s %d vulnerabilities known to be exploited, the catalogue of %s\n", green, reset,
		len(ids), nonEmpty(cat.DateReleased, "an unknown date"))
	return selfCheck(root)
}

// selfReport is a self-check's result, as kept and shown.
type selfReport struct {
	selfvuln.Report
	Binary   selfvuln.Verdict `json:"binary"`
	Unread   string           `json:"unread,omitempty"`
	Snapshot string           `json:"snapshot"`
	// Exploited is CISA's catalogue as this check read it.
	Exploited kevStatus `json:"exploited"`
}

func selfReportPath(root string) string { return filepath.Join(root, "self", "report.json") }

// runSelfCheck assesses this binary and keeps the result.
func runSelfCheck(root string, now time.Time) (selfReport, error) {
	snap, err := selfvuln.Load(root)
	if err != nil {
		return selfReport{}, err
	}
	fm, err := selfvuln.Features()
	if err != nil {
		return selfReport{}, err
	}
	linked, started, lerr := selfBinary()
	_, kev := loadKEV(root)
	rep := selfReport{Report: selfvuln.Assess(snap, selfvuln.GoVersion(), linked, fm, exploitedIDs(root), now),
		Snapshot: snap.Source, Exploited: kev}
	if lerr != nil {
		rep.Unread = lerr.Error()
	}
	if exe, err := os.Executable(); err == nil {
		if v, err := selfvuln.Verify(root, exe, version, started, now); err == nil {
			rep.Binary = v
		}
	}
	if err := os.MkdirAll(filepath.Dir(selfReportPath(root)), 0o700); err == nil {
		if b, err := json.MarshalIndent(rep, "", " "); err == nil {
			_ = atomicfile.Write(selfReportPath(root), b, 0o600)
		}
	}
	return rep, nil
}

// loadSelfReport is the last self-check kept.
func loadSelfReport(root string) (selfReport, error) {
	var rep selfReport
	b, err := os.ReadFile(selfReportPath(root))
	if err != nil {
		return rep, err
	}
	return rep, json.Unmarshal(b, &rep)
}

// tellTheShield raises what a self-check found at now: a contained flaw
// for each feature it reaches, a flaw to upgrade for, a binary that is not
// itself. The same findings come every hour, so they go to the one engine
// that remembers having acted on them (shieldFor), and the playbooks'
// day-long rest keeps a person from hearing of the same flaw every hour.
//
// A contained feature cannot rest the whole day. Turning it off lasts a
// day at most, as long as the rest, so the feature came back on when its
// day ran out and stayed on until the run after, open to whoever was using
// the flaw. Its rest is ended a few hours before (containmentEnding), and
// a flaw still there is contained, and told, again without the feature
// coming back on in between.
func tellTheShield(root string, rep selfReport, now time.Time) int {
	sh := shieldFor(root)
	n := 0
	for _, f := range rep.Findings {
		switch f.Decision {
		case selfvuln.Contain:
			for _, ft := range f.Features {
				s := shield.Signal{Name: "self-exposure", Subject: ft, At: now}
				if containmentEnding(root, ft, now) {
					sh.engine.Wake(s)
				}
				sh.engine.Observe(s)
				n++
			}
		case selfvuln.Tell:
			sh.engine.Observe(shield.Signal{Name: "self-flaw", Subject: f.ID, At: now})
			n++
		}
	}
	if rep.Binary.Suspicious() {
		sh.engine.Observe(shield.Signal{Name: "binary-changed", Subject: "binary", At: now})
		n++
	}
	return n
}

// containAhead is how long before a feature turned off for a flaw would
// come back on that the self-check contains it again. The next run is an
// hour or an hour and a quarter away (the upkeep wakes every quarter of an
// hour), later when a slow job ahead of it holds the upkeep up.
const containAhead = 3 * time.Hour

// containmentEnding reports whether the shield turned this feature off by
// itself and that ends within containAhead. One a person set, or lifted,
// is theirs, and is left to them.
func containmentEnding(root, feature string, now time.Time) bool {
	st, err := shield.Load(root)
	if err != nil {
		return false
	}
	for _, p := range st.Active(now) {
		if p.Auto && p.Kind == shield.Feature && p.Target == feature && p.Until.Before(now.Add(containAhead)) {
			return true
		}
	}
	return false
}

// selfJob is the self-check as the admin's upkeep runs it: at most hourly.
func selfJob(root string) upkeep.Job {
	var last time.Time
	return upkeep.Job{Name: "self-check", Do: func(now time.Time) (int, error) {
		if !last.IsZero() && now.Sub(last) < time.Hour {
			return 0, nil
		}
		last = now
		rep, err := runSelfCheck(root, now)
		if err != nil {
			return 0, err
		}
		return tellTheShield(root, rep, now), nil
	}}
}

func cmdSelf(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"check"}
	}
	switch args[0] {
	case "check":
		return selfCheck(root)
	case "verify":
		return selfVerify(root)
	case "update":
		return selfUpdate(root, args[1:])
	case "vex":
		return selfVEX(root)
	case "kev":
		return selfKEV(root, args[1:])
	}
	return fmt.Errorf("unknown self command %q; try check, verify, update, kev or vex", args[0])
}

func selfCheck(root string) error {
	rep, err := runSelfCheck(root, time.Now())
	if err != nil {
		return err
	}
	if w.JSON(rep) {
		return nil
	}
	w.Human("%sthis build%s: %s, with the Go vulnerability database of %s (%s)\n", bold, reset,
		rep.Go, rep.Database.Format("2 January 2006"), rep.Snapshot)
	if age := time.Since(rep.Database); age > 30*24*time.Hour {
		w.Human("  %sthe database is %d days old; give a newer one with quilzo self update vulndb.zip%s\n",
			yellow, int(age.Hours()/24), reset)
	}
	// What is known to be exploited is what contains a flaw at once, and
	// without the catalogue that never happens: this used to say nothing.
	const kevFetch = "quilzo self kev known_exploited_vulnerabilities.json (from https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"
	switch kev := rep.Exploited; {
	case kev.Problem != "":
		w.Human("  %sCISA's catalogue of exploited vulnerabilities cannot be read (%s), so no flaw is contained "+
			"at once; give it again with %s%s\n", yellow, kev.Problem, kevFetch, reset)
	case !kev.Kept:
		w.Human("  %sno catalogue of exploited vulnerabilities has been given, so no flaw is contained at once; "+
			"give CISA's with %s%s\n", yellow, kevFetch, reset)
	default:
		w.Human("  with CISA's catalogue of exploited vulnerabilities of %s (%d)\n",
			kev.Of.UTC().Format("2 January 2006"), kev.Count)
		if age := time.Since(kev.Of); age > 30*24*time.Hour {
			w.Human("  %sthe catalogue is %d days old; give a newer one with %s%s\n",
				yellow, int(age.Hours()/24), kevFetch, reset)
		}
	}
	if rep.Unread != "" {
		w.Human("  %swhat is linked into this binary could not be read (%s), so nothing is cleared for not being linked%s\n",
			yellow, rep.Unread, reset)
	}
	if len(rep.Findings) == 0 {
		w.Human("%sno known flaw in the standard library concerns %s%s (of %d advisories read)\n",
			green, rep.Go, reset, rep.Records)
	}
	for _, f := range rep.Findings {
		colour := map[selfvuln.Decision]string{selfvuln.Contain: red, selfvuln.Tell: yellow, selfvuln.Clear: green}[f.Decision]
		fix := ""
		if f.Fixed != "" {
			fix = "; fixed in Go " + f.Fixed
		}
		w.Human("  %s%-8s%s %s %s%s\n    %s%s%s\n", colour, f.Decision, reset, f.ID, f.Summary, fix, dim, f.Why, reset)
	}
	w.Human("\n%sthe binary%s: %s\n", bold, reset, rep.Binary.Says)
	return nil
}

func selfVerify(root string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	_, started, _ := selfBinary()
	v, err := selfvuln.Verify(root, exe, version, started, time.Now())
	if err != nil {
		return err
	}
	if w.JSON(v) {
		return nil
	}
	colour := green
	if v.Suspicious() {
		colour = red
	}
	w.Human("%s%s%s\n  %s %s\n  sha256 %s\n", colour, v.Says, reset, v.Path, v.Version, v.SHA256)
	if v.Suspicious() {
		return errors.New("the binary is not the one it says it is")
	}
	return nil
}

func selfUpdate(root string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: quilzo self update vulndb.zip (from https://vuln.go.dev/vulndb.zip; read here, nothing is fetched)")
	}
	caller := resolveCaller(root, flagToken)
	gz, snap, err := selfvuln.FromZip(args[0])
	if err != nil {
		return err
	}
	if cur, err := selfvuln.Load(root); err == nil && !snap.Modified.After(cur.Modified) {
		return fmt.Errorf("that database is of %s, and the one in use is of %s already",
			snap.Modified.Format("2 January 2006"), cur.Modified.Format("2 January 2006"))
	}
	if err := os.MkdirAll(filepath.Dir(selfvuln.Path(root)), 0o700); err != nil {
		return err
	}
	if err := atomicfile.Write(selfvuln.Path(root), gz, 0o600); err != nil {
		return err
	}
	record(root, caller.auditRecord("self.database-updated", "/security/inventory", audit.Success,
		map[string]string{"records": fmt.Sprint(len(snap.Records)), "of": snap.Modified.Format(time.RFC3339)}))
	w.Human("%skept%s %d standard-library advisories, the database of %s\n", green, reset,
		len(snap.Records), snap.Modified.Format("2 January 2006"))
	return selfCheck(root)
}

// selfVEX writes an OpenVEX statement for every advisory that concerns
// this Go: not_affected with the reason when what it names is not linked,
// affected otherwise. Unsigned: a draft for the release to sign.
func selfVEX(root string) error {
	rep, err := runSelfCheck(root, time.Now())
	if err != nil {
		return err
	}
	product := "pkg:golang/github.com/quilzo/quilzo@" + version
	type stmt struct {
		Vulnerability struct {
			Name    string   `json:"name"`
			Aliases []string `json:"aliases,omitempty"`
		} `json:"vulnerability"`
		Products      []map[string]string `json:"products"`
		Status        string              `json:"status"`
		Justification string              `json:"justification,omitempty"`
		Impact        string              `json:"impact_statement,omitempty"`
		Action        string              `json:"action_statement,omitempty"`
	}
	doc := map[string]any{
		"@context":  "https://openvex.dev/ns/v0.2.0",
		"@id":       "https://openvex.dev/docs/quilzo/" + strings.ReplaceAll(version, "/", "-"),
		"author":    "Quilzo",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   1,
	}
	var stmts []stmt
	for _, f := range rep.Findings {
		var s stmt
		s.Vulnerability.Name, s.Vulnerability.Aliases = f.ID, f.Aliases
		s.Products = []map[string]string{{"@id": product}}
		switch f.Decision {
		case selfvuln.Clear:
			s.Status, s.Justification = "not_affected", "vulnerable_code_not_present"
			s.Impact = "The functions the advisory names are not linked into this binary."
		default:
			s.Status = "affected"
			s.Action = "Upgrade to a release built with Go " + f.Fixed + " or later."
			if f.Fixed == "" {
				s.Action = "No fixed Go release yet; " + f.Why + "."
			}
		}
		stmts = append(stmts, s)
	}
	doc["statements"] = stmts
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
