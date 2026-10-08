// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// exploitedIDs is which advisory ids the feeds this store loaded (CISA KEV
// and the like) attest as exploited.
func exploitedIDs(root string) func(ids []string) bool {
	known := map[string]bool{}
	if advs, err := loadAdvisories(storedAdvisories(root)); err == nil {
		for _, a := range advs {
			if len(a.Exploited) == 0 {
				continue
			}
			known[a.ID] = true
			for _, al := range a.Aliases {
				known[al] = true
			}
		}
	}
	return func(ids []string) bool {
		for _, id := range ids {
			if known[id] {
				return true
			}
		}
		return false
	}
}

// selfReport is a self-check's result, as kept and shown.
type selfReport struct {
	selfvuln.Report
	Binary   selfvuln.Verdict `json:"binary"`
	Unread   string           `json:"unread,omitempty"`
	Snapshot string           `json:"snapshot"`
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
	rep := selfReport{Report: selfvuln.Assess(snap, selfvuln.GoVersion(), linked, fm, exploitedIDs(root), now),
		Snapshot: snap.Source}
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

// tellTheShield raises what a self-check found: a contained flaw for each
// feature it reaches, a flaw to upgrade for, a binary that is not itself.
func tellTheShield(root string, rep selfReport) int {
	sh := newShieldHost(root)
	n := 0
	for _, f := range rep.Findings {
		switch f.Decision {
		case selfvuln.Contain:
			for _, ft := range f.Features {
				sh.engine.Observe(shield.Signal{Name: "self-exposure", Subject: ft})
				n++
			}
		case selfvuln.Tell:
			sh.engine.Observe(shield.Signal{Name: "self-flaw", Subject: f.ID})
			n++
		}
	}
	if rep.Binary.Suspicious() {
		sh.engine.Observe(shield.Signal{Name: "binary-changed", Subject: "binary"})
		n++
	}
	return n
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
		return tellTheShield(root, rep), nil
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
	}
	return fmt.Errorf("unknown self command %q; try check, verify, update or vex", args[0])
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
