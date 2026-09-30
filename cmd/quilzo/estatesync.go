// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// Keeping the estate current without anybody remembering to.
//
// A sync reads every installed tool, rebuilds the estate and, when it is
// allowed to, sends the reminders that are due. `quilzo estate sync` does
// it once; `quilzo estate auto --every 24h` has the admin server do it on
// that interval, from the same loop that enforces form retention.
//
// Why in the server and not on an external timer, when scheduled publishing
// keeps its external timer on purpose: publishing is a gated write whose
// moment matters. Reading tools and rebuilding findings is idempotent and
// can happen late without harm, which is the argument internal/upkeep makes
// for retention. Sending reminders is the exception — a message to every
// employee with something outstanding — so it has a switch of its own, off
// unless an administrator turns it on, and even then it only sends inside
// the configured hours, at most weekly to a person, and records each one.

func estateSchedulePath(root string) string {
	return filepath.Join(estateDir(root), "schedule.json")
}

func estateSyncPath(root string) string {
	return filepath.Join(estateDir(root), "sync.json")
}

// estateSchedule is how often the server syncs, and on whose authority.
type estateSchedule struct {
	// Every is the interval; zero is off.
	Every time.Duration `json:"every"`
	// Remind sends due reminders from the loop as well.
	Remind bool `json:"remind"`
	// By is the administrator who set this, whom every scheduled sync is
	// recorded as acting for.
	By string    `json:"by"`
	At time.Time `json:"at"`
}

// MinSyncEvery bounds how often a schedule may read the tools. Hourly: the
// tools' daily limits are shared with their own consoles, and a sync every
// few minutes would spend KnowBe4's day by lunchtime.
const MinSyncEvery = time.Hour

func loadEstateSchedule(root string) (estateSchedule, error) {
	var s estateSchedule
	b, err := os.ReadFile(estateSchedulePath(root))
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("estate/schedule.json: %w", err)
	}
	return s, nil
}

// syncTool is one tool's part of a sync.
type syncTool struct {
	Name       string   `json:"name"`
	Records    int      `json:"records"`
	Requests   int      `json:"requests"`
	Incomplete []string `json:"incomplete,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// syncReport is what a sync did, kept as the latest.
type syncReport struct {
	At         time.Time  `json:"at"`
	Took       string     `json:"took"`
	Tools      []syncTool `json:"tools"`
	Found      int        `json:"found"`
	BuildError string     `json:"build_error,omitempty"`
	Reminded   int        `json:"reminded,omitempty"`
	NotSent    int        `json:"not_sent,omitempty"`
	RemindNote string     `json:"remind_note,omitempty"`
}

func loadSyncReport(root string) (*syncReport, error) {
	b, err := os.ReadFile(estateSyncPath(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r syncReport
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// SyncLockStale is how long a sync lock is honoured. Two hours, not the
// quarter hour the finding register's lock allows: a sync over a large
// estate paced to the tools' limits takes longer than that, and a second
// sync starting beside it would fetch its own Vanta token and revoke the
// first one's.
const SyncLockStale = 2 * time.Hour

func lockSync(root string) (func(), error) {
	if err := os.MkdirAll(estateDir(root), 0o700); err != nil {
		return nil, err
	}
	lock := filepath.Join(estateDir(root), "sync.lock")
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { _ = os.Remove(lock) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		fi, serr := os.Stat(lock)
		if serr != nil || time.Since(fi.ModTime()) < SyncLockStale {
			return nil, fmt.Errorf("a sync is already running (%s exists)",
				lock)
		}
		_ = os.Remove(lock)
	}
	return nil, fmt.Errorf("could not take %s", lock)
}

// syncRunning reports whether a sync holds the lock now.
func syncRunning(root string) bool {
	fi, err := os.Stat(filepath.Join(estateDir(root), "sync.lock"))
	return err == nil && time.Since(fi.ModTime()) < SyncLockStale
}

// syncStatus is what the workforce screen says about reading the tools.
func syncStatus(root string) (admin.SyncStatus, error) {
	st := admin.SyncStatus{Running: syncRunning(root)}
	if sch, err := loadEstateSchedule(root); err == nil {
		st.Every = sch.Every
	}
	rep, err := loadSyncReport(root)
	if err != nil || rep == nil {
		return st, err
	}
	st.Last, st.Tools = rep.At, len(rep.Tools)
	for _, t := range rep.Tools {
		if t.Error != "" {
			st.Problems = append(st.Problems, t.Name+": "+t.Error)
		}
	}
	if rep.BuildError != "" {
		st.Problems = append(st.Problems, "building: "+rep.BuildError)
	}
	return st, nil
}

// credentialsOf lists the credentials a manifest needs.
func credentialsOf(m connector.Manifest) []string {
	var out []string
	if m.Auth.Kind != connector.NoAuth {
		out = append(out, m.Auth.Secret)
	}
	if t := m.Auth.Token; t != nil {
		out = append(out, t.Client)
		if t.Refresh != "" {
			out = append(out, t.Refresh)
		}
	}
	return out
}

// estateSync reads every installed tool, rebuilds the estate, and sends due
// reminders when remind is set and reminders are enabled.
func estateSync(root string, now time.Time, caller *Caller,
	remind bool) (syncReport, error) {

	unlock, err := lockSync(root)
	if err != nil {
		return syncReport{}, err
	}
	defer unlock()
	started := time.Now()
	rep := syncReport{At: now}

	all, err := manifests(root)
	if err != nil {
		return rep, err
	}
	held, err := loadSecrets(root)
	if err != nil {
		return rep, err
	}
	for _, m := range all {
		t := syncTool{Name: m.Name}
		if verr := m.Validate(); verr != nil {
			t.Error = verr.Error()
			rep.Tools = append(rep.Tools, t)
			continue
		}
		var missing []string
		for _, c := range credentialsOf(m) {
			if strings.TrimSpace(held[c]) == "" {
				missing = append(missing, c)
			}
		}
		if len(missing) > 0 {
			t.Error = "no credential stored for " + strings.Join(missing, ", ")
			rep.Tools = append(rep.Tools, t)
			continue
		}
		out, failed, rerr := runConnector(root, m, nil, false, true, caller)
		t.Records, t.Requests = len(out.Records), out.Requests
		for _, r := range out.Runs {
			if r["complete"] == false || r["error"] != nil {
				t.Incomplete = append(t.Incomplete, fmt.Sprint(r["endpoint"]))
			}
		}
		switch {
		case rerr != nil:
			t.Error = rerr.Error()
		case failed != nil:
			t.Error = failed.Error()
		}
		rep.Tools = append(rep.Tools, t)
	}

	if s, berr := buildAndRecord(root, now, caller.Name, caller.Kind,
		caller.Verified); berr != nil {
		rep.BuildError = berr.Error()
	} else {
		rep.Found = s.Found
	}

	if remind {
		c, cerr := loadRemindConfig(root)
		switch {
		case cerr != nil:
			rep.RemindNote = cerr.Error()
		case !c.Enabled:
			rep.RemindNote = "reminders are not enabled"
		case !c.InHours(now):
			rep.RemindNote = "outside the sending hours"
		default:
			sent, notSent, serr := remindSendNow(root, now, caller.Name,
				caller.Kind)
			rep.Reminded, rep.NotSent = sent, notSent
			if serr != nil {
				rep.RemindNote = serr.Error()
			}
		}
	}
	rep.Took = time.Since(started).Round(time.Second).String()

	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return rep, err
	}
	if err := atomicfile.Write(estateSyncPath(root), b, 0o600); err != nil {
		return rep, err
	}
	failedTools := 0
	for _, t := range rep.Tools {
		if t.Error != "" {
			failedTools++
		}
	}
	record(root, audit.Record{
		Action: "estate.sync", Resource: "/workforce", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"tools": fmt.Sprint(len(rep.Tools)), "failed": fmt.Sprint(failedTools),
			"found": fmt.Sprint(rep.Found), "reminded": fmt.Sprint(rep.Reminded),
		},
	})
	return rep, nil
}

// scheduleCaller is who a scheduled sync is recorded as: the server, as a
// service, acting for the administrator who set the schedule.
func scheduleCaller(s estateSchedule) *Caller {
	return &Caller{Name: "estate-schedule:" + s.By, Kind: audit.KindService,
		Verified: true}
}

// estateJob is the upkeep job that runs the schedule.
func estateJob(root string) upkeep.Job {
	return upkeep.Job{
		Name: "estate",
		Do: func(now time.Time) (int, error) {
			s, err := loadEstateSchedule(root)
			if err != nil || s.Every <= 0 {
				return 0, err
			}
			last, _ := loadSyncReport(root)
			if last == nil || now.Sub(last.At) >= s.Every {
				rep, err := estateSync(root, now.UTC(), scheduleCaller(s),
					s.Remind)
				if err != nil {
					return 0, err
				}
				return len(rep.Tools), nil
			}
			// Between syncs, reminders are still sent when they fall due:
			// a sync at three in the morning is outside anybody's sending
			// hours, and the ledger's spacing makes asking every quarter of
			// an hour cost nothing but a plan with nobody in it.
			if s.Remind {
				c, cerr := loadRemindConfig(root)
				if cerr == nil && c.Enabled && c.InHours(now.UTC()) {
					caller := scheduleCaller(s)
					if _, _, err := remindSendNow(root, now.UTC(), caller.Name,
						caller.Kind); err != nil {
						return 0, err
					}
				}
			}
			return 0, nil
		},
	}
}

func cmdEstateSync(root string, args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	remind := fs.Bool("remind", false,
		"send the reminders that are due, if reminders are enabled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Reads every tool with its stored credential and rebuilds findings
	// that name people: an administrator's.
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	rep, err := estateSync(root, time.Now().UTC(), caller, *remind)
	if err != nil {
		return err
	}
	if w.JSON(rep) {
		return nil
	}
	printSync(rep)
	return nil
}

func printSync(rep syncReport) {
	sort.Slice(rep.Tools, func(i, j int) bool {
		return rep.Tools[i].Name < rep.Tools[j].Name
	})
	for _, t := range rep.Tools {
		switch {
		case t.Error != "":
			w.Human("%s%s%s  %s%s%s\n", bold, t.Name, reset, red, t.Error, reset)
		case len(t.Incomplete) > 0:
			w.Human("%s%s%s  %d record(s), not read to the end: %s\n", bold,
				t.Name, reset, t.Records, strings.Join(t.Incomplete, ", "))
		default:
			w.Human("%s%s%s  %d record(s) in %d request(s)\n", bold, t.Name,
				reset, t.Records, t.Requests)
		}
	}
	if rep.BuildError != "" {
		w.Human("\n%snot built: %s%s\n", red, rep.BuildError, reset)
	} else {
		w.Human("\n%d finding(s) from the estate\n", rep.Found)
	}
	if rep.Reminded+rep.NotSent > 0 {
		w.Human("%d reminder(s) sent, %d not\n", rep.Reminded, rep.NotSent)
	}
	if rep.RemindNote != "" {
		w.Human("%sreminders: %s%s\n", dim, rep.RemindNote, reset)
	}
	w.Human("%stook %s%s\n", dim, rep.Took, reset)
}

func cmdEstateAuto(root string, args []string) error {
	fs := flag.NewFlagSet("auto", flag.ContinueOnError)
	every := fs.Duration("every", 0, "how often the admin server syncs, e.g. 24h")
	off := fs.Bool("off", false, "stop syncing on a schedule")
	remind := fs.Bool("remind", false,
		"also send due reminders, if reminders are enabled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
		return err
	}
	s := estateSchedule{By: caller.Name, At: time.Now().UTC()}
	switch {
	case *off:
	case *every < MinSyncEvery:
		return fmt.Errorf("--every is at least %s: the tools' daily limits "+
			"are shared with their own consoles", MinSyncEvery)
	default:
		s.Every, s.Remind = *every, *remind
	}
	if err := os.MkdirAll(estateDir(root), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicfile.Write(estateSchedulePath(root), b, 0o600); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "estate.schedule", Resource: "/workforce",
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified,
		Detail: map[string]string{"every": s.Every.String(),
			"remind": fmt.Sprint(s.Remind)},
	})
	if w.JSON(s) {
		return nil
	}
	if s.Every == 0 {
		w.Human("the estate is no longer synced on a schedule\n")
		return nil
	}
	w.Human("the admin server syncs every %s", s.Every)
	if s.Remind {
		w.Human(", and sends due reminders when they are enabled")
	}
	w.Human("\n")
	return nil
}
