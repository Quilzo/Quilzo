// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/site"
)

func schedulePath(root string) string { return filepath.Join(root, "schedule.json") }

func loadSchedule(root string) (*schedule.Schedule, error) {
	s := &schedule.Schedule{}
	return s, loadJSON(schedulePath(root), s)
}

// lockSchedule takes the schedule's lock, which every change to it holds
// from reading the file to writing it back.
//
// Adding, cancelling and firing each read the file, changed it and wrote
// it, with nothing between. Two of them at once — an entry added in the
// browser while the server's timer fired another, or a timer and a cron
// job firing the same entry — each wrote what they read plus their own
// change, and the second write lost the first: an entry that vanished, or a
// publish recorded as pending after it went out.
func lockSchedule(root string) (func(), error) {
	return atomicfile.Lock(schedulePath(root) + ".lock")
}

// updateSchedule changes the schedule under its lock, and writes it only
// when fn succeeds.
func updateSchedule(root string, fn func(*schedule.Schedule) error) error {
	unlock, err := lockSchedule(root)
	if err != nil {
		return err
	}
	defer unlock()
	sch, err := loadSchedule(root)
	if err != nil {
		return err
	}
	if err := fn(sch); err != nil {
		return err
	}
	return saveJSON(schedulePath(root), sch)
}

func cmdSchedule(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return scheduleList(root)
	case "add":
		return scheduleAdd(root, args[1:])
	case "cancel":
		return scheduleCancel(root, args[1:])
	case "run":
		return scheduleRun(root, args[1:])
	default:
		return fmt.Errorf("unknown schedule command %q; try list, add, cancel "+
			"or run", args[0])
	}
}

func scheduleAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	note := fs.String("note", "", "why, for whoever finds this next week")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf(
			"usage: quilzo schedule add <when>\n" +
				"  when is RFC 3339 (2026-09-01T09:00:00Z) or a duration (48h)")
	}

	when, err := parseWhen(pos[0], time.Now())
	if err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	draft := s.GetRef(site.RefDraft)
	if draft == "" {
		return fmt.Errorf("there is no draft to schedule")
	}

	// The caller the command was authorised as, --token included: resolving
	// it again without the flag recorded whoever QUILZO_TOKEN or the token
	// file named, which is not always who was let in.
	caller := resolveCaller(root, flagToken)
	who := schedule.Who{Name: caller.Name, Kind: string(caller.Kind), Verified: caller.Verified}
	var refused error
	if err := updateSchedule(root, func(sch *schedule.Schedule) error {
		refused = sch.Add(draft, when, who, *note, time.Now())
		return refused
	}); err != nil {
		if refused != nil {
			return errBlocked{refused}
		}
		return err
	}

	record(root, audit.Record{
		Action: "schedule.add", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{
			"scheduled": draft, "at": when.UTC().Format(time.RFC3339),
			"note": truncate(*note, 200),
		},
	})
	fireWebhooks(root, "scheduled", draft, nil)

	w.Human("%s will publish at %s%s%s\n", short(draft), bold,
		when.UTC().Format("15:04 on 2 Jan 2006"), reset)
	w.Human("  %sthis names that exact commit. Editing the draft afterwards does\n"+
		"  not change what is scheduled — it makes the entry stale, and a stale\n"+
		"  entry is reported rather than fired%s\n", dim, reset)
	w.Human("  %severy gate runs at publication, not now%s\n", dim, reset)
	return nil
}

// parseWhen accepts a timestamp or a duration.
//
// Both, because "in 48h" is what somebody types for an embargo and an absolute
// time is what they type for a launch, and forcing one into the other is how a
// scheduled publish goes out at the wrong hour.
func parseWhen(s string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("%q is not in the future", s)
		}
		return now.Add(d), nil
	}
	return time.Time{}, fmt.Errorf(
		"%q is neither a time (2026-09-01T09:00:00Z) nor a duration (48h)", s)
}

func scheduleCancel(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo schedule cancel <commit>")
	}
	if err := updateSchedule(root, func(sch *schedule.Schedule) error {
		if !sch.Cancel(args[0]) {
			return fmt.Errorf("nothing pending matches %q", args[0])
		}
		return nil
	}); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	record(root, audit.Record{
		Action: "schedule.cancel", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{"cancelled": args[0]},
	})
	w.Human("cancelled\n")
	return nil
}

func scheduleList(root string) error {
	sch, err := loadSchedule(root)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	draft := s.GetRef(site.RefDraft)
	states := sch.Check(draft, time.Now())

	if w.JSON(map[string]any{"pending": states, "entries": sch.Entries}) {
		return nil
	}
	if len(states) == 0 {
		w.Human("nothing is scheduled\n")
		w.Human("  %squilzo schedule add 48h — publish the current draft then%s\n",
			dim, reset)
		return nil
	}
	for _, st := range states {
		at := time.Unix(st.Entry.At, 0)
		mark, colour := "pending", dim
		if st.Stale {
			mark, colour = "stale", yellow
		}
		if st.Entry.Due(time.Now()) {
			mark, colour = "due", green
		}
		w.Human("  %s%-8s%s %s  %s\n", colour, mark, reset,
			at.UTC().Format("2006-01-02 15:04"), short(st.Entry.Commit))
		w.Human("           %sby %s", dim, st.Entry.By)
		if st.Entry.Note != "" {
			w.Human(" — %s", st.Entry.Note)
		}
		w.Human("%s\n", reset)
		if st.Stale {
			w.Human("           %sthe draft has moved to %s since this was "+
				"scheduled,%s\n", yellow, short(st.Current), reset)
			w.Human("           %sso this entry describes content nobody has "+
				"looked at since%s\n", yellow, reset)
		}
	}
	return nil
}

// scheduleRun fires whatever is due.
//
// For a timer — systemd, cron, a Kubernetes CronJob — where `quilzo serve`
// is not running, or runs with schedule.in_server off. Where it is running,
// it fires these itself (runScheduler), and the two never fire one entry
// twice: both take the schedule's lock and read the file afresh under it.
func scheduleRun(root string, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "report what would publish and change nothing")
	tplDir := fs.String("templates", "templates", "where page.html lives, as for publish")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fired, err := fireDue(root, resolveCaller(root, flagToken), time.Now,
		fireOptions{dry: *dry, templates: *tplDir})
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"fired": fired}) {
		return nil
	}
	if len(fired) == 0 {
		w.Human("%snothing due%s\n", dim, reset)
		return nil
	}
	for _, f := range fired {
		sayFiring(f)
	}
	return nil
}

// A firing is what happened to one entry whose time had come.
type firing struct {
	Commit string `json:"commit"`
	By     string `json:"by"`
	At     int64  `json:"at"`
	// Outcome is published, refused, stale (the draft has moved on, so it is
	// left for a person to cancel) or would-publish (a dry run).
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	// Late is how long after its time it went out, when that was more than
	// a minute: the server was down, or nothing was running a timer.
	Late time.Duration `json:"late_ns,omitempty"`
}

func sayFiring(f firing) {
	late := ""
	if f.Late > 0 {
		late = fmt.Sprintf(" (%s late)", lateBy(f.Late))
	}
	switch f.Outcome {
	case "published":
		w.Human("  %spublished%s %s, scheduled by %s%s\n", green, reset, short(f.Commit), f.By, late)
	case "refused":
		w.Human("  %srefused%s %s, scheduled by %s — %s\n", red, reset, short(f.Commit), f.By, f.Reason)
	case "stale":
		w.Human("  %sskipped%s %s — the draft has moved since this was scheduled\n",
			yellow, reset, short(f.Commit))
		w.Human("          %squilzo schedule cancel %s, then schedule again%s\n",
			dim, short(f.Commit), reset)
	case "would-publish":
		w.Human("  %swould publish%s %s, scheduled by %s\n", dim, reset, short(f.Commit), f.By)
	}
}

// lateBy is how late something was, in the unit a person would say it in:
// "4 minutes", "3 hours", "2 days", and never "4m12.093s".
func lateBy(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours())/24)
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	case d >= 2*time.Minute:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	default:
		return "a minute"
	}
}

// errRunnerMayNotPublish is fireDue refusing to fire anything, and leaving
// every entry as it was, because whatever is running it may not publish.
var errRunnerMayNotPublish = errors.New("may not publish")

// fireDue publishes every entry whose time has come.
//
// # Whose authority
//
// A scheduled publish goes out on the authority of the person who
// scheduled it, checked when it fires, and of whatever fires it. Both.
//
// The runner alone was the old rule: `schedule run` checked the token cron
// held, which is usually an administrator's. Somebody who scheduled a
// launch and then lost the publisher role, or whose grant ran out, still
// had it published, by an identity that never looked at it. The scheduler
// alone would let a forged entry in schedule.json publish as anybody; a
// process that can write that file can also move the draft, so it gains
// nothing a runner it is not could not already do, and that is why the
// runner is checked too. Their intersection is the least this act needs.
//
// The scheduled act carries the publisher role and no more, whatever else
// the person holds: it is a publish, so that is all it may be.
//
// # Every gate, now
//
// It goes through publishAs, the publish command itself, so the
// accessibility gate, provenance, content types, the freeze and dual
// authorisation run against the content as it stands when it fires.
//
// # Once
//
// Under the schedule's lock it decides what is due and claims it, then
// publishes with the lock let go — publishing tells webhooks, and a slow
// receiver must not hold up somebody adding an entry in the browser — and
// takes the lock again to record what happened. A timer and a cron job
// firing together publish an entry once: the second finds it claimed.
func fireDue(root string, runner *Caller, now func() time.Time, opts fireOptions) ([]firing, error) {
	var out []firing
	var claimed []schedule.Entry
	err := updateSchedule(root, func(sch *schedule.Schedule) error {
		due := sch.Due(now())
		if len(due) == 0 {
			return errNothingToSave
		}
		s, err := open(root)
		if err != nil {
			return err
		}
		draft := s.GetRef(site.RefDraft)

		// The runner first, and before any entry is touched: a server started
		// without an identity that may publish leaves every entry pending, for
		// a timer that has one, rather than marking them refused.
		if !opts.dry {
			if err := authorise(root, runner, auth.ActPublish, "/"); err != nil {
				return fmt.Errorf("%s %w, so nothing scheduled was published: %v",
					runner.Name, errRunnerMayNotPublish, err)
			}
		}
		for _, e := range due {
			f := firing{Commit: e.Commit, By: e.By, At: e.At}
			switch {
			case draft != "" && e.Commit != draft:
				// Refused rather than fired. The entry describes bytes that are
				// no longer what anybody is looking at, and publishing them
				// because a clock said so is how a scheduled publish surprises
				// everyone.
				f.Outcome = "stale"
				out = append(out, f)
			case opts.dry:
				f.Outcome = "would-publish"
				out = append(out, f)
			default:
				if sch.Claim(e.Commit, now()) {
					claimed = append(claimed, e)
				}
			}
		}
		if len(claimed) == 0 {
			return errNothingToSave
		}
		return nil
	})
	if err != nil && !errors.Is(err, errNothingToSave) {
		return out, err
	}
	if len(claimed) == 0 {
		return out, nil
	}

	results := make([]firing, 0, len(claimed))
	for _, e := range claimed {
		f := firing{Commit: e.Commit, By: e.By, At: e.At}
		perr := publishAs(root, []string{e.Commit}, scheduledBy(e, runner),
			publishFlags{tplDir: opts.templates})
		if late := now().Sub(time.Unix(e.At, 0)); late > time.Minute {
			f.Late = late
		}
		if perr != nil {
			f.Outcome, f.Reason = "refused", perr.Error()
		} else {
			f.Outcome = "published"
		}
		results = append(results, f)
	}
	err = updateSchedule(root, func(sch *schedule.Schedule) error {
		at := now()
		for _, f := range results {
			result := "published"
			switch {
			case f.Outcome == "refused":
				result = "refused: " + f.Reason
			case f.Late > 0:
				result = fmt.Sprintf("published %s late", lateBy(f.Late))
			}
			sch.Complete(f.Commit, result, at)
		}
		return nil
	})
	return append(out, results...), err
}

// errNothingToSave ends an update that changed nothing, so the schedule is
// not written back for no reason.
var errNothingToSave = errors.New("nothing to save")

// fireOptions are how fireDue publishes: as a dry run, and with which
// templates the accessibility gate renders pages through — the server's
// own, so a scheduled publish is checked as the site will be served.
type fireOptions struct {
	dry       bool
	templates string
}

// scheduledBy is the caller a scheduled publish acts as: the person who
// scheduled it, holding the publisher role and no more, and as verified as
// they were when they scheduled it.
//
// An entry written before who was verified was recorded counts as
// verified: access control was on and it was let in (the schedule command
// needs a verified identity to publish), or access control was off and
// nothing is checked. One recorded as unverified is checked as that, so it
// fires on a store without access control and is refused on one with it.
func scheduledBy(e schedule.Entry, runner *Caller) *Caller {
	verified := e.Verified == nil || *e.Verified
	kind := audit.Kind(e.Kind)
	if kind == "" {
		kind = audit.KindHuman
	}
	c := &Caller{Name: e.By, Kind: kind, Verified: verified, Role: auth.RolePublisher,
		Via: "schedule", FiredBy: runner.Name}
	if !verified {
		c.Why = "they were not a verified identity when they scheduled it"
	}
	return c
}

// schedulePoll bounds how long the server's timer sleeps, so an entry the
// command line or another process added is noticed within it.
const schedulePoll = 30 * time.Second

// scheduler is what runScheduler is given: whether it is on
// (schedule.in_server, read on every pass so turning it off takes effect
// without a restart), who it fires as, and where it says what happened.
type scheduler struct {
	templates string
	// poll is the longest it sleeps; schedulePoll when zero.
	poll   time.Duration
	on     func() bool
	runner func() *Caller
	report func(firing, error)
}

// runScheduler publishes scheduled entries at their time, inside quilzo
// serve, until ctx is done.
//
// # Why in the server now
//
// Scheduled publishing used to need a timer calling `quilzo schedule run`,
// on the argument that a scheduler which is also a long-lived process is a
// second thing that can be down. That was right while it would have been a
// second process. It is the server's own goroutine here, so it is down
// exactly when the admin is, and the posture check reports an entry that
// did not fire either way. What the old rule cost was real: an operator who
// never set up the cron entry had launches that silently did not happen,
// the commonest complaint about scheduling in any CMS.
//
// It sleeps until the next entry is due, and never more than schedulePoll,
// so a publish goes out within a second of its time and an entry added
// elsewhere is seen within half a minute. It fires what is overdue when it
// starts, so a restart over nine o'clock publishes at once rather than
// never. Who it fires as is resolved each time, so a token that expires or
// is revoked while the server runs stops it publishing.
func runScheduler(ctx context.Context, root string, sc scheduler) {
	lastErr := ""
	for {
		var fired []firing
		var err error
		if sc.on() {
			fired, err = fireDue(root, sc.runner(), time.Now, fireOptions{templates: sc.templates})
		}
		switch {
		case err != nil:
			// Said once, not every half minute, and said again only when it
			// changes: the same refusal on every tick is noise that hides
			// the next different one.
			if err.Error() != lastErr {
				sc.report(firing{}, err)
			}
			lastErr = err.Error()
		default:
			lastErr = ""
			for _, f := range fired {
				if f.Outcome != "stale" {
					sc.report(f, nil)
				}
			}
		}

		wait := sc.poll
		if wait <= 0 {
			wait = schedulePoll
		}
		if sch, lerr := loadSchedule(root); lerr == nil {
			if next, ok := sch.Next(time.Now()); ok {
				if d := time.Until(next); d < wait {
					wait = d
				}
			}
		}
		if wait < 0 {
			wait = 0
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
