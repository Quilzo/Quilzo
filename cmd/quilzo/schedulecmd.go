package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/site"
)

func schedulePath(root string) string { return filepath.Join(root, "schedule.json") }

func loadSchedule(root string) (*schedule.Schedule, error) {
	s := &schedule.Schedule{}
	return s, loadJSON(schedulePath(root), s)
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

	sch, err := loadSchedule(root)
	if err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	if err := sch.Add(draft, when, caller.Name, *note, time.Now()); err != nil {
		return errBlocked{err}
	}
	if err := saveJSON(schedulePath(root), sch); err != nil {
		return err
	}

	record(root, audit.Record{
		Action: "schedule.add", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{
			"scheduled": draft, "at": when.UTC().Format(time.RFC3339),
			"note": truncate(*note, 200),
		},
	})

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
	sch, err := loadSchedule(root)
	if err != nil {
		return err
	}
	if !sch.Cancel(args[0]) {
		return fmt.Errorf("nothing pending matches %q", args[0])
	}
	if err := saveJSON(schedulePath(root), sch); err != nil {
		return err
	}
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "schedule.cancel", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
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
// Meant for a timer — systemd, cron, a Kubernetes CronJob. It does not daemonise,
// because a scheduler that is also a long-lived process is a second thing that
// can be down, and the machinery for running something every minute already
// exists on every system this runs on.
func scheduleRun(root string, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "report what would publish and change nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sch, err := loadSchedule(root)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	draft := s.GetRef(site.RefDraft)
	now := time.Now()

	due := sch.Due(now)
	if len(due) == 0 {
		w.Human("%snothing due%s\n", dim, reset)
		return nil
	}

	for _, e := range due {
		if draft != "" && e.Commit != draft {
			// Refused rather than fired. The entry describes bytes that are no
			// longer what anybody is looking at, and publishing them because a
			// clock said so is how a scheduled publish surprises everyone.
			w.Human("  %sskipped%s %s — the draft has moved since this was "+
				"scheduled\n", yellow, reset, short(e.Commit))
			w.Human("          %squilzo schedule cancel %s, then schedule "+
				"again%s\n", dim, short(e.Commit), reset)
			continue
		}
		if *dry {
			w.Human("  %swould publish%s %s\n", dim, reset, short(e.Commit))
			continue
		}

		// Publishing goes through the ordinary command, so every gate —
		// accessibility, provenance, content types, dual authorization — runs
		// now, against the content as it stands, rather than having run when
		// somebody clicked schedule.
		if err := cmdPublish(root, []string{e.Commit}); err != nil {
			sch.Complete(e.Commit, "refused: "+err.Error())
			w.Human("  %srefused%s %s — %v\n", red, reset, short(e.Commit), err)
			continue
		}
		sch.Complete(e.Commit, "published")
		w.Human("  %spublished%s %s\n", green, reset, short(e.Commit))
	}

	if !*dry {
		if err := saveJSON(schedulePath(root), sch); err != nil {
			return err
		}
	}
	return nil
}
