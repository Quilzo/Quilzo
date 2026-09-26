// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/work"
)

// Four states, and why that is enough.
//
// Every Jira administrator has had the conversation about how many statuses
// is too many, and Atlassian's own community has a thread called Worst Jira
// Admin Contest: Multiple Green Statuses. The usual diagnosis is that
// people are not thinking clearly, which is why the problem never goes
// away: "dev done" and "ready for test" are the same moment from two sides,
// and "in review", "awaiting QA" and "blocked" are not states of the work
// at all. They are statements about who is holding it up, put in the only
// field available.
//
// `work demo` builds a board with the states a team would have invented and
// shows what they turn into.

func cmdWork(args []string) error {
	if len(args) == 0 {
		args = []string{"demo"}
	}
	switch args[0] {
	case "demo":
		return workDemo(args[1:])
	default:
		return fmt.Errorf("unknown work command %q; try demo", args[0])
	}
}

func workDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	stale := fs.Duration("stale", 7*24*time.Hour,
		"how long without moving counts as stuck")
	if err := fs.Parse(args); err != nil {
		return err
	}
	at := time.Now().UTC()
	day := func(n int) time.Time {
		return at.Add(-time.Duration(n) * 24 * time.Hour)
	}

	b, err := work.NewBoard("eng",
		work.Kind{Name: "change", Requires: []string{"reviewed", "tested"}},
		work.Kind{Name: "chore"},
	)
	if err != nil {
		return err
	}

	// The statuses a team would have invented, and what each one really is.
	w.Human("%swhat a team would have made statuses for%s\n\n", bold, reset)
	type row struct {
		was   string
		title string
		kind  string
		owner string
		state work.State
		wait  *work.Waiting
		since int
	}
	rows := []row{
		{"in review", "write the migration", "change", "grace", work.Doing,
			&work.Waiting{Kind: work.OnPerson, On: "alan",
				For: "a review"}, 9},
		{"awaiting QA", "rotate the signing key", "change", "grace",
			work.Doing, &work.Waiting{Kind: work.OnTeam, On: "platform",
				For: "a test environment"}, 14},
		{"blocked", "upgrade the parser", "change", "alan", work.Doing,
			&work.Waiting{Kind: work.OnThing, On: "upstream",
				For: "the 3.2 release"}, 21},
		{"ready for deploy", "tidy the logs", "chore", "alan", work.Doing,
			&work.Waiting{Kind: work.OnTime, For: "the friday window",
				Until: at.Add(48 * time.Hour)}, 2},
		{"in progress", "write the migration", "change", "priya",
			work.Doing, nil, 26},
		{"to do", "document the rotation", "chore", "", work.Todo, nil, 3},
	}
	for _, r := range rows {
		it, err := b.Add(r.title, r.kind, r.owner,
			work.Origin{Kind: work.FromPerson, Who: "ada", At: day(r.since)},
			day(r.since))
		if err != nil {
			return err
		}
		if r.state != work.Todo {
			if err := b.Move(it.ID, r.state, r.owner+"", "",
				day(r.since)); err != nil {
				return err
			}
		}
		if r.wait != nil {
			wt := *r.wait
			wt.Since = day(r.since)
			if err := b.Wait(it.ID, wt, day(r.since)); err != nil {
				return err
			}
		}
		w.Human("  %s%-17s%s %s\n", yellow, r.was, reset, r.title)
		w.Human("    %s→ %s", dim, r.state)
		if r.wait != nil {
			if r.wait.Kind == work.OnTime {
				w.Human(", waiting for %s", r.wait.For)
			} else {
				w.Human(", waiting on %s for %s", r.wait.On, r.wait.For)
			}
		}
		w.Human("%s\n", reset)
	}
	w.Human("\n  %ssix statuses become two states and a dimension that "+
		"names\n  somebody. The dimension is the thing the statuses were "+
		"always\n  carrying, and unlike a word it can be asked "+
		"questions%s\n\n", dim, reset)

	// The question a status cannot answer.
	w.Human("%swhat is alan holding up%s\n", bold, reset)
	for _, it := range b.Blocking("alan") {
		w.Human("  %s — %s%s, %s%s\n", it.Title, dim, it.Owner,
			plainly(it.Waiting.Held(at)), reset)
	}
	w.Human("  %sin a tracker where \"in review\" is a word, this is a "+
		"question\n  you ask in a meeting and get \"I think you have a "+
		"couple of mine?\"%s\n\n", dim, reset)

	w.Human("%swho the board is waiting on%s\n", bold, reset)
	for _, l := range b.Queue(at) {
		w.Human("  %-10s %s%d item(s), worst %s (%s)%s\n", l.On, dim,
			l.Items, plainly(l.Worst), l.Kind, reset)
	}
	w.Human("\n")

	w.Human("%swhat has stopped moving%s\n", bold, reset)
	for _, s := range b.Stuck(*stale, at) {
		w.Human("  %s%-28s%s %s%s%s\n", bold, s.Item.Title, reset, dim,
			plainly(s.For), reset)
		w.Human("    %s%s%s\n", dim, s.Why, reset)
	}
	w.Human("  %sthe friday window has not arrived, so that one is not "+
		"stuck.\n  A wait on a date is the only kind nobody can be chased "+
		"about%s\n\n", dim, reset)

	// Duplicates.
	w.Human("%sthe same work twice%s\n", bold, reset)
	for _, group := range b.Twice() {
		for _, it := range group {
			owner := it.Owner
			if owner == "" {
				owner = "nobody"
			}
			w.Human("  %s %s(%s, %s)%s\n", it.Title, dim, owner, it.State,
				reset)
		}
	}
	w.Human("  %sreported, not merged. Two similar titles are sometimes "+
		"two\n  pieces of work, and silently joining them would be worse "+
		"than\n  the duplication%s\n\n", dim, reset)

	// The definition of done.
	w.Human("%sfinishing something%s\n", bold, reset)
	mine := b.Blocking("alan")[0]
	if err := b.Meet(mine.ID, "reviewed"); err != nil {
		return err
	}
	if err := b.Move(mine.ID, work.Done, "grace", "", at); err == nil {
		return fmt.Errorf("it finished without meeting its definition")
	} else {
		w.Human("  %srefused%s %s\n", green, reset,
			wrapAt(firstLine(err), 64, "          "))
	}
	if err := b.Excuse(mine.ID, "tested", "ada",
		"covered by the integration suite"); err != nil {
		return err
	}
	if err := b.Move(mine.ID, work.Done, "grace", "", at); err != nil {
		return err
	}
	w.Human("  %sdone, with \"tested\" excused by ada rather than met. "+
		"That\n  difference is the only thing anybody wants to know a "+
		"quarter\n  later, and a green status cannot hold it%s\n\n",
		dim, reset)

	shape := b.Look(*stale, at)
	if w.JSON(map[string]any{"shape": shape, "queue": b.Queue(at)}) {
		return nil
	}
	w.Human("%sthe board%s\n", bold, reset)
	w.Human("  %s%d item(s), %d open, %d waiting on somebody%s\n", dim,
		shape.Items, shape.Open, shape.Waiting, reset)
	if why := shape.Why(); why != "" {
		w.Human("  %s%s%s\n", yellow, wrapAt(why, 64, "  "), reset)
	}
	return nil
}

func plainly(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s)", int(d.Hours()/24))
}
