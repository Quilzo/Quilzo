// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package upkeep runs the work that has to happen because time passed.
//
// # The bug this exists for
//
// A form declares how long its submissions are kept. internal/form said so
// plainly: "That ceiling is enforced when somebody enforces it… If nobody runs
// either, submissions past their declared ceiling are kept indefinitely." The
// disclosure was honest and the gap was real, and a declared retention period
// that nothing enforces is worse than none — the declaration is what a data
// protection authority reads, and what the person filling in the form is told.
//
// Nothing ran it. There is no installer here, so there was no moment at which
// somebody was handed a cron entry, and an operator who had not read that
// comment had a site that promised to forget and did not.
//
// # Why this, and not a daemon for everything
//
// `quilzo schedule run` deliberately does not daemonise, and says why: "a
// scheduler that is also a long-lived process is a second thing that can be
// down, and the machinery for running something every minute already exists on
// every system this runs on." That argument is right and this does not
// contradict it.
//
// It is an argument about publishing, which is a gated write that has to be
// deterministic and auditable, and where firing late is better than firing from
// a process nobody is watching. Expiring a submission is neither of those
// things: it is a delete in a mutable directory the serving process already
// writes to, it is idempotent, and nothing downstream depends on the minute it
// happens. So the two get different answers, and scheduled publishing keeps its
// timer while retention stops needing one.
//
// # Once at the start, then on the clock
//
// A process restarted more often than the interval would otherwise never sweep
// at all. That is the failure mode of every ticker-only loop: it works on the
// machine that stays up and not on the deployment that restarts on release.
package upkeep

import (
	"context"
	"time"
)

// Every is how often the loop wakes.
//
// Retention is measured in days and this is measured in minutes, so the
// interval only has to be small against the ceiling rather than close to it.
// Sweeping a directory every quarter of an hour costs nothing and bounds how
// long a submission outlives its period by an amount nobody has to think about.
const Every = 15 * time.Minute

// A Job is one piece of work, and the name to report it under.
//
// It returns how many things it did, because a sweep that did nothing and a
// sweep that removed four hundred submissions should not look the same.
type Job struct {
	Name string
	Do   func(now time.Time) (int, error)
}

// Run does every job now, and again on every tick, until ctx is done.
//
// An error does not stop the loop. These are sweeps over a directory other
// processes are writing to, so a failure is usually a file that moved
// underneath, and a loop that exits on the first one stops doing the job it
// exists for — silently, which is how this area went wrong in the first place.
// It is reported, and the next tick tries again.
func Run(ctx context.Context, every time.Duration, report func(Job, int, error), jobs ...Job) {
	if len(jobs) == 0 {
		return
	}
	if every <= 0 {
		every = Every
	}
	do := func() {
		for _, j := range jobs {
			n, err := j.Do(time.Now())
			// Silence when there was nothing to do. A line every quarter of an
			// hour saying nothing happened is a log nobody reads, and this has
			// to be readable on the day it says something.
			if report != nil && (n > 0 || err != nil) {
				report(j, n, err)
			}
		}
	}

	do()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			do()
		}
	}
}
