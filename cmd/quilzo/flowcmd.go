// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/flow"
)

// Automation that cannot lose anything quietly.
//
// Zapier's own troubleshooting advice says that every time you use a filter
// or a path you must ask what happens to the data that does not pass, and
// that without an else-path or a fallback notification that data is gone
// forever. It is a description of the default behaviour of the largest
// automation platform there is, and it is why an industry of third-party
// monitors exists whose whole product is telling you your automation
// stopped.
//
// `flow demo` builds one and shows the three failures that are invisible
// everywhere else: a run that lost items, a flow that ran perfectly and
// discarded everything, and a stretch of source time no run covered.

func cmdFlow(args []string) error {
	if len(args) == 0 {
		args = []string{"demo"}
	}
	switch args[0] {
	case "demo":
		return flowDemo(args[1:])
	default:
		return fmt.Errorf("unknown flow command %q; try demo", args[0])
	}
}

func flowDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	at := time.Now().UTC().Truncate(time.Hour)
	hour := func(n int) time.Time {
		return at.Add(time.Duration(n-8) * time.Hour)
	}

	f := flow.Flow{
		Name: "incidents", What: "page the on-call for new criticals",
		Every: time.Hour,
		Steps: []flow.Step{
			{Name: "only criticals", Kind: flow.Keep},
			{Name: "add the runbook", Kind: flow.Change},
			{Name: "page the on-call", Kind: flow.Act,
				Reaches: "pagerduty", Retries: 3},
		},
	}

	// The thing every automation platform lets you build.
	w.Human("%sthe flow as somebody would first write it%s\n", bold, reset)
	if err := f.Validate(); err != nil {
		w.Human("  %srefused%s %s\n", green, reset,
			wrapAt(firstLine(err), 64, "          "))
	} else {
		return fmt.Errorf("a filter with no exit was accepted")
	}
	f.Steps[0].Rejects = &flow.Exit{Kind: flow.Drop,
		Why: "not worth a page at night"}
	if err := f.Validate(); err != nil {
		return err
	}
	w.Human("  %sonce the filter says where its rejects go, it validates. "+
		"The\n  drop is still a drop — it is now a decision somebody made "+
		"and\n  signed rather than a default%s\n\n", dim, reset)

	// A run whose books balance.
	good := flow.Run{Flow: f.Name, Started: hour(1), Ended: hour(1),
		From: hour(0), To: hour(1), In: 100, Acted: 3, Held: 1}
	if err := good.Reject(f.Steps[0], 95); err != nil {
		return err
	}
	good.Fail("page the on-call", "inc-9", "rate limited", 3)
	w.Human("%sa run that adds up%s\n", bold, reset)
	ledger(good)
	if err := good.Check(); err != nil {
		return err
	}
	w.Human("  %s%s%s\n\n", dim, good.Why(), reset)

	// The same run, as every other platform would report it.
	bad := flow.Run{Flow: f.Name, Started: hour(2), Ended: hour(2),
		From: hour(1), To: hour(2), In: 100, Acted: 3}
	if err := bad.Reject(f.Steps[0], 40); err != nil {
		return err
	}
	w.Human("%sthe same run with a step that quietly ate things%s\n", bold,
		reset)
	ledger(bad)
	if err := bad.Check(); err != nil {
		w.Human("  %srefused%s %s\n", green, reset,
			wrapAt(firstLine(err), 64, "          "))
	} else {
		return fmt.Errorf("a run that lost 57 items passed")
	}
	w.Human("  %severywhere else this is a green tick and a log line "+
		"saying\n  \"3 tasks succeeded\"%s\n\n", dim, reset)

	// A week where the filter started matching everything.
	var runs []flow.Run
	runs = append(runs, good, bad)
	for i := 3; i <= 6; i++ {
		r := flow.Run{Flow: f.Name, Started: hour(i), Ended: hour(i),
			From: hour(i - 1), To: hour(i), In: 25}
		if err := r.Reject(f.Steps[0], 25); err != nil {
			return err
		}
		if err := r.Check(); err != nil {
			return err
		}
		runs = append(runs, r)
	}
	// And a gap, because the source was busy and polling fell behind.
	late := flow.Run{Flow: f.Name, Started: hour(9), Ended: hour(9),
		From: hour(8), To: hour(9), In: 4, Acted: 4}
	runs = append(runs, late)

	w.Human("%swhat the week looked like%s\n", bold, reset)
	for _, r := range runs {
		mark := " "
		if !r.Balances() {
			mark = "!"
		}
		w.Human("  %s%s%s %s  %sin %-4d acted %-3d dropped %d%s\n",
			yellow, mark, reset, r.Started.Format("15:04"), dim, r.In,
			r.Acted, r.Dropped(), reset)
	}
	w.Human("\n")

	w.Human("%swhat is wrong, in the order somebody would fix it%s\n", bold,
		reset)
	trouble := f.Look(runs, hour(11))
	for _, t := range trouble {
		w.Human("  %s%-3d%s %s\n", dim, t.Weight, reset, t.What)
		if t.Detail != "" {
			w.Human("      %s%s%s\n", dim, wrapAt(t.Detail, 62, "      "),
				reset)
		}
	}
	if w.JSON(map[string]any{
		"flow": f, "runs": runs, "trouble": trouble,
		"gaps": flow.Gaps(runs),
	}) {
		return nil
	}
	w.Human("\n  %sranked rather than one alert per condition, because an "+
		"alert\n  per condition is how a team learns to ignore alerts. And "+
		"none of\n  these had to be switched on: losing data, missing a "+
		"window and\n  going quiet are not opt-in notifications here, they "+
		"are what a\n  run failing to add up means%s\n", dim, reset)
	return nil
}

func ledger(r flow.Run) {
	w.Human("  %s%-22s %6d%s\n", dim, "arrived", r.In, reset)
	w.Human("  %s%-22s %6d%s\n", dim, "  acted on", r.Acted, reset)
	for _, rj := range r.Rejects {
		w.Human("  %s%-22s %6d  (%s)%s\n", dim, "  "+rj.Step, rj.Count,
			rj.Kind, reset)
	}
	if len(r.Failed) > 0 {
		w.Human("  %s%-22s %6d%s\n", dim, "  failed", len(r.Failed), reset)
	}
	if r.Held > 0 {
		w.Human("  %s%-22s %6d%s\n", dim, "  held", r.Held, reset)
	}
	colour := green
	if !r.Balances() {
		colour = yellow
	}
	w.Human("  %s%-22s %6d%s\n", colour, "unaccounted for",
		r.Unaccounted(), reset)
}
