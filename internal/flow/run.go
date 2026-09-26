// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package flow

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Rejected is how many items one filter turned away, and where they went.
type Rejected struct {
	Step  string   `json:"step"`
	Kind  ExitKind `json:"kind"`
	To    string   `json:"to,omitempty"`
	Why   string   `json:"why,omitempty"`
	Count int      `json:"count"`
}

// Failure is one item a step could not handle.
//
// Named down to the item, not counted. "Seventeen failures" is a number
// somebody acknowledges; "seventeen failures, all of them in post-to-slack,
// all of them rate limited" is a thing somebody fixes.
type Failure struct {
	Step  string `json:"step"`
	Item  string `json:"item"`
	Error string `json:"error"`
	Tries int    `json:"tries"`
}

// Run is one execution, and its accounts.
//
// The accounts are the point. In is what arrived. Acted, Rejects, Failed
// and Held are where it all went, and they have to add up: a run that
// cannot say what became of every item is not a run that mostly worked.
type Run struct {
	Flow    string    `json:"flow"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended,omitzero"`

	// From and To are the window of source time this run covered.
	//
	// Not the same as Started and Ended, which are when the run happened.
	// The window is what lets consecutive runs be checked for gaps, which
	// is how polling silently misses data when a source is busy.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`

	In      int        `json:"in"`
	Acted   int        `json:"acted"`
	Held    int        `json:"held"`
	Rejects []Rejected `json:"rejects,omitempty"`
	Failed  []Failure  `json:"failed,omitempty"`
}

// Reject records items a filter turned away.
func (r *Run) Reject(s Step, n int) error {
	if s.Kind != Keep {
		return fmt.Errorf("%q is a %s and rejects nothing", s.Name, s.Kind)
	}
	if s.Rejects == nil {
		return fmt.Errorf("%q has no exit for its rejects", s.Name)
	}
	if n < 0 {
		return fmt.Errorf("a negative rejection is not a thing")
	}
	for i := range r.Rejects {
		if r.Rejects[i].Step == s.Name {
			r.Rejects[i].Count += n
			return nil
		}
	}
	r.Rejects = append(r.Rejects, Rejected{
		Step: s.Name, Kind: s.Rejects.Kind, To: s.Rejects.To,
		Why: s.Rejects.Why, Count: n,
	})
	return nil
}

// Fail records an item a step could not handle.
func (r *Run) Fail(step, item, err string, tries int) {
	r.Failed = append(r.Failed, Failure{
		Step: step, Item: item, Error: err, Tries: tries,
	})
}

// Out is everything that left the run.
func (r Run) Out() int {
	n := r.Acted + r.Held + len(r.Failed)
	for _, rj := range r.Rejects {
		n += rj.Count
	}
	return n
}

// Unaccounted is what came in and cannot be explained.
//
// The number this package exists to make impossible to ignore. Positive
// means items vanished; negative means the run claims to have done more
// than it received, which is a different bug and an equally real one.
func (r Run) Unaccounted() int { return r.In - r.Out() }

// Balances reports whether the accounts add up.
func (r Run) Balances() bool { return r.Unaccounted() == 0 }

// Check refuses a run that cannot say where everything went.
//
// It is deliberately an error and not a warning. A warning on a run that
// lost data is a line in a log, and a line in a log is how it is found six
// weeks later by somebody looking for something else.
func (r Run) Check() error {
	if r.In < 0 {
		return fmt.Errorf("a run cannot receive %d items", r.In)
	}
	if n := r.Unaccounted(); n > 0 {
		return fmt.Errorf(
			"%d of %d item(s) in this run of %q are unaccounted for. They "+
				"were not acted on, no filter says it rejected them, no "+
				"step says it failed on them, and they are not being held. "+
				"That is the shape of data being lost quietly, and it is "+
				"the failure rather than a note attached to a success",
			n, r.In, r.Flow)
	} else if n < 0 {
		return fmt.Errorf(
			"this run of %q accounts for %d item(s) and received %d. "+
				"Something is being counted twice, which makes every other "+
				"number here unreliable", r.Flow, r.Out(), r.In)
	}
	if !r.To.IsZero() && r.To.Before(r.From) {
		return fmt.Errorf("this run covers a window that ends before it " +
			"starts")
	}
	return nil
}

// Dropped is how many items this run threw away.
func (r Run) Dropped() int {
	n := 0
	for _, rj := range r.Rejects {
		if rj.Kind == Drop {
			n += rj.Count
		}
	}
	return n
}

// Quiet reports whether a run did nothing at all.
//
// Distinguished from a failure on purpose: a flow that received nothing is
// not broken, and a flow that received a hundred items and acted on none is
// not quiet. Conflating them is how a filter that started matching
// everything goes unnoticed for a month.
func (r Run) Quiet() bool { return r.In == 0 }

// Why describes a run in a sentence.
func (r Run) Why() string {
	switch {
	case r.Quiet():
		return "nothing arrived"
	case !r.Balances():
		return fmt.Sprintf("%d of %d item(s) are unaccounted for",
			r.Unaccounted(), r.In)
	case r.Acted == 0 && r.In > 0:
		return fmt.Sprintf("%d item(s) arrived and none were acted on; "+
			"%s", r.In, r.wherefore())
	case len(r.Failed) > 0:
		return fmt.Sprintf("%d of %d acted on, %d failed", r.Acted, r.In,
			len(r.Failed))
	}
	return fmt.Sprintf("%d of %d acted on", r.Acted, r.In)
}

func (r Run) wherefore() string {
	var parts []string
	for _, rj := range r.Rejects {
		if rj.Count == 0 {
			continue
		}
		switch rj.Kind {
		case Drop:
			parts = append(parts, fmt.Sprintf("%s dropped %d (%s)",
				rj.Step, rj.Count, rj.Why))
		case Divert:
			parts = append(parts, fmt.Sprintf("%s sent %d to %s",
				rj.Step, rj.Count, rj.To))
		case Hold:
			parts = append(parts, fmt.Sprintf("%s held %d", rj.Step,
				rj.Count))
		}
	}
	if len(parts) == 0 {
		return "and no step says why"
	}
	return strings.Join(parts, ", ")
}

// Gap is a stretch of source time no run covered.
type Gap struct {
	From time.Time     `json:"from"`
	To   time.Time     `json:"to"`
	For  time.Duration `json:"for"`
	// After names the run that ended before the gap, so somebody has
	// somewhere to start looking.
	After time.Time `json:"after"`
}

// Gaps is the source time that no run covered.
//
// Polling misses data when the source is busy or rate-limited, and the
// evidence is right here and is never looked at: one run's window ends
// where the next one's begins, until one day it does not. Finding the gap
// is the difference between knowing what was lost and discovering it when
// somebody asks where their record went.
func Gaps(runs []Run) []Gap {
	windowed := make([]Run, 0, len(runs))
	for _, r := range runs {
		if !r.From.IsZero() && !r.To.IsZero() {
			windowed = append(windowed, r)
		}
	}
	sort.SliceStable(windowed, func(i, j int) bool {
		return windowed[i].From.Before(windowed[j].From)
	})
	var out []Gap
	for i := 1; i < len(windowed); i++ {
		prev, next := windowed[i-1], windowed[i]
		if !next.From.After(prev.To) {
			continue // Contiguous, or overlapping, which loses nothing.
		}
		out = append(out, Gap{
			From: prev.To, To: next.From, For: next.From.Sub(prev.To),
			After: prev.Started,
		})
	}
	return out
}

// Trouble is something wrong with a flow, ranked rather than thresholded.
type Trouble struct {
	Flow string `json:"flow"`
	What string `json:"what"`
	// Weight orders trouble. Losing data outranks a flow being late,
	// which outranks a flow being loud, because that is the order somebody
	// would work on them if they could see all three at once.
	Weight int    `json:"weight"`
	Detail string `json:"detail,omitempty"`
}

// Weights, stated rather than buried in comparisons.
const (
	// Lost: items vanished. Nothing else on a board matters more.
	Lost = 100
	// Missed: a stretch of source time nobody covered.
	Missed = 90
	// Silent: the flow has stopped running.
	Silent = 80
	// Broke: steps are failing.
	Broke = 60
	// Discarding: the flow is running and throwing everything away, which
	// is the failure that looks most like success.
	Discarding = 50
)

// Look examines a flow's recent runs and reports what is wrong.
//
// Ranked, not thresholded. A list of everything wrong in the order somebody
// would fix it beats an alert per condition, because an alert per condition
// is how a team learns to ignore alerts.
func (f Flow) Look(runs []Run, at time.Time) []Trouble {
	var out []Trouble
	var last time.Time
	for _, r := range runs {
		if r.Started.After(last) {
			last = r.Started
		}
		if n := r.Unaccounted(); n > 0 {
			out = append(out, Trouble{
				Flow: f.Name, Weight: Lost,
				What: fmt.Sprintf("%d item(s) unaccounted for", n),
				Detail: fmt.Sprintf("in the run that started %s",
					r.Started.Format(time.RFC3339)),
			})
		}
		if len(r.Failed) > 0 {
			out = append(out, Trouble{
				Flow: f.Name, Weight: Broke,
				What:   fmt.Sprintf("%d item(s) failed", len(r.Failed)),
				Detail: worstOf(r.Failed),
			})
		}
	}
	for _, g := range Gaps(runs) {
		out = append(out, Trouble{
			Flow: f.Name, Weight: Missed,
			What: fmt.Sprintf("%s of source time no run covered",
				plainly(g.For)),
			Detail: fmt.Sprintf("between %s and %s",
				g.From.Format(time.RFC3339), g.To.Format(time.RFC3339)),
		})
	}
	if over, by := f.Overdue(last, at); over {
		what := "has never run"
		if !last.IsZero() {
			what = fmt.Sprintf("overdue by %s", plainly(by))
		}
		out = append(out, Trouble{Flow: f.Name, Weight: Silent, What: what,
			Detail: fmt.Sprintf("expected every %s", plainly(f.Every))})
	}
	if n, items := barren(runs); n >= 2 {
		out = append(out, Trouble{
			Flow: f.Name, Weight: Discarding,
			What: fmt.Sprintf("%d run(s) in a row took %d item(s) and "+
				"acted on none", n, items),
			Detail: "the failure that looks most like a quiet week. A " +
				"filter that started matching everything produces exactly " +
				"this, and the only difference from a genuinely quiet " +
				"week is a number nobody is shown",
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Weight > out[j].Weight
	})
	return out
}

// barren is the longest run of consecutive executions that received work
// and did none of it.
//
// A streak rather than a total, because the total is wrong in both
// directions: a flow that worked this morning and has discarded everything
// since is broken, and a flow that had one busy hour in a quiet week is
// not. What a broken filter looks like is a stretch where items kept
// arriving and nothing kept happening.
func barren(runs []Run) (n, items int) {
	in := append([]Run(nil), runs...)
	sort.SliceStable(in, func(i, j int) bool {
		return in[i].Started.Before(in[j].Started)
	})
	var streak, got int
	for _, r := range in {
		if r.In > 0 && r.Acted == 0 {
			streak++
			got += r.In
			if streak > n {
				n, items = streak, got
			}
			continue
		}
		if r.In > 0 {
			streak, got = 0, 0
		}
	}
	return n, items
}

func worstOf(f []Failure) string {
	by := map[string]int{}
	for _, e := range f {
		by[e.Step]++
	}
	type pair struct {
		step string
		n    int
	}
	var ps []pair
	for s, n := range by {
		ps = append(ps, pair{s, n})
	}
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].n != ps[j].n {
			return ps[i].n > ps[j].n
		}
		return ps[i].step < ps[j].step
	})
	if len(ps) == 0 {
		return ""
	}
	first := f[0].Error
	for _, e := range f {
		if e.Step == ps[0].step {
			first = e.Error
			break
		}
	}
	return fmt.Sprintf("%d in %s, the first being %q", ps[0].n, ps[0].step,
		first)
}

func plainly(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d second(s)", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d.Hours()))
	}
	return fmt.Sprintf("%d day(s)", int(d.Hours()/24))
}
