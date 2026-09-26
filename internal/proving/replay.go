// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package proving

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// MinEvents is how much recorded telemetry a replay has to cover.
//
// Not a statistical threshold, a sanity one: below this the answer is a
// property of the sample rather than of the rule, and a confident number
// from a thousand events is worse than no number because somebody will
// quote it.
const MinEvents = 10_000

// MinWindow is how much wall-clock time the replay has to span.
//
// A day of events tells you about a day. The traffic that makes a
// detection unusable is almost always periodic — a nightly job, a weekly
// reconciliation, a Monday morning — and a replay that never saw one has
// not seen the thing that will wake somebody at four in the morning.
const MinWindow = 24 * time.Hour

// Indiscriminate is the share of events above which a rule is matching
// most of what it sees.
//
// One in twenty. There is no principled threshold here and this is not
// pretending to be one: it is a tripwire for the Channel File 291 shape,
// where a wildcard in the test data meant nobody noticed the rule had
// stopped discriminating. A legitimate rule that matches five percent of
// all telemetry exists, and it should have to be argued for.
const Indiscriminate = 0.05

// Replay is what a candidate did against recorded events.
type Replay struct {
	At     time.Time     `json:"at"`
	Events int           `json:"events"`
	Window time.Duration `json:"window"`
	// Matched is how many events the rule fired on.
	Matched int `json:"matched"`
	// Source names the recording, so a promotion can be traced to the
	// telemetry it was decided on.
	Source string `json:"source,omitempty"`

	// Labelled, True and False come from a replay over events somebody has
	// marked. Optional, because most recordings are not labelled, and the
	// volume number is useful without them.
	Labelled int `json:"labelled,omitempty"`
	True     int `json:"true,omitempty"`
	False    int `json:"false,omitempty"`

	// Samples are a few of the events it matched, kept so the person
	// deciding can look at what they are about to be paged for rather than
	// at a count.
	Samples []string `json:"samples,omitempty"`
}

// MaxSamples caps what a replay carries back.
const MaxSamples = 5

// Validate refuses a replay that cannot be reasoned about.
func (r Replay) Validate() error {
	if r.Events < 0 || r.Matched < 0 {
		return fmt.Errorf("a replay cannot have negative counts")
	}
	if r.Matched > r.Events {
		return fmt.Errorf("this replay matched %d of %d events, which is "+
			"more than it saw", r.Matched, r.Events)
	}
	if r.True+r.False > r.Labelled {
		return fmt.Errorf("more matches are labelled than there are labels")
	}
	return nil
}

// Enough reports whether a replay is big enough to decide on.
func (r Replay) Enough() error {
	if r.Events < MinEvents {
		return fmt.Errorf(
			"this replay covers %d event(s) and the floor is %d. Below "+
				"that the answer is a property of the sample rather than "+
				"of the rule, and a confident number from a small one is "+
				"worse than none because somebody will quote it",
			r.Events, MinEvents)
	}
	if r.Window < MinWindow {
		return fmt.Errorf(
			"this replay spans %s and the floor is %s. The traffic that "+
				"makes a detection unusable is almost always periodic, and "+
				"a replay that never saw a nightly job has not seen the "+
				"thing that will wake somebody up", plainly(r.Window),
			plainly(MinWindow))
	}
	return nil
}

// Share is the fraction of events this matched.
func (r Replay) Share() float64 {
	if r.Events == 0 {
		return 0
	}
	return float64(r.Matched) / float64(r.Events)
}

// Indiscriminate reports whether this matched most of what it saw.
func (r Replay) Indiscriminate() bool { return r.Share() > Indiscriminate }

// Fired reports whether the rule did anything at all.
func (r Replay) Fired() bool { return r.Matched > 0 }

// PerDay is how often this would wake somebody.
//
// The number the whole package exists to produce, and the one every team
// finds out after deploying rather than before.
func (r Replay) PerDay() float64 {
	if r.Window <= 0 {
		return 0
	}
	return float64(r.Matched) / (float64(r.Window) / float64(24*time.Hour))
}

// Precision is the share of matches that were real, when the recording was
// labelled.
func (r Replay) Precision() (float64, bool) {
	if r.True+r.False == 0 {
		return 0, false
	}
	return float64(r.True) / float64(r.True+r.False), true
}

// Why describes a replay for somebody about to decide on it.
//
// Leads with the volume, because that is the cost, and says what the
// precision does or does not tell them. A replay over unlabelled events
// cannot report precision and says so rather than reporting a hundred
// percent, which is what a system that counted only confirmed matches
// would appear to do.
func (r Replay) Why() string {
	if r.Events == 0 {
		return "nothing was replayed"
	}
	rate := fmt.Sprintf("%.1f a day", r.PerDay())
	if r.PerDay() < 1 {
		rate = fmt.Sprintf("%.1f a week", r.PerDay()*7)
	}
	out := fmt.Sprintf("matched %d of %d event(s) over %s — about %s",
		r.Matched, r.Events, plainly(r.Window), rate)
	if p, ok := r.Precision(); ok {
		out += fmt.Sprintf(", and %.0f%% of the labelled matches were real",
			p*100)
		return out
	}
	if r.Matched > 0 {
		out += ". Nothing here is labelled, so this says how loud it is " +
			"and nothing about whether it is right"
	}
	return out
}

// Run replays a rule over recorded events.
//
// The recording is the argument. A rule replayed over events chosen because
// they are the ones it was written for has been shown to match them, which
// is what Channel File 291's tests showed about the input they wildcarded.
func Run(r detect.Rule, events []telemetry.Event, source string,
	at time.Time) Replay {
	out := Replay{At: at.UTC(), Source: source, Events: len(events)}
	var first, last time.Time
	for _, e := range events {
		when := e.Time
		if when.IsZero() {
			when = e.Received
		}
		if !when.IsZero() {
			if first.IsZero() || when.Before(first) {
				first = when
			}
			if when.After(last) {
				last = when
			}
		}
		if !r.Matches(e) {
			continue
		}
		out.Matched++
		if len(out.Samples) < MaxSamples {
			out.Samples = append(out.Samples, describe(e))
		}
	}
	if !first.IsZero() {
		out.Window = last.Sub(first)
	}
	return out
}

// Labelled replays over events somebody has marked as malicious or benign.
//
// bad reports whether an event is one the rule ought to catch. Where a
// recording has labels this gives precision and recall, which is the only
// honest way to compare two candidates that fire at different rates.
func Labelled(r detect.Rule, events []telemetry.Event,
	bad func(telemetry.Event) bool, source string, at time.Time) Replay {
	out := Run(r, events, source, at)
	for _, e := range events {
		if !bad(e) && !r.Matches(e) {
			continue
		}
		out.Labelled++
		switch {
		case r.Matches(e) && bad(e):
			out.True++
		case r.Matches(e):
			out.False++
		}
	}
	return out
}

func describe(e telemetry.Event) string {
	var parts []string
	if e.Source != "" {
		parts = append(parts, e.Source)
	}
	if !e.Actor.Zero() {
		parts = append(parts, e.Actor.String())
	}
	if e.Message != "" {
		m := e.Message
		if len(m) > 80 {
			m = m[:77] + "..."
		}
		parts = append(parts, m)
	}
	if len(parts) == 0 {
		return "an event with nothing to show"
	}
	return strings.Join(parts, " · ")
}

// Change is what a new version of a rule does differently.
//
// A rule edit is not a new rule and is not the same rule. What matters is
// the difference: what it now catches that it did not, and what it has
// stopped catching. The second is the one nobody looks at, and it is how a
// tuning change quietly removes a detection.
type Change struct {
	Was  Replay `json:"was"`
	Now  Replay `json:"now"`
	Gain int    `json:"gain"`
	Lost int    `json:"lost"`
	Kept int    `json:"kept"`
	// LostSamples are events the old rule caught and the new one does not.
	LostSamples []string `json:"lost_samples,omitempty"`
}

// Compare replays two versions of a rule over the same events.
func Compare(was, now detect.Rule, events []telemetry.Event, source string,
	at time.Time) Change {
	c := Change{
		Was: Run(was, events, source, at),
		Now: Run(now, events, source, at),
	}
	for _, e := range events {
		before, after := was.Matches(e), now.Matches(e)
		switch {
		case before && after:
			c.Kept++
		case before:
			c.Lost++
			if len(c.LostSamples) < MaxSamples {
				c.LostSamples = append(c.LostSamples, describe(e))
			}
		case after:
			c.Gain++
		}
	}
	return c
}

// Quieter reports whether the change reduces volume.
func (c Change) Quieter() bool { return c.Now.Matched < c.Was.Matched }

// Why describes a change, leading with what was lost.
func (c Change) Why() string {
	switch {
	case c.Gain == 0 && c.Lost == 0:
		return "this changes nothing about what it matches"
	case c.Lost == 0:
		return fmt.Sprintf("catches %d more and stops catching nothing",
			c.Gain)
	case c.Gain == 0:
		return fmt.Sprintf(
			"stops catching %d event(s) and catches nothing new. If that "+
				"is tuning, the %d are the false positives; if it is a "+
				"mistake, they are the detection", c.Lost, c.Lost)
	}
	return fmt.Sprintf(
		"catches %d more, stops catching %d. The second number is the one "+
			"nobody looks at, and it is how a tuning change quietly "+
			"removes a detection", c.Gain, c.Lost)
}

// Loudest is the candidates in an estate ordered by how often they fire.
func (e *Estate) Loudest() []*Candidate {
	var out []*Candidate
	for _, c := range e.Candidates {
		if _, ok := c.Latest(); ok {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := out[i].Latest()
		b, _ := out[j].Latest()
		return a.PerDay() > b.PerDay()
	})
	return out
}
