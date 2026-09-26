// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package flow is automation that cannot lose anything quietly.
//
// # The failure this exists for
//
// Zapier's own troubleshooting advice contains this sentence: every time you
// use a filter or a path, you must ask what happens to the data that does
// not pass, and if you have no else-path or fallback notification, that data
// is gone forever. That is not a warning about an edge case. It is a
// description of the default behaviour of the largest automation platform in
// the world, and it is why an industry of third-party monitors exists whose
// entire product is telling you that your automation stopped working.
//
// Errors are not the dangerous part. An error at least produces something,
// somewhere, eventually — Zapier's arrive batched or daily. The dangerous
// part is the filter that discards, because a run that quietly dropped
// ninety-seven of a hundred items looks exactly like a quiet day.
//
// So the organising idea here is an accounting identity. Every item that
// enters a run leaves it through exactly one named exit: it was acted on, a
// named filter rejected it for a stated reason, a step failed on it, or it
// is still held. Those counts must add up to what came in. A run that cannot
// say where every item went does not report success with a caveat — it is
// itself the failure, and Check refuses it.
//
// Three more things follow from taking that seriously:
//
//   - A filter has to declare where its rejects go before the flow will
//     validate. Dropping is allowed and has to be chosen and explained,
//     which is the whole difference between a decision and an accident.
//
//   - Silence is a failure. A flow states how often it should run, and a
//     run that did not happen is reported. This is the failure mode nobody
//     detects, because nothing arrives to be noticed.
//
//   - A run states the window of time it covered. Polling misses data when
//     the source is busy or rate-limited, and the evidence is a gap between
//     one run's window and the next. Gaps finds them, rather than leaving
//     the loss to be discovered by somebody asking where their record went.
package flow

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Kind is what a step does.
type Kind string

const (
	// Keep is a filter: some items go on and some do not.
	Keep Kind = "keep"
	// Change transforms items and passes all of them on.
	Change Kind = "change"
	// Act does something outside this program. The only kind that can have
	// an effect somebody else notices, and the only one worth retrying
	// carefully.
	Act Kind = "act"
)

// Kinds is every kind of step.
var Kinds = []Kind{Keep, Change, Act}

// Known reports whether a kind is one of the three.
func (k Kind) Known() bool {
	for _, c := range Kinds {
		if c == k {
			return true
		}
	}
	return false
}

// ExitKind is what happens to an item a filter rejects.
type ExitKind string

const (
	// Drop throws it away. Permitted, and it has to be chosen and
	// explained, because the difference between a decision and an accident
	// is whether anybody wrote down which one it was.
	Drop ExitKind = "drop"
	// Divert sends it somewhere else — another flow, a queue, a person.
	Divert ExitKind = "divert"
	// Hold keeps it for later, which is the right answer when the reason
	// for rejecting it might stop being true.
	Hold ExitKind = "hold"
)

// Exit is where rejected items go.
type Exit struct {
	Kind ExitKind `json:"kind"`
	// To names the destination for a divert.
	To string `json:"to,omitempty"`
	// Why is required for a drop.
	Why string `json:"why,omitempty"`
}

// Validate refuses an exit that loses things without saying so.
func (e Exit) Validate() error {
	switch e.Kind {
	case Drop:
		if strings.TrimSpace(e.Why) == "" {
			return fmt.Errorf(
				"dropping rejected items needs a reason. This is the one " +
					"thing every automation platform lets you do by " +
					"accident: a filter with nowhere for its rejects to go " +
					"discards them, and a run that discarded everything " +
					"looks exactly like a quiet day")
		}
	case Divert:
		if strings.TrimSpace(e.To) == "" {
			return fmt.Errorf("diverting means naming where to")
		}
	case Hold:
	default:
		return fmt.Errorf("%q is not something to do with a rejected item; "+
			"it is drop, divert or hold", e.Kind)
	}
	return nil
}

// Step is one stage of a flow.
type Step struct {
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	// Rejects is where this step's rejected items go. Required for a
	// filter, and meaningless for anything else.
	Rejects *Exit `json:"rejects,omitempty"`
	// Reaches names what an Act step touches outside this program, so that
	// a flow can be read for its effects without running it.
	Reaches string `json:"reaches,omitempty"`
	// Retries is how many times a failing Act is tried again.
	Retries int `json:"retries,omitempty"`
}

// MaxRetries caps retrying.
//
// An act retried forever is an act that will be performed forever against
// something that is not answering, and the usual result is the same message
// delivered four thousand times when it recovers.
const MaxRetries = 5

// Validate refuses a step that could lose items.
func (s Step) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("a step needs a name; a failure in \"step 3\" is " +
			"a failure nobody can find")
	}
	if !s.Kind.Known() {
		return fmt.Errorf("%q is not a kind of step; they are %s", s.Kind,
			kindList())
	}
	switch s.Kind {
	case Keep:
		if s.Rejects == nil {
			return fmt.Errorf(
				"the filter %q does not say what happens to the items it "+
					"rejects. That is the question Zapier's own "+
					"troubleshooting tells you to ask about every filter "+
					"you write, and it is a question this refuses to leave "+
					"to whoever reads the logs a month later", s.Name)
		}
		if err := s.Rejects.Validate(); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
	default:
		if s.Rejects != nil {
			return fmt.Errorf(
				"%q is a %s, so nothing is rejected by it", s.Name, s.Kind)
		}
	}
	if s.Kind == Act && strings.TrimSpace(s.Reaches) == "" {
		return fmt.Errorf("%q acts on something outside this program and "+
			"does not say what. A flow should be readable for its effects "+
			"without being run", s.Name)
	}
	if s.Kind != Act && s.Retries != 0 {
		return fmt.Errorf("only an act is retried; %q is a %s", s.Name,
			s.Kind)
	}
	if s.Retries < 0 || s.Retries > MaxRetries {
		return fmt.Errorf("%q retries %d times; the range is 0 to %d, "+
			"because something retried without limit is delivered four "+
			"thousand times when the other end recovers", s.Name,
			s.Retries, MaxRetries)
	}
	return nil
}

func kindList() string {
	out := make([]string, 0, len(Kinds))
	for _, k := range Kinds {
		out = append(out, string(k))
	}
	return strings.Join(out, ", ")
}

// Flow is an automation.
type Flow struct {
	Name  string `json:"name"`
	What  string `json:"what"`
	Steps []Step `json:"steps"`

	// Every is how often this is expected to run.
	//
	// Required, and it is the whole of the silence check. An automation
	// that stops running produces nothing, and nothing is what a working
	// automation produces on a quiet day, so the only way to tell them
	// apart is to have said in advance how often something should happen.
	Every time.Duration `json:"every"`
	// Late is how far past Every something can be before it is a problem.
	Late time.Duration `json:"late,omitempty"`
}

// Validate refuses a flow that could lose things.
func (f Flow) Validate() error {
	if strings.TrimSpace(f.Name) == "" {
		return fmt.Errorf("a flow needs a name")
	}
	if len(f.Steps) == 0 {
		return fmt.Errorf("a flow with no steps does nothing, and will do " +
			"it reliably")
	}
	if f.Every <= 0 {
		return fmt.Errorf("say how often %q should run. Without that, a "+
			"flow that has stopped and a flow with nothing to do are the "+
			"same observation, and the first one is an incident",
			f.Name)
	}
	seen := map[string]bool{}
	acts := 0
	for _, s := range f.Steps {
		if err := s.Validate(); err != nil {
			return err
		}
		k := strings.ToLower(s.Name)
		if seen[k] {
			return fmt.Errorf("two steps are called %q, so a failure in "+
				"one of them names both", s.Name)
		}
		seen[k] = true
		if s.Kind == Act {
			acts++
		}
	}
	if acts == 0 {
		return fmt.Errorf("%q never acts on anything. A flow that filters "+
			"and transforms and then stops is a report, and it should say "+
			"so rather than look like an automation that is working",
			f.Name)
	}
	return nil
}

// Grace is how late a run may be before it counts as missing.
func (f Flow) Grace() time.Duration {
	if f.Late > 0 {
		return f.Late
	}
	// Half a period. Generous enough for an ordinary delay and short
	// enough that a daily job which has not run by lunchtime is noticed.
	return f.Every / 2
}

// Overdue reports whether a flow has gone quiet, and by how much.
func (f Flow) Overdue(last, at time.Time) (bool, time.Duration) {
	if last.IsZero() {
		return true, 0
	}
	due := last.Add(f.Every)
	if at.Before(due.Add(f.Grace())) {
		return false, 0
	}
	return true, at.Sub(due)
}

// Filters is every step that can reject an item.
func (f Flow) Filters() []Step {
	var out []Step
	for _, s := range f.Steps {
		if s.Kind == Keep {
			out = append(out, s)
		}
	}
	return out
}

// Drops is every filter that throws things away, with its stated reason.
//
// Worth being able to list on its own. A flow acquires drops one at a time
// and each is defensible when it is added; the set of them is what nobody
// ever looks at, and it is the set that explains where the records went.
func (f Flow) Drops() []Step {
	var out []Step
	for _, s := range f.Filters() {
		if s.Rejects != nil && s.Rejects.Kind == Drop {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// Reaches is everything outside this program that a flow touches.
func (f Flow) Reaches() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range f.Steps {
		if s.Kind != Act || s.Reaches == "" {
			continue
		}
		if !seen[s.Reaches] {
			seen[s.Reaches] = true
			out = append(out, s.Reaches)
		}
	}
	sort.Strings(out)
	return out
}
