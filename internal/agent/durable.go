// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Runs that outlive the process, and stop for a person.
//
// A run was one call: it started, it finished or it was lost. Two things
// follow from that. An agent could not hold an action for somebody to look
// at, so "a person approves" could only mean approving afterwards what had
// already happened; and a run that was interrupted left nothing to continue
// from.
//
// # Asking first
//
// A manifest names the capabilities and tools it asks about. When the model
// proposes one, and the declaration would otherwise allow it, the run stops
// before anything is charged or done and the trace carries the exact action
// as Pending. Nothing about the action can change between the asking and the
// doing: what a person approves is the stored action, and the run continues
// by performing that and not by asking the model again.
//
// Approval is not a way around the gate. The approved action still goes
// through Authorize, against the declaration as it stands when the run is
// continued — so a capability withdrawn while the run waited is refused,
// approval or not.
//
// # Continuing
//
// What the steps already taken returned is rebuilt from the trace and given
// to the model as what it has seen, with the same trust each had the first
// time: a refusal is ours, and everything else came from content. The spend
// and the taint are carried over, so a run cannot be given a fresh budget or
// a clean record by stopping it.

// Pending is an action a run stopped at.
type Pending struct {
	// N is the step it would be. A decision names it, so that a decision
	// made on a page opened earlier cannot land on a later question.
	N      int
	Action Action
	Since  time.Time
	// Why is the reason it waits when it is not the declaration's asking
	// first: the exfiltration breaker's sentence, which the person reads.
	Why string `json:",omitempty"`
}

// PendingTTL is how long a question stays answerable. After that whatever
// the agent read to get there is old enough that a person would be agreeing
// to something decided about a different state of things.
const PendingTTL = 72 * time.Hour

// Verdict is a person's answer to a pending action.
type Verdict struct {
	N       int
	Approve bool
	// By is who decided. Shown to the model on a refusal, and recorded.
	By string
}

// ErrNotWaiting is returned for a verdict on a run with no question open.
var ErrNotWaiting = errors.New("this run is not waiting for anybody")

// AsksFirst reports whether the manifest asks a person about this action.
func (s *Session) AsksFirst(a Action) bool {
	name := a.Op
	if a.Tool != "" {
		name = a.Tool
	}
	if name == "" {
		return false
	}
	for _, x := range s.manifest.AskFirst {
		if x == name {
			return true
		}
	}
	return false
}

// wouldAllow reports whether the gate would let an action through, without
// charging for it or recording a refusal.
func (s *Session) wouldAllow(a Action) bool {
	if a.Tool != "" {
		_, declared := s.ToolFor(a.Tool)
		return declared
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capabilities[a.Op]
}

// carry restores what the steps already taken spent, and that they read.
//
// Counted from the steps rather than taken from a figure stored beside
// them: a step that was allowed was charged, a tool call against the tool
// budget and everything else against the steps. The clock is not carried. Time spent waiting for a person is not
// time the agent used, and the duration budget applies to each stretch.
func (s *Session) carry(prior Trace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range prior.Steps {
		if !st.Allowed || st.Action.Done() {
			continue
		}
		if st.Action.Tool != "" {
			s.toolUses++
			continue
		}
		s.steps++
	}
	s.tokens += prior.Spent.Tokens
	if prior.Tainted {
		s.tainted = true
	}
}

// Recall restores the sources an earlier stretch of the same run read, so
// the receipt at the end names all of them.
func (s *Session) Recall(sources []Source, omitted int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reads := s.reads
	for _, src := range sources {
		s.note(src.Kind, src.Name, src.Where)
	}
	s.reads = reads + len(sources)
	s.omitted += omitted
	if len(sources) > 0 {
		s.tainted = true
	}
}

// observed rebuilds what a model had seen from the steps already taken.
func observed(steps []Step) []Observation {
	var seen []Observation
	for _, st := range steps {
		switch {
		case st.Action.Done():
		case !st.Allowed:
			seen = append(seen, Observation{From: "quilzo",
				Body: "refused: " + st.Why, Trusted: true})
		case st.Err != "":
			seen = append(seen, Observation{From: from(st.Action),
				Body: "failed: " + st.Err, Err: errors.New(st.Err)})
		default:
			seen = append(seen, Observation{From: from(st.Action),
				Body: st.Result})
		}
	}
	return seen
}

// Continue takes a run on from where it stopped.
//
// With a verdict, the run was waiting: an approval performs the pending
// action through the gate, and a refusal is told to the model as one. With
// none, the run was interrupted or is being replayed from an earlier step,
// and the model is asked what comes next.
//
// The session is a new one for the agent's declaration as it now stands,
// with the earlier spend carried into it by the caller.
func (r Runner) Continue(ctx context.Context, s *Session, prior Trace,
	v *Verdict, now time.Time) (Trace, error) {

	t := Trace{Agent: s.Manifest().Name, Goal: prior.Goal,
		Steps: append([]Step(nil), prior.Steps...)}
	if prior.Agent != t.Agent {
		return prior, fmt.Errorf("this run was %s's and the session is %s's",
			prior.Agent, t.Agent)
	}
	seen := observed(t.Steps)
	carried := false
	carry := func() {
		if !carried {
			carried = true
			s.carry(prior)
		}
	}

	switch {
	case v == nil && prior.Waiting != nil:
		return prior, fmt.Errorf("this run is waiting for a person to " +
			"decide, and continuing it without an answer would be one")
	case v == nil:
		if prior.Complete {
			return prior, fmt.Errorf("this run finished; there is nothing " +
				"to continue")
		}
		carry()
		return r.run(ctx, s, t, seen, nil)
	case prior.Waiting == nil:
		return prior, ErrNotWaiting
	case v.N != prior.Waiting.N:
		return prior, fmt.Errorf("the run is waiting at step %d and this "+
			"answers step %d", prior.Waiting.N, v.N)
	case now.Sub(prior.Waiting.Since) > PendingTTL:
		return prior, fmt.Errorf("this was asked %s ago. What the agent "+
			"read to get here is too old to agree to; run it again",
			now.Sub(prior.Waiting.Since).Round(time.Hour))
	}

	carry()
	if !v.Approve {
		why := "a person declined this"
		if v.By != "" {
			why = v.By + " declined this"
		}
		t.Steps = append(t.Steps, Step{N: prior.Waiting.N,
			Action: prior.Waiting.Action, Why: why, At: now})
		seen = append(seen, Observation{From: "quilzo",
			Body: "refused: " + why, Trusted: true})
		r.checkpoint(t, s)
		return r.run(ctx, s, t, seen, nil)
	}
	a := prior.Waiting.Action
	return r.run(ctx, s, t, seen, &a)
}

// Upto is a trace cut back to its first n steps, for running again from
// there. Nothing is waiting in it and it has not finished.
func (t Trace) Upto(n int) (Trace, error) {
	if n < 0 || n > len(t.Steps) {
		return t, fmt.Errorf("this run has %d steps", len(t.Steps))
	}
	// Tainted stays as it was: which step first read content is not
	// recorded, and guessing clean would be guessing in the wrong direction.
	out := Trace{Agent: t.Agent, Goal: t.Goal, Tainted: t.Tainted,
		Steps: append([]Step(nil), t.Steps[:n]...)}
	for _, st := range out.Steps {
		if st.Action.Done() {
			return t, fmt.Errorf("step %d is where it finished; run it "+
				"again from before that", st.N)
		}
	}
	return out, nil
}

// checkpoint hands the trace so far to the host, if it asked.
func (r Runner) checkpoint(t Trace, s *Session) {
	if r.Checkpoint == nil {
		return
	}
	t.Tainted = s.Tainted()
	t.Spent = spendOf(s)
	r.Checkpoint(t)
}
