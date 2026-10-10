// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/pii"
)

// Running an agent: the loop that turns a manifest into something that happens.
//
// # The shape, and why the model is injected
//
// Nothing in this package knows what a model is. Decide is a function the host
// supplies, and everything here treats it as an untrusted oracle that proposes
// actions — because that is the honest description of it, and because a runner
// that imported a provider would make the provider a dependency of the CMS.
//
// That also means this is testable without a network, a key or a bill, which is
// how the security properties below are asserted rather than argued.
//
// # The CaMeL split, as a data structure
//
// CaMeL's insight is that the plan must be formed from the trusted request and
// that untrusted data must not reach the decision about what to do next. A full
// implementation needs two models and an interpreter between them. What a CMS
// can do without one is keep the boundary visible and enforce the consequences:
//
//	Goal          trusted. It came from a person, through an authenticated
//	              surface, and it is what the run is for.
//	Observation   untrusted. It came out of the store or off a tool, and
//	              anybody who can write a page or run a server can influence it.
//
// Observations are marked, never merged into the goal, and the moment one
// arrives the session is tainted — which is what stops the run publishing its
// own output. An instruction that arrives inside an observation is still a
// string the model may act on; what it cannot do is widen the capability list,
// because the list was fixed before the loop started and Authorize is the only
// way through.
//
// This is deliberately not a claim to have solved prompt injection. It is the
// smaller, checkable claim: a hijacked run is bounded by its manifest, every
// attempt outside it is refused and recorded, and nothing it produced goes
// public without a person.

// Action is what a model proposes doing next.
type Action struct {
	// Op is a capability name, or the empty string when the model is done.
	Op string
	// Tool is the external tool name, for an integration call.
	Tool string
	// Delegate is the named agent this work is handed to. Only a supervisor
	// may set it, and only to a name its own manifest already lists.
	Delegate string
	// Input is whatever the operation needs. Opaque here.
	Input map[string]any
	// Say is the model's answer when it is finished.
	Say string
}

// Done reports whether this action ends the run.
// Done reports that the model has finished.
//
// Every field that carries work has to be named here, and this is the second
// time that has bitten. An action naming only a Tool had no Op, so before the
// tool branch existed this said the run was over; the same was true of a
// delegation, which named only an agent, so a supervisor's first hand-off
// ended the run and the answer was whatever the supervisor had said to the
// delegate. A probe walking a manifest reported three capabilities and no
// pipeline, and looked exactly like a supervisor with nothing to do.
func (a Action) Done() bool {
	return a.Op == "" && a.Tool == "" && a.Delegate == ""
}

// Observation is the result of an action, fed back for the next decision.
//
// Trusted is false for anything that came out of the store or off a tool, which
// is everything the loop produces. The field exists rather than being assumed
// so that a host adding a genuinely trusted source has to say so, in writing,
// at the call site.
type Observation struct {
	From    string
	Body    string
	Trusted bool
	Err     error
}

// Decide proposes the next action. Supplied by the host; treated as untrusted.
//
// It receives the goal and the observations so far, and returns what it would
// like to do. It is asked, never obeyed: the return value is a request that
// Authorize may refuse.
type Decide func(ctx context.Context, goal string, seen []Observation) (Action, error)

// Perform carries out an authorised action. Supplied by the host, because this
// package deliberately cannot reach the store or the network itself.
type Perform func(ctx context.Context, a Action) (string, error)

// Step is one turn of the loop, kept whole for the record.
type Step struct {
	N       int
	Action  Action
	Allowed bool
	// Why is the refusal, when there was one.
	Why    string
	Result string
	Err    string
	At     time.Time
	// Redirected records a tool call whose input named a different host from
	// the one the tool declares.
	//
	// Nothing acts on it — the declared host is what is authorised and dialled
	// either way — but it is exactly what an injected page trying to point a
	// tool somewhere else looks like, and a run that silently corrected it
	// would leave no trace of the attempt. internal/agentwatch reads the
	// audit log for patterns like this.
	Redirected string
}

// Trace is what a run produced, and is the audit record.
//
// Every step, allowed or refused, in order. The refusals matter most: "it tried
// to publish four times" is a finding, and a counter of twelve refusals is not.
type Trace struct {
	Agent    string
	Goal     string
	Steps    []Step
	Answer   string
	Tainted  bool
	Spent    Spend
	Stopped  string
	Complete bool
	// Waiting is the action this run stopped at for a person to decide.
	// See durable.go.
	Waiting *Pending `json:",omitempty"`
}

// Spend is what the run cost.
type Spend struct {
	Steps   int
	Tools   int
	Elapsed time.Duration
	// Tokens is what the host reported the model using, and Metered says
	// whether anybody reported anything at all.
	//
	// The two are separate because zero is a real answer. A local model costs
	// nothing and reports nothing, and a hosted run whose usage nobody wrote
	// down also shows zero — those are opposite situations and a single
	// integer cannot tell them apart. An invoice built on the second would be
	// charging for work it has no record of.
	Tokens  int
	Metered bool
	// Cost is what the model calls cost at the gateway's prices, in
	// millionths of its currency; zero when nothing was priced.
	Cost int64
}

// Refused returns the steps that were refused.
func (t Trace) Refused() []Step {
	var out []Step
	for _, s := range t.Steps {
		if !s.Allowed {
			out = append(out, s)
		}
	}
	return out
}

// Runner drives one agent through one goal.
type Runner struct {
	// Decide proposes; Perform carries out. Both are the host's.
	Decide  Decide
	Perform Perform
	// OwnDomains are the organisation's own email domains: an address at
	// one, in what a tool returned, is not somebody's personal data.
	OwnDomains []string
	// MaxTurns is a backstop above the manifest's own step budget.
	//
	// The budget is the real limit and this is the seatbelt: a Decide that
	// proposes only refused actions never spends a step, because a refused
	// step is not charged, so without this the loop is unbounded on exactly
	// the input a hijacked model produces.
	MaxTurns int
	// Record is called with the receipt for every run, however it ended.
	//
	// A hook rather than something the caller does afterwards, because a
	// caller that has to remember is a caller that forgets — and the runs
	// worth recording most are the ones that ended badly, which are exactly
	// the paths where an afterwards-step gets skipped by an early return.
	//
	// Called for a cancelled run, a model that could not be reached and a
	// budget that ran out, not only for a clean finish. An outcome record that
	// only exists when things went well is a record of nothing: the buyer
	// disputing a charge and the operator investigating a runaway are both
	// asking about the runs that are missing.
	//
	// Nil records nothing, which is right for a test and wrong for anything
	// somebody is billed for.
	Record func(Receipt)
	// Checkpoint is called with the trace after every step, so a host can
	// keep a run that outlives the process. Pause says the host can hold a
	// run for a person and continue it afterwards; without it an action
	// that asks first is refused, because there is nobody to ask. See
	// durable.go.
	Checkpoint func(Trace)
	Pause      bool
	// Hold waits, in this process, for a person to decide on an action that
	// asks first, for a run that cannot be paused and picked up later: a
	// program's, whose program is waiting on the call. beat keeps the run's
	// record fresh while it waits. An error (nobody decided in time, the run
	// was cancelled) refuses the action, with the reason. Nil refuses
	// straight away, because there is nobody to ask.
	Hold func(ctx context.Context, w Pending, beat func()) (Verdict, error)
	// Weighs says why an action commits to something a person should see
	// first, beyond what the declaration asks about: a browser click that
	// submits a form, or one on a button called Pay. Empty is an ordinary
	// action. Such an action waits for a person in this process (Hold), or
	// is refused when the run has nobody to ask.
	Weighs func(Action) string
}

// holdFor asks a person about an action while the run waits in this
// process. It reports whether they approved it and, when not, why it is
// refused. The run's record carries the question while it waits, marked
// live, so the run's page and `quilzo agent approve` can answer it.
func (r Runner) holdFor(ctx context.Context, t *Trace, s *Session, w Pending) (bool, string) {
	what := from(w.Action)
	if r.Hold == nil {
		if w.Why != "" {
			return false, w.Why
		}
		return false, fmt.Sprintf("%s asks a person first, and this run has nobody to ask", what)
	}
	w.Live = true
	t.Waiting = &w
	r.checkpoint(*t, s)
	// No longer than the run may last: the program is waiting on this call
	// inside a box whose clock does not stop for a person.
	hctx, cancel := context.WithTimeout(ctx, time.Duration(s.Remaining().Duration))
	v, err := r.Hold(hctx, w, func() { r.checkpoint(*t, s) })
	cancel()
	t.Waiting = nil
	// The reason it waited goes with the refusal, so the program knows what
	// a person was asked about and not only that they were.
	because := ""
	if w.Why != "" {
		because = ": " + w.Why
	}
	switch {
	case err != nil:
		return false, fmt.Sprintf("%s waited for a person and was not decided (%v)%s", what, err, because)
	case v.N != w.N:
		return false, fmt.Sprintf("the answer was for step %d and this is step %d", v.N, w.N)
	case !v.Approve:
		if v.By != "" {
			return false, v.By + " declined this" + because
		}
		return false, "a person declined this" + because
	}
	return true, ""
}

// ErrNoDecide is returned when a runner has no way to decide anything.
var ErrNoDecide = errors.New("this runner has no Decide function")

// Run executes one goal under one session.
//
// The session is the authority. Run never consults the manifest directly — if
// it did, there would be two places that decide what an agent may do, and the
// history of this project is that the two disagree.
func (r Runner) Run(ctx context.Context, s *Session, goal string) (Trace, error) {
	return r.run(ctx, s, Trace{Agent: s.Manifest().Name, Goal: goal}, nil, nil)
}

// run is the loop, from the start or from where an earlier run stopped.
//
// seen is what the steps already taken returned, and first is an action
// already chosen — the one a person has just approved — which goes through
// the same gate as any other and is not asked about twice.
func (r Runner) run(ctx context.Context, s *Session, t Trace,
	seen []Observation, first *Action) (Trace, error) {

	goal := t.Goal
	if r.Decide == nil {
		// Recorded too. A runner wired without a way to decide anything is a
		// misconfiguration that produces no work and no error anybody sees
		// unless the caller checks — which is exactly the kind of silence an
		// outcome record exists to break.
		t.Stopped = ErrNoDecide.Error()
		r.record(t, s)
		return t, ErrNoDecide
	}
	maxTurns := r.MaxTurns
	if maxTurns <= 0 {
		// Three turns per budgeted step: enough headroom that a run doing
		// real work is never cut off here, tight enough that a model
		// proposing nothing but refused actions stops.
		maxTurns = s.Manifest().Budget.Steps * 3
	}

	for turn := len(t.Steps) + 1; turn <= maxTurns; turn++ {
		if err := ctx.Err(); err != nil {
			t.Stopped = "cancelled"
			t.Spent = spendOf(s)
			r.record(t, s)
			return t, err
		}

		var action Action
		var err error
		approved := first != nil
		if approved {
			action, first = *first, nil
		} else if action, err = r.Decide(ctx, goal, seen); err != nil {
			t.Stopped = "the model could not be asked: " + err.Error()
			t.Spent = spendOf(s)
			r.record(t, s)
			return t, err
		}

		step := Step{N: turn, Action: action, At: time.Now()}

		if action.Done() {
			t.Answer = action.Say
			t.Complete = true
			step.Allowed = true
			step.Result = "done"
			t.Steps = append(t.Steps, step)
			break
		}

		// Asked about before it is charged or done. Only an action the
		// declaration would allow anyway: one it refuses needs no person to
		// refuse it, and asking would teach people to approve without
		// reading.
		if !approved && s.AsksFirst(action) && s.wouldAllow(action) {
			if !r.Pause {
				w := Pending{N: turn, Action: action, Since: step.At}
				if approved, step.Why = r.holdFor(ctx, &t, s, w); !approved {
					t.Steps = append(t.Steps, step)
					seen = append(seen, Observation{From: "quilzo",
						Body: "refused: " + step.Why, Trusted: true})
					r.checkpoint(t, s)
					continue
				}
			} else {
				t.Waiting = &Pending{N: turn, Action: action, Since: step.At}
				t.Stopped = fmt.Sprintf("waiting for a person to decide on %s",
					from(action))
				break
			}
		}

		// What the action itself commits to, which only the performer can
		// tell: a click that submits a form. Waits for a person in this
		// process, since the page it would act on lives here.
		if !approved && r.Weighs != nil && s.wouldAllow(action) {
			if why := r.Weighs(action); why != "" {
				// One question, with every reason: approving it settles the
				// breaker as well, so the person sees that too.
				if b, breaks := s.Breaks(action); breaks {
					why += "; and " + b
				}
				w := Pending{N: turn, Action: action, Since: step.At, Why: why}
				if approved, step.Why = r.holdFor(ctx, &t, s, w); !approved {
					t.Steps = append(t.Steps, step)
					seen = append(seen, Observation{From: "quilzo",
						Body: "refused: " + step.Why, Trusted: true})
					r.checkpoint(t, s)
					continue
				}
			}
		}

		// The exfiltration breaker: what this run holds in private, after
		// somebody else's words, is not sent outside without a person. Only
		// for a call the declaration allows anyway, as with asking first.
		if !approved && s.wouldAllow(action) {
			if why, breaks := s.Breaks(action); breaks {
				if !r.Pause {
					w := Pending{N: turn, Action: action, Since: step.At, Why: why}
					if approved, step.Why = r.holdFor(ctx, &t, s, w); !approved {
						t.Steps = append(t.Steps, step)
						seen = append(seen, Observation{From: "quilzo", Body: "refused: " + step.Why, Trusted: true})
						r.checkpoint(t, s)
						continue
					}
				} else {
					t.Waiting = &Pending{N: turn, Action: action, Since: step.At, Why: why}
					t.Stopped = "waiting for a person: " + why
					break
				}
			}
		}

		// The one gate. A tool call is authorised by host first, because the
		// useful refusal for "call evil.example.com" names the host rather
		// than the capability.
		switch {
		case action.Delegate != "":
			// Authorised by name against the manifest's list, because a
			// supervisor choosing a worker at run time is the thing the
			// design refuses: the graph is named in advance so that a
			// supervisor which has been talked into something cannot invent
			// one.
			err = s.MayDelegate(action.Delegate)
		case action.Tool != "":
			// Recorded whether or not it is refused, because the attempt is
			// the finding. See Step.Redirected and Session.MayCallTool.
			asked := hostAsked(action)
			if asked != "" && !strings.EqualFold(asked, s.HostFor(action.Tool)) {
				step.Redirected = asked
			}
			err = s.MayCallTool(action.Tool, asked)
		default:
			err = s.Authorize(action.Op)
		}
		if err != nil {
			step.Allowed = false
			step.Why = err.Error()
			t.Steps = append(t.Steps, step)

			// Refused, and the model is told so. Telling it is the point: an
			// agent that learns it may not publish can finish the work it is
			// allowed to do, and one that is silently ignored loops.
			seen = append(seen, Observation{
				From: "quilzo", Body: "refused: " + err.Error(),
				// Trusted, unusually: this sentence is ours, not content's.
				Trusted: true,
			})

			// A budget refusal ends the run. A capability refusal does not —
			// the agent may have other work it is permitted to do, and
			// stopping on the first "no" would make every over-broad plan a
			// total failure.
			if isBudget(err) {
				t.Stopped = err.Error()
				break
			}
			r.checkpoint(t, s)
			continue
		}

		step.Allowed = true
		if r.Perform == nil {
			step.Err = "nothing to perform actions with"
			t.Steps = append(t.Steps, step)
			t.Stopped = "this runner has no Perform function"
			break
		}

		out, perr := r.Perform(ctx, action)
		if perr != nil {
			step.Err = perr.Error()
			seen = append(seen, Observation{
				From: from(action), Err: perr,
				Body: "failed: " + perr.Error(),
			})
		} else {
			step.Result = out
			// Personal data off a tool is private from here on, as a draft
			// is: a customer's address looked up in one system is not to
			// be posted to another because a page said so (the
			// exfiltration breaker).
			if action.Tool != "" {
				if kinds := personalIn(out, r.OwnDomains); kinds != "" {
					s.HoldsPrivate("personal data (" + kinds + ") returned by " + action.Tool)
				}
			}
			// Untrusted, always. It came out of the store or off a tool.
			seen = append(seen, Observation{
				From: from(action), Body: out, Trusted: false,
			})
		}
		t.Steps = append(t.Steps, step)
		r.checkpoint(t, s)
	}

	if !t.Complete && t.Stopped == "" {
		t.Stopped = fmt.Sprintf(
			"stopped after %d turns without finishing; the model kept "+
				"proposing actions rather than an answer", maxTurns)
	}
	t.Tainted = s.Tainted()
	t.Spent = spendOf(s)
	r.record(t, s)
	return t, nil
}

// record hands the receipt to the host, if it asked for one.
func (r Runner) record(t Trace, s *Session) {
	if r.Record == nil {
		return
	}
	r.Record(t.Receipt(s))
}

// Publishable reports whether what a run produced may go live without a person.
//
// Asked of the trace and the session together, because both halves matter: the
// manifest decides whether this agent may ever publish, and the run decides
// whether this particular one read anything it should not be trusted about.
func (t Trace) Publishable(s *Session) (bool, string) {
	if !t.Complete {
		return false, fmt.Sprintf(
			"%s did not finish (%s), so there is nothing settled to publish",
			t.Agent, t.Stopped)
	}
	if n := len(t.Refused()); n > 0 {
		// Not a hard refusal on its own — a plan that overreached and was
		// trimmed is normal. But it is worth a person's eye, and saying so is
		// cheaper than explaining afterwards why nobody looked.
		if ok, why := s.Publishable(); !ok {
			return false, why
		}
		return false, fmt.Sprintf(
			"%s was refused %d time(s) during this run; a person should see "+
				"what it was trying to do before it goes live", t.Agent, n)
	}
	return s.Publishable()
}

func spendOf(s *Session) Spend {
	steps, tools, elapsed := s.Spent()
	tokens := s.TokensUsed()
	return Spend{
		Steps: steps, Tools: tools, Elapsed: elapsed,
		Tokens: tokens, Metered: tokens > 0, Cost: s.Cost(),
	}
}

// hostAsked is the host an action's own input names.
//
// Kept only to report the disagreement. Nothing authorises against it — see
// Session.HostFor for why — but a model that asked for one host while its
// tool declares another is worth saying out loud rather than silently
// correcting, because it is what an injected page trying to redirect a tool
// call looks like.
func hostAsked(a Action) string {
	if h, ok := a.Input["host"].(string); ok {
		return strings.TrimSpace(h)
	}
	return ""
}

// isBudget reports whether a refusal was a budget rather than a permission.
func isBudget(err error) bool {
	var r *Refusal
	if !errors.As(err, &r) {
		return false
	}
	return strings.Contains(r.Reason, "budget") ||
		strings.Contains(r.Reason, "has taken")
}

// from names what produced an observation.
//
// Concatenating the fields worked while there were two and one was always
// empty. A delegate's answer would have come back labelled with the empty
// string, which is the one label a model cannot use to tell two results apart.
func from(a Action) string {
	switch {
	case a.Delegate != "":
		return "delegate/" + a.Delegate
	case a.Tool != "":
		return a.Tool
	}
	return a.Op
}

// personalIn is the kinds of personal data in text, or nothing.
func personalIn(text string, own []string) string {
	seen := map[string]bool{}
	for _, h := range pii.Scan(text, own) {
		seen[strings.ReplaceAll(string(h.Kind), "_", " ")] = true
	}
	kinds := make([]string, 0, len(seen))
	for k := range seen {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return strings.Join(kinds, ", ")
}
