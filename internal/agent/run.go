package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
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
	// Input is whatever the operation needs. Opaque here.
	Input map[string]any
	// Say is the model's answer when it is finished.
	Say string
}

// Done reports whether this action ends the run.
func (a Action) Done() bool { return a.Op == "" && a.Tool == "" }

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
}

// Spend is what the run cost.
type Spend struct {
	Steps   int
	Tools   int
	Elapsed time.Duration
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
}

// ErrNoDecide is returned when a runner has no way to decide anything.
var ErrNoDecide = errors.New("this runner has no Decide function")

// Run executes one goal under one session.
//
// The session is the authority. Run never consults the manifest directly — if
// it did, there would be two places that decide what an agent may do, and the
// history of this project is that the two disagree.
func (r Runner) Run(ctx context.Context, s *Session, goal string) (Trace, error) {
	t := Trace{Agent: s.Manifest().Name, Goal: goal}
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

	var seen []Observation
	for turn := 1; turn <= maxTurns; turn++ {
		if err := ctx.Err(); err != nil {
			t.Stopped = "cancelled"
			t.Spent = spendOf(s)
			r.record(t, s)
			return t, err
		}

		action, err := r.Decide(ctx, goal, seen)
		if err != nil {
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

		// The one gate. A tool call is authorised by host first, because the
		// useful refusal for "call evil.example.com" names the host rather
		// than the capability.
		if action.Tool != "" {
			err = s.MayReach(hostOf(action))
		} else {
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
				From: action.Op + action.Tool, Err: perr,
				Body: "failed: " + perr.Error(),
			})
		} else {
			step.Result = out
			// Untrusted, always. It came out of the store or off a tool.
			seen = append(seen, Observation{
				From: action.Op + action.Tool, Body: out, Trusted: false,
			})
		}
		t.Steps = append(t.Steps, step)
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
	return Spend{Steps: steps, Tools: tools, Elapsed: elapsed}
}

// hostOf extracts the host an action wants to reach.
//
// Read from the action's own field rather than parsed out of a URL the model
// produced: the allow-list is checked against what the runner will dial, and a
// host taken from one string while a different string is dialled is the bug
// every SSRF filter has had.
func hostOf(a Action) string {
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
