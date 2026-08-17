// Package agentwatch notices when a model starts behaving badly.
//
// # Why the audit log is the only input
//
// Everything this needs is already recorded: who acted, whether they were a
// model, what they tried, and whether it was refused. So this reads the log
// rather than adding instrumentation, and that has a property worth stating —
// an agent cannot avoid detection by taking a path that was not instrumented,
// because the log is what the system already believes happened. Adding a new
// counter somewhere would create exactly that gap.
//
// # Being refused is not the same as misbehaving
//
// The distinction this package exists to make, and the one an earlier version
// of this idea got wrong: an agent that attempts something, is told it needs
// approval, and stops has behaved correctly. It asked. Counting that against it
// quarantines the well-behaved agents fastest, because they are the ones that
// try things and accept the answer.
//
// What counts is attempting something the agent was never permitted to do —
// reaching for a role it does not hold, writing content that fails a gate it
// should have satisfied, retrying a refusal it has already been given. The
// shape being detected is not "was refused" but "keeps trying".
//
// # Quarantine is a suggestion to a person
//
// Nothing here revokes anything on its own. It reports, and the report names
// what it saw and when. Automatic revocation on a heuristic means a busy
// afternoon of legitimate work looks like an incident and the agent doing that
// work is cut off — after which somebody turns the detector off, and then it
// detects nothing at all.
package agentwatch

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

// Window is how far back behaviour is considered.
//
// Twenty-four hours. Long enough that a pattern spread over an afternoon is
// visible, short enough that something from last month is not still counting
// against an agent that has behaved since.
const Window = 24 * time.Hour

// Threshold is how many strikes before an agent is flagged.
const Threshold = 5

// Strike is one thing an agent did that it should not have.
type Strike struct {
	// Kind names the pattern, so a report can group rather than list.
	Kind string `json:"kind"`
	// Seq points at the audit entry, so every strike is checkable against the
	// record rather than being this package's opinion.
	Seq      int64  `json:"seq"`
	At       string `json:"at"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Why      string `json:"why"`
}

// The patterns. Each names something an agent did that a correctly behaving one
// would not, and each is deliberately narrow — a broad rule produces a detector
// people stop reading.
const (
	// RepeatedRefusal is the core signal: being told no and trying the same
	// thing again. Once is an agent exploring; five times is an agent that has
	// not accepted the answer.
	RepeatedRefusal = "repeated-refusal"
	// Escalation is reaching for something above the role it holds.
	Escalation = "escalation"
	// GateFailure is content refused by a check the agent should have satisfied
	// — a content type, the accessibility gate, provenance.
	GateFailure = "gate-failure"
	// Unattributed is an action recorded with no verified identity behind it,
	// from a surface that should have one.
	Unattributed = "unattributed"
)

// Report is what was seen about one agent.
type Report struct {
	Principal string   `json:"principal"`
	Model     string   `json:"model,omitempty"`
	Strikes   []Strike `json:"strikes"`
	// Counts group the strikes, because "twelve refusals" is a different
	// situation from "twelve different things" and a flat list hides which.
	Counts map[string]int `json:"counts"`
	// Actions is how much the agent did in total, so a rate can be judged. Six
	// strikes in six actions is a different agent from six in six thousand.
	Actions int `json:"actions"`
	// Flagged is whether this crossed the threshold. It is not a decision.
	Flagged bool   `json:"flagged"`
	Summary string `json:"summary"`
}

// Look examines the log and reports on every agent that appears in it.
func Look(events []audit.Event, now time.Time) []Report {
	cutoff := now.Add(-Window)

	type agent struct {
		model    string
		actions  int
		strikes  []Strike
		refusals map[string]int // action+resource -> times refused
	}
	agents := map[string]*agent{}

	for _, e := range events {
		if e.Kind != audit.KindAI {
			continue
		}
		at, err := time.Parse(time.RFC3339, e.At)
		if err != nil || at.Before(cutoff) {
			continue
		}

		a := agents[e.Principal]
		if a == nil {
			a = &agent{refusals: map[string]int{}}
			agents[e.Principal] = a
		}
		if e.Model != "" {
			a.model = e.Model
		}
		a.actions++

		if e.Outcome != audit.Denied {
			continue
		}

		reason := e.Detail["reason"]
		// An agent told it needs approval, that stopped, behaved correctly. It
		// asked. Counting that is what quarantines the well-behaved agents
		// fastest, because they are the ones that try and accept the answer.
		if isApprovalRefusal(reason) {
			continue
		}

		key := e.Action + " " + e.Resource
		a.refusals[key]++

		s := Strike{
			Seq: e.Seq, At: e.At, Action: e.Action, Resource: e.Resource,
		}
		switch {
		case a.refusals[key] > 1:
			s.Kind = RepeatedRefusal
			s.Why = fmt.Sprintf(
				"the same request has now been refused %d times; the first is "+
					"an agent exploring, this is one that has not accepted the "+
					"answer", a.refusals[key])
		case strings.Contains(reason, "authorisation"),
			strings.Contains(reason, "role"),
			strings.Contains(reason, "permit"):
			s.Kind = Escalation
			s.Why = "reached for something above the role it holds"
		case strings.Contains(reason, "accessibility"),
			strings.Contains(reason, "provenance"),
			strings.Contains(reason, "type"):
			s.Kind = GateFailure
			s.Why = "produced content refused by a gate it should have satisfied"
		default:
			s.Kind = RepeatedRefusal
			s.Why = "refused: " + reason
		}
		a.strikes = append(a.strikes, s)
	}

	// An unverified AI action is its own signal, counted once per agent rather
	// than per action — otherwise a single misconfiguration produces thousands
	// of strikes and buries everything else.
	for principal, a := range agents {
		if unverified := countUnverified(events, principal, cutoff); unverified > 0 {
			a.strikes = append(a.strikes, Strike{
				Kind: Unattributed,
				Why: fmt.Sprintf(
					"%d actions were recorded with no verified identity, so the "+
						"log cannot say which agent took them", unverified),
			})
		}
	}

	var out []Report
	for principal, a := range agents {
		r := Report{
			Principal: principal, Model: a.model, Strikes: a.strikes,
			Actions: a.actions, Counts: map[string]int{},
		}
		for _, s := range a.strikes {
			r.Counts[s.Kind]++
		}
		r.Flagged = len(a.strikes) >= Threshold
		r.Summary = summarise(r)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Strikes) != len(out[j].Strikes) {
			return len(out[i].Strikes) > len(out[j].Strikes)
		}
		return out[i].Principal < out[j].Principal
	})
	return out
}

// isApprovalRefusal recognises the refusal that means "you asked correctly".
func isApprovalRefusal(reason string) bool {
	r := strings.ToLower(reason)
	return strings.Contains(r, "approval") || strings.Contains(r, "dual-authorization") ||
		strings.Contains(r, "needs a human") || strings.Contains(r, "cannot also approve")
}

func countUnverified(events []audit.Event, principal string, cutoff time.Time) int {
	n := 0
	for _, e := range events {
		if e.Kind != audit.KindAI || e.Principal != principal || e.Verified {
			continue
		}
		if at, err := time.Parse(time.RFC3339, e.At); err == nil && at.After(cutoff) {
			n++
		}
	}
	return n
}

func summarise(r Report) string {
	if len(r.Strikes) == 0 {
		return fmt.Sprintf("%d actions, nothing refused", r.Actions)
	}
	var parts []string
	for _, k := range []string{RepeatedRefusal, Escalation, GateFailure, Unattributed} {
		if n := r.Counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	// The rate, not just the count. Six strikes in six actions is a different
	// agent from six in six thousand, and a report that cannot tell them apart
	// is one that flags the busy agent and misses the bad one.
	return fmt.Sprintf("%s across %d actions", strings.Join(parts, ", "), r.Actions)
}

// Flagged returns only the agents over the threshold.
func Flagged(reports []Report) []Report {
	var out []Report
	for _, r := range reports {
		if r.Flagged {
			out = append(out, r)
		}
	}
	return out
}
