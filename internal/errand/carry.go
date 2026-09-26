// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package errand

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// Do is what actually performs an operation.
//
// Supplied by the caller, because this package has no business knowing how
// to create a task or send a message. It knows whether one may be done.
type Do func(op string, input map[string]string) (string, error)

// Receipt is what happened, and why it was allowed to.
//
// Separate from agent.Receipt, which answers "what did this run do". This
// answers "why does this exist", and the two are read by different people
// at different times: the first by whoever is paying, the second by
// whoever has just found a ticket with their name on it.
type Receipt struct {
	Errand string     `json:"errand"`
	Op     string     `json:"op"`
	State  State      `json:"state"`
	From   Provenance `json:"from"`
	// Agreed names who confirmed and when, so the chain from a sentence
	// somebody said to a thing that happened is one hop.
	Agreed string    `json:"agreed"`
	At     time.Time `json:"at"`
	// Stayed is true when the result reached nobody outside the call.
	Stayed bool     `json:"stayed"`
	Told   []string `json:"told,omitempty"`
	Result string   `json:"result,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// Why is the receipt in a sentence, for somebody who did not ask for it.
func (r Receipt) Why() string {
	if r.From.Gone() {
		return fmt.Sprintf("%s, and the words behind it have since been "+
			"erased", r.Op)
	}
	who := "it stayed inside the call"
	if !r.Stayed {
		who = fmt.Sprintf("it also reached %s", plainly(r.Told))
	}
	return fmt.Sprintf("%s said %q at %s; %s confirmed it; %s",
		r.From.Speaker, r.From.Words, plainClock(r.From.At), r.Agreed, who)
}

func plainly(in []string) string {
	switch len(in) {
	case 0:
		return "nobody"
	case 1:
		return in[0]
	case 2:
		return in[0] + " and " + in[1]
	}
	return strings.Join(in[:len(in)-1], ", ") + " and " + in[len(in)-1]
}

// Approval is a person agreeing that a result may travel further than the
// call it came from.
type Approval struct {
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	Knowing []string  `json:"knowing"`
}

// Covers reports whether an approval was given knowing about these people.
//
// Exact, not a superset. An approval to tell the security team is not an
// approval to tell the security team and a mailing list, and the ordinary
// way that distinction is lost is an approval recorded as a boolean.
//
// A nil approval covers nothing. That is the common call — most errands
// have nobody standing by to approve anything — so it answers rather than
// being a thing every caller has to remember to check first.
func (a *Approval) Covers(who []string) bool {
	if a == nil || a.By == "" {
		return false
	}
	knew := map[string]bool{}
	for _, k := range normalise(a.Knowing) {
		knew[k] = true
	}
	for _, w := range who {
		if !knew[w] {
			return false
		}
	}
	return true
}

// Carry performs an errand.
//
// The order of the checks is the design. Provenance first, because an
// errand with nothing behind it should not reach the manifest at all;
// then the owner's agreement, because that is the human decision; then the
// manifest, which is the chokepoint and is not this package's to weaken;
// then the audience, which is the one thing the manifest cannot see.
func (e *Errand) Carry(s *agent.Session, r Reach, ok *Approval,
	do Do, at time.Time) (Receipt, error) {
	rec := Receipt{Errand: e.ID, Op: e.Op, From: e.From, At: at.UTC()}

	if e.Orphaned() {
		e.Orphan(at)
		rec.State = Orphaned
		rec.Error = "the words behind this were erased"
		return rec, fmt.Errorf("%s: %s", e.ID, rec.Error)
	}
	if e.State != Accepted {
		rec.State = e.State
		return rec, fmt.Errorf(
			"%s has not agreed to this yet; it is %s", e.Owner, e.State)
	}
	if strings.TrimSpace(e.Op) == "" {
		rec.State = Failed
		return rec, fmt.Errorf("this errand names no operation")
	}
	if s == nil {
		rec.State = Failed
		return rec, fmt.Errorf("an errand is carried inside a session, " +
			"because the session is what the manifest is enforced by")
	}
	// The manifest. Authorize spends from the budget and refuses anything
	// outside the declared set, which is not this package's decision to
	// second-guess in either direction.
	if err := s.Authorize(e.Op); err != nil {
		rec.State = Failed
		rec.Error = err.Error()
		return rec, err
	}

	newly := e.Widens(r)
	rec.Stayed = len(newly) == 0
	rec.Told = newly
	if !rec.Stayed && !ok.Covers(newly) {
		rec.State = Failed
		rec.Error = fmt.Sprintf(
			"this came out of a call %s %s in, and doing it would tell "+
				"%s, who %s not. Somebody has to agree to that, knowing "+
				"who it is",
			plainly(e.Heard), were(e.Heard), plainly(newly), were(newly))
		return rec, fmt.Errorf("%s", rec.Error)
	}
	if !rec.Stayed {
		rec.Agreed = ok.By
	}

	out, err := do(e.Op, e.Input)
	if err != nil {
		e.State, e.When = Failed, at.UTC()
		rec.State, rec.Error = Failed, err.Error()
		return rec, err
	}
	e.State, e.When = Carried, at.UTC()
	rec.State, rec.Result = Carried, out
	if rec.Agreed == "" {
		rec.Agreed = e.Owner
	}
	return rec, nil
}

func were(in []string) string {
	if len(in) == 1 {
		return "was"
	}
	return "were"
}

// List is a set of errands from one call.
type List struct {
	Call    string    `json:"call"`
	Errands []*Errand `json:"errands"`
}

// Add appends an errand.
func (l *List) Add(e Errand) *Errand {
	l.Errands = append(l.Errands, &e)
	return l.Errands[len(l.Errands)-1]
}

// For is everything one person agreed to do.
func (l *List) For(owner string) []*Errand {
	var out []*Errand
	for _, e := range l.Errands {
		if strings.EqualFold(e.Owner, owner) {
			out = append(out, e)
		}
	}
	return out
}

// Waiting is everything nobody has confirmed yet, oldest first.
func (l *List) Waiting() []*Errand {
	var out []*Errand
	for _, e := range l.Errands {
		if e.State == Proposed {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Made.Before(out[j].Made)
	})
	return out
}

// Erased marks every errand resting on one speaker's words.
//
// Called when somebody withdraws consent. Returns what was orphaned, so
// the people who had those tasks can be told rather than finding out by
// noticing something is missing.
func (l *List) Erased(seat int, at time.Time) []*Errand {
	var out []*Errand
	for _, e := range l.Errands {
		if e.From.Seat == seat && !e.Orphaned() {
			e.Orphan(at)
			out = append(out, e)
		}
	}
	return out
}

// Owners is everybody who has something outstanding.
func (l *List) Owners() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range l.Errands {
		if e.State == Carried || e.State == Declined || e.Orphaned() {
			continue
		}
		k := strings.ToLower(e.Owner)
		if !seen[k] {
			seen[k] = true
			out = append(out, e.Owner)
		}
	}
	sort.Strings(out)
	return out
}
