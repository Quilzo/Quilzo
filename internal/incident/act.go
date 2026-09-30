// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package incident

import (
	"fmt"
	"strings"
	"time"
)

// Acts: the things done to another tool during an incident.
//
// A playbook step is carried out by a person. An act is carried out by
// this program — it suspends the account — and so it has more between
// asking and doing than anything else here:
//
//   - Somebody requests it, naming the account and saying why.
//   - Somebody else approves it, or the commander does. The request shows
//     the exact call that will be made; approval is of that.
//   - It is recorded as approved before the call is made and as done or
//     failed after. If this program dies in between, the record says the
//     outcome is not known, which is true, and not that nothing happened.
//   - One that can be reversed can be, by anybody working the incident,
//     with a reason. Undoing is the safe direction and waits for nobody.
//
// What may be acted on is decided outside this package, by whoever can see
// the findings: only an account the incident is already about.

// ActState is where an act has got to.
type ActState string

const (
	ActRequested ActState = "requested"
	// ActApproved is approved and sent, with no outcome recorded yet.
	ActApproved  ActState = "approved"
	ActDone      ActState = "done"
	ActFailed    ActState = "failed"
	ActWithdrawn ActState = "withdrawn"
	// ActUndoing is an undo sent, with no outcome recorded yet.
	ActUndoing ActState = "undoing"
	ActUndone  ActState = "undone"
)

// Act is one thing done, or to be done, to another tool.
type Act struct {
	ID int `json:"id"`
	// Action is the declared action's name, and Title what it is called.
	Action string `json:"action"`
	Title  string `json:"title"`
	// Target is the account or thing, as issuer:value.
	Target string `json:"target"`
	// Says is the call itself, as it was shown to whoever approved it.
	Says       string `json:"says"`
	Reversible bool   `json:"reversible,omitempty"`

	State     ActState `json:"state"`
	Requested Moment   `json:"requested"`
	Approved  *Moment  `json:"approved,omitempty"`
	Undone    *Moment  `json:"undone,omitempty"`
	// Code is the tool's answer to the last call, and At when it came.
	Code int       `json:"code,omitempty"`
	At   time.Time `json:"at,omitzero"`
}

// Unknown reports whether a call was sent and no answer was recorded: the
// state a crash between the two leaves behind.
func (a Act) Unknown() bool { return a.State == ActApproved || a.State == ActUndoing }

// MaxActs bounds how many acts one incident takes. Past this it is not a
// response, it is a script.
const MaxActs = 20

func (i *Incident) act(id int) *Act {
	for n := range i.Acts {
		if i.Acts[n].ID == id {
			return &i.Acts[n]
		}
	}
	return nil
}

// RequestAct asks for an action to be taken. Nothing is sent.
func (i *Incident) RequestAct(spec Act, by, why string, at time.Time) (int, error) {
	if strings.TrimSpace(why) == "" {
		return 0, fmt.Errorf("say why. Somebody approves this from the " +
			"reason and the call, and afterwards the reason is the record")
	}
	if strings.TrimSpace(spec.Action) == "" || strings.TrimSpace(spec.Target) == "" ||
		strings.TrimSpace(spec.Says) == "" {
		return 0, fmt.Errorf("an act names an action, what it acts on, and " +
			"the call it makes")
	}
	if len(i.Acts) >= MaxActs {
		return 0, fmt.Errorf("this incident has taken %d acts", MaxActs)
	}
	for _, a := range i.Acts {
		if a.Action == spec.Action && a.Target == spec.Target &&
			(a.State == ActRequested || a.Unknown() || a.State == ActDone) {
			return 0, fmt.Errorf("%s on %s is already %s", spec.Action,
				spec.Target, a.State)
		}
	}
	spec.ID = len(i.Acts) + 1
	spec.State = ActRequested
	spec.Requested = Moment{At: at.UTC(), By: by, Why: strings.TrimSpace(why)}
	spec.Approved, spec.Undone, spec.Code, spec.At = nil, nil, 0, time.Time{}
	i.Acts = append(i.Acts, spec)
	i.note(by, fmt.Sprintf("requested %s on %s: %s", spec.Action, spec.Target,
		strings.TrimSpace(why)), at)
	return spec.ID, nil
}

// ApproveAct marks a requested act as approved and about to be sent.
//
// By somebody other than whoever asked, or by the commander: the same rule
// as a playbook, for the same reason, and here it is what stands between
// one person and another person's account.
func (i *Incident) ApproveAct(id int, by string, at time.Time) (Act, error) {
	a := i.act(id)
	if a == nil {
		return Act{}, fmt.Errorf("there is no act %d", id)
	}
	if a.State != ActRequested {
		return Act{}, fmt.Errorf("act %d is %s", id, a.State)
	}
	commanding := strings.EqualFold(strings.TrimSpace(i.Filled[Commander]), by)
	if !commanding && strings.EqualFold(a.Requested.By, by) {
		return Act{}, fmt.Errorf("%s asked for this. It is approved by "+
			"somebody else, or by whoever is commanding the incident", by)
	}
	a.Approved = &Moment{At: at.UTC(), By: by, Why: "approved"}
	a.State = ActApproved
	i.note(by, fmt.Sprintf("approved %s on %s", a.Action, a.Target), at)
	return *a, nil
}

// WithdrawAct takes back a request nobody approved.
func (i *Incident) WithdrawAct(id int, by, why string, at time.Time) error {
	a := i.act(id)
	if a == nil {
		return fmt.Errorf("there is no act %d", id)
	}
	if a.State != ActRequested {
		return fmt.Errorf("act %d is %s, and only a request can be withdrawn",
			id, a.State)
	}
	if strings.TrimSpace(why) == "" {
		return fmt.Errorf("say why it is not needed after all")
	}
	a.State = ActWithdrawn
	i.note(by, fmt.Sprintf("withdrew %s on %s: %s", a.Action, a.Target,
		strings.TrimSpace(why)), at)
	return nil
}

// FinishAct records the tool's answer to an approved act.
func (i *Incident) FinishAct(id int, ok bool, code int, at time.Time) error {
	a := i.act(id)
	if a == nil || a.State != ActApproved {
		return fmt.Errorf("act %d was not waiting for an answer", id)
	}
	a.Code, a.At = code, at.UTC()
	a.State = ActFailed
	word := "failed"
	if ok {
		a.State, word = ActDone, "done"
	}
	i.note("quilzo", fmt.Sprintf("%s on %s %s (the tool answered %d)", a.Action,
		a.Target, word, code), at)
	return nil
}

// UndoAct marks a done act as being reversed.
func (i *Incident) UndoAct(id int, by, why string, at time.Time) (Act, error) {
	a := i.act(id)
	if a == nil {
		return Act{}, fmt.Errorf("there is no act %d", id)
	}
	if a.State != ActDone {
		return Act{}, fmt.Errorf("act %d is %s; only something done can be "+
			"undone", id, a.State)
	}
	if !a.Reversible {
		return Act{}, fmt.Errorf("%s cannot be undone from here", a.Action)
	}
	if strings.TrimSpace(why) == "" {
		return Act{}, fmt.Errorf("say why it is being undone")
	}
	a.Undone = &Moment{At: at.UTC(), By: by, Why: strings.TrimSpace(why)}
	a.State = ActUndoing
	i.note(by, fmt.Sprintf("undoing %s on %s: %s", a.Action, a.Target,
		strings.TrimSpace(why)), at)
	return *a, nil
}

// FinishUndo records the tool's answer to an undo. One that failed leaves
// the act done: the account is still as the act left it.
func (i *Incident) FinishUndo(id int, ok bool, code int, at time.Time) error {
	a := i.act(id)
	if a == nil || a.State != ActUndoing {
		return fmt.Errorf("act %d was not being undone", id)
	}
	a.Code, a.At = code, at.UTC()
	if ok {
		a.State = ActUndone
		i.note("quilzo", fmt.Sprintf("%s on %s undone (the tool answered %d)",
			a.Action, a.Target, code), at)
		return nil
	}
	a.State, a.Undone = ActDone, nil
	i.note("quilzo", fmt.Sprintf("undoing %s on %s failed (the tool answered "+
		"%d); it is still in force", a.Action, a.Target, code), at)
	return nil
}

// ActsOpen names the acts an incident cannot close over: asked for and
// never answered, or sent with no outcome recorded.
func (i *Incident) ActsOpen() []string {
	var out []string
	for _, a := range i.Acts {
		switch {
		case a.State == ActRequested:
			out = append(out, fmt.Sprintf("%s on %s (requested, never "+
				"approved or withdrawn)", a.Action, a.Target))
		case a.Unknown():
			out = append(out, fmt.Sprintf("%s on %s (sent, outcome not "+
				"known: check the tool)", a.Action, a.Target))
		}
	}
	return out
}

// InForce names the reversible acts still in force, for whoever is closing:
// a suspended account stays suspended after the incident is over.
func (i *Incident) InForce() []string {
	var out []string
	for _, a := range i.Acts {
		if a.State == ActDone && a.Reversible {
			out = append(out, a.Action+" on "+a.Target)
		}
	}
	return out
}
