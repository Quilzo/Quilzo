// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"errors"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// What follows an approval: the review a decision made alone owes, and the
// day an approval lapses.
//
// A team of one decides alone because there is nobody else to ask at the
// time, and the decision says so wherever it is shown. The second pair of
// eyes arrives later: somebody else, an executive, the risk function or an
// adviser from outside, looks at exactly what was approved, by its hash,
// and says with their own passkey whether it stands. Until they do the
// review is owed, and once the policy's days have passed it is overdue,
// which is a problem in the posture: a decision made alone and never looked
// at again is a decision nobody checked.

// Held is a decision the register holds with its approval, as what follows
// it is shown.
type Held struct {
	Record register.ID   `json:"record"`
	Kind   register.Kind `json:"kind"`
	// Label names the record, in its own reference and title.
	Label    string             `json:"label"`
	Approval *register.Approval `json:"approval"`
	// Review is the compensating review, once there is one.
	Review *register.Review `json:"review,omitempty"`
	// Overdue says a decision made alone has gone past the day its review
	// was due with none, and Lapsed that the approval has stopped
	// counting.
	Overdue bool `json:"overdue,omitempty"`
	Lapsed  bool `json:"lapsed,omitempty"`
}

// Held is every decision the register holds with an approval, in the order
// of the kinds and then of their identifiers, with where each stands at
// now.
func (m *Approvals) Held() ([]Held, error) {
	now := register.TimeOf(m.now())
	var out []Held
	for _, spec := range register.Kinds() {
		if !carriesApproval(spec) {
			continue
		}
		entries, _, err := m.Register.List(spec.Kind, 0, 0)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			a := register.ApprovalOf(e.Record)
			if a == nil {
				continue
			}
			h := Held{Record: e.ID, Kind: e.Kind, Label: register.Label(e.Record), Approval: a, Lapsed: a.Lapsed(now)}
			if a.Alone {
				rv, err := m.reviewOf(e.ID, a.Surface)
				if err != nil {
					return nil, err
				}
				h.Review = rv
				h.Overdue = rv == nil && a.ReviewDue != 0 && now >= a.ReviewDue
			}
			out = append(out, h)
		}
	}
	return out, nil
}

// Problems are the decisions whose compensating review is overdue, and the
// approvals that have lapsed: what the posture reports.
func (m *Approvals) Problems() (overdue, lapsed []Held, err error) {
	all, err := m.Held()
	if err != nil {
		return nil, nil, err
	}
	for _, h := range all {
		if h.Overdue {
			overdue = append(overdue, h)
		}
		if h.Lapsed {
			lapsed = append(lapsed, h)
		}
	}
	return overdue, lapsed, nil
}

// reviewOf is the review of an approval, or nil when there is none.
func (m *Approvals) reviewOf(id register.ID, surface register.Digest) (*register.Review, error) {
	rid, err := register.IDOf(register.Review{About: id, Surface: surface})
	if err != nil {
		return nil, err
	}
	e, err := m.Register.Get(rid)
	if errors.Is(err, register.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rv, ok := e.Record.(register.Review)
	if !ok {
		return nil, nil
	}
	return &rv, nil
}

// Review is somebody else's compensating review of a decision made alone,
// over the hash of exactly what was approved.
func (m *Approvals) Review(by Person, id register.ID, outcome register.ReviewOutcome, proof Proof) (register.Receipt, error) {
	if m.Audit == nil {
		return register.Receipt{}, fmt.Errorf("the approvals have no audit log to record a review in, so none is made")
	}
	pol, err := m.policy()
	if err != nil {
		return register.Receipt{}, err
	}
	if err := m.mayDecide(pol, by); err != nil {
		return register.Receipt{}, err
	}
	e, err := m.Register.Get(id)
	if err != nil {
		return register.Receipt{}, err
	}
	a := register.ApprovalOf(e.Record)
	if a == nil || !a.Alone {
		return register.Receipt{}, errRefused("only a decision made alone owes a review, and this %s was not made alone",
			strings.ToLower(string(e.Kind)))
	}
	if outcome != "upheld" && outcome != "challenged" {
		return register.Receipt{}, errRefused("a review upholds the decision or challenges it")
	}
	subject, err := m.people().Pseudonym(by.Name)
	if err != nil {
		return register.Receipt{}, err
	}
	if subject == a.Raised {
		return register.Receipt{}, errRefused("you raised this decision, and its review is somebody else's")
	}
	for _, s := range a.Signers {
		if s.Subject == subject {
			return register.Receipt{}, errRefused("you made this decision alone, and its review is somebody else's: " +
				"that is what it is for")
		}
	}
	// Somebody who could have approved it, had they been there, or who
	// the policy names as a second.
	spec, _ := register.SpecOf(string(e.Kind))
	holds := m.ask2(by, auth.Action(a.Atom), spec.Resource()) == nil
	if !holds && pol.functionOf(by.Name) == "" {
		return register.Receipt{}, errRefused("a review is made by somebody who holds %s, or whom the separation policy "+
			"names as a second approver, and you are neither", a.Atom)
	}
	if rv, err := m.reviewOf(id, a.Surface); err != nil {
		return register.Receipt{}, err
	} else if rv != nil {
		return register.Receipt{}, errRefused("this decision has been reviewed already")
	}
	now := m.now()
	ev, err := m.evidenceOf(by, subject, ForReview, a.Surface, proof, now)
	if err != nil {
		m.audited(by, audit.Denied, AuditRefused, map[string]string{"record": string(id), "surface": string(a.Surface),
			"why": err.Error()})
		return register.Receipt{}, err
	}
	d, err := keep(m.Root, ev)
	if err != nil {
		return register.Receipt{}, err
	}
	rv := register.Review{About: id, Surface: a.Surface, Reviewer: subject, At: register.TimeOf(now), Outcome: outcome,
		Assertion: d, Method: ev.Method}
	rc, err := m.Register.Put(m.recorder(by, subject, register.KindReview), "the compensating review of a decision made alone", rv)
	if err != nil && !errors.Is(err, register.ErrUnrecorded) {
		return rc, err
	}
	if aerr := m.audited(by, audit.Success, AuditReviewed, map[string]string{"record": string(id), "surface": string(a.Surface),
		"evidence": string(d), "outcome": string(outcome)}); aerr != nil && err == nil {
		err = aerr
	}
	return rc, err
}

// AuditReviewed is the name a compensating review is recorded under.
const AuditReviewed = "approval.reviewed"
