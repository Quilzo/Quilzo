// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// Decisions: a starter taken in or out, a scope, a line of the statement of
// applicability, a control test. Each is a record that carries the approval
// of the person who decided it, and each is made one of two ways. The
// person who raises it is the only person who may approve it, and it is
// written at once, marked as approved alone with a review by somebody else
// due; or somebody else may, and it waits on the register's proposals ref
// until one of them approves it (Approve). Nobody approves what they
// raised while anybody else could.

// Programme is the security programme kept in one register.
type Programme struct {
	Reg *register.Register
	// Keep keeps who each pseudonym is and the words of justifications.
	Keep Keeper
	// Now is the clock. Nil is the system's.
	Now func() time.Time
}

func (p *Programme) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

// Decider is a person deciding, as the surface they came through proved
// them.
type Decider struct {
	// By is the person, as the register names a writer. A decision is a
	// person's: By.Kind is a person and By.Subject their pseudonym.
	By register.Actor
	// Eligible is how many people may approve a decision of this kind, as
	// the access policy has it when they ask, themselves included when
	// MayApprove says they are one of them.
	Eligible int
	// MayApprove says the policy lets this person approve a decision of
	// this kind. Somebody who may not decides nothing alone: what they
	// raise waits for somebody who may.
	MayApprove bool
	// Proof is what the surface proved them by: the name of the credential
	// they signed in with and how. It is hashed with the decision's surface
	// into the approval's assertion, so the approval names what was
	// approved and how its approver was known.
	Proof string
}

// ReviewWithin is how soon a decision made alone is reviewed by somebody
// else. A team of one decides; a month later another person looks.
const ReviewWithin = 30 * 24 * time.Hour

// ErrWaits is a decision that cannot be approved by whoever raised it,
// because somebody else may: it waits for them.
var ErrWaits = errors.New("somebody else who may approve it decides this")

// Decided is what became of a decision raised or approved.
type Decided struct {
	// ID is the decision's record, in the register or waiting.
	ID register.ID `json:"id"`
	// Waits says it is on the proposals ref, for somebody else.
	Waits bool `json:"waits,omitempty"`
	// Alone says it was approved by the only person eligible.
	Alone   bool             `json:"alone,omitempty"`
	Receipt register.Receipt `json:"receipt"`
}

// approvalOf is a person's approval of a record that somebody raised.
func (p *Programme) approvalOf(rec register.Record, raised register.ID, d Decider, at time.Time) (*register.Approval, error) {
	if d.By.Kind != audit.KindHuman || !d.By.Subject.Valid() {
		return nil, fmt.Errorf("%w: a decision is a person's, named by their pseudonym", register.ErrModel)
	}
	eligible := d.Eligible
	if eligible < 1 {
		eligible = 1
	}
	id, err := register.IDOf(rec)
	if err != nil {
		return nil, err
	}
	surface, err := p.Reg.Surface(rec, id)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("quilzo/approval evidence v1\n" + string(surface) + "\n" + d.Proof))
	a := &register.Approval{Atom: string(auth.ActApprove), Rule: "raiser-is-not-approver", Needed: 1, Of: eligible,
		Surface: surface, Raised: raised,
		Signers: []register.Signer{{Subject: d.By.Subject, At: register.TimeOf(at),
			Assertion: register.Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))}}}
	if raised == d.By.Subject {
		if eligible > 1 || !d.MayApprove {
			return nil, ErrWaits
		}
		a.Rule, a.Alone, a.ReviewDue = "only-person-eligible", true, register.TimeOf(at.Add(ReviewWithin))
	}
	return a, nil
}

// Raise makes a decision a person raises: written at once, with what
// follows from it, when they are the only person who may approve it, and
// otherwise proposed, to wait for somebody else.
func (p *Programme) Raise(d Decider, why string, rec register.Record) (Decided, error) {
	follows, err := p.follows(rec)
	if err != nil {
		return Decided{}, err
	}
	id, err := register.IDOf(rec)
	if err != nil {
		return Decided{}, err
	}
	a, err := p.approvalOf(rec, d.By.Subject, d, p.now())
	if errors.Is(err, ErrWaits) {
		rc, err := p.Reg.Propose(d.By, why, rec)
		return Decided{ID: id, Waits: true, Receipt: rc}, err
	}
	if err != nil {
		return Decided{}, err
	}
	rc, err := p.Reg.Put(d.By, why, append([]register.Record{withApproval(rec, a)}, follows...)...)
	return Decided{ID: id, Alone: a.Alone, Receipt: rc}, err
}

// Approve is a person's approval of a decision that waits, written with
// what follows from it in one commit. The person who raised it is named as
// having asked; the register refuses an approver who proposed it.
func (p *Programme) Approve(d Decider, id register.ID) (Decided, error) {
	waiting, err := p.Reg.Proposals()
	if err != nil {
		return Decided{}, err
	}
	var found *register.Proposal
	for i := range waiting {
		if waiting[i].ID == id {
			found = &waiting[i]
		}
	}
	if found == nil {
		return Decided{}, fmt.Errorf("%w: no decision with the identifier %s is waiting", register.ErrNotFound, id)
	}
	raised := found.Subject
	if raised == "" {
		// An agent asked: it is named by a pseudonym of its own, as an
		// agent, so the approval says what asked.
		if raised, err = p.Keep.Pseudonym("agent:"+found.Agent, "agent"); err != nil {
			return Decided{}, err
		}
	}
	rec := withApproval(found.Record, nil)
	follows, err := p.follows(rec)
	if err != nil {
		return Decided{}, err
	}
	if t, ok := rec.(register.ControlTest); ok {
		if err := p.sameDenominator(t); err != nil {
			return Decided{}, err
		}
		q, err := p.waitingQuery(waiting, t.Query)
		if err != nil {
			return Decided{}, err
		}
		if q != nil {
			follows = append(follows, *q)
		}
	}
	a, err := p.approvalOf(rec, raised, d, p.now())
	if errors.Is(err, ErrWaits) || err == nil && raised == d.By.Subject {
		return Decided{}, fmt.Errorf("%w: whoever raised a decision is not the one who approves it", register.ErrRefused)
	}
	if err != nil {
		return Decided{}, err
	}
	rc, err := p.Reg.AcceptWith(d.By, id, a, follows...)
	return Decided{ID: id, Receipt: rc}, err
}

// follows is what a decision brings with it, written in its commit: a
// starter taken in brings its requirements and mappings, and a starter
// whose content is not one this program carries is refused, because what
// would be approved is not what would be written.
func (p *Programme) follows(rec register.Record) ([]register.Record, error) {
	s, ok := rec.(register.Starter)
	if !ok {
		return nil, nil
	}
	st, found := StarterNamed(s.Framework)
	if !found {
		return nil, fmt.Errorf("%w: there is no starter for %q", register.ErrNotFound, s.Framework)
	}
	if s.Content != st.Content() || s.Version != st.Version {
		return nil, fmt.Errorf("%w: the decision is about another edition of the %s starter than this program carries",
			register.ErrInvalid, s.Framework)
	}
	if !s.Installed {
		return nil, nil
	}
	return st.Records()
}

// withApproval is a record with its approval set, of whichever kind.
func withApproval(rec register.Record, a *register.Approval) register.Record {
	switch r := rec.(type) {
	case register.Starter:
		r.Approval = a
		return r
	case register.Scope:
		r.Approval = a
		return r
	case register.Applicability:
		r.Approval = a
		return r
	case register.ControlTest:
		r.Approval = a
		return r
	}
	return rec
}
