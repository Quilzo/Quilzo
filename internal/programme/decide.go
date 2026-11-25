// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

import (
	"errors"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/register"
)

// Decisions: a starter taken in or out, a scope, a line of the statement of
// applicability, a control test. Each is a record that carries the approval
// of the person who decided it, and each is decided the one way every
// decision in the register is: raised as a proposal (Raise), where it
// waits, and approved through the approvals module's engine (Approve here,
// Sign-off in the admin, `quilzo approval approve` at the console), under
// the organisation's separation policy. The engine holds the rules: nobody
// approves what they raised while anybody else could, no agent approves
// anything, an approver signs in in a way that cannot be phished, each
// approval is bound to the hash of what was shown and lapses at the end of
// its rule's term, and the only person eligible approves alone, marked so,
// with a review by somebody else owed.
//
// The programme says only what a decision brings with it (FollowWith): a
// starter its requirements and mappings, refused for an edition this
// program does not carry, and a control test the query waiting beside it,
// refused when its population was redefined since it was drafted.

func init() {
	approval.FollowWith(register.KindStarter, func(r *register.Register, rec register.Record, _ []register.Proposal) ([]register.Record, error) {
		return (&Programme{Reg: r}).follows(rec)
	})
	approval.FollowWith(register.KindControlTest, func(r *register.Register, rec register.Record, waiting []register.Proposal) ([]register.Record, error) {
		p := &Programme{Reg: r}
		t, ok := rec.(register.ControlTest)
		if !ok {
			return nil, nil
		}
		if err := p.sameDenominator(t); err != nil {
			return nil, err
		}
		q, err := p.waitingQuery(waiting, t.Query)
		if err != nil || q == nil {
			return nil, err
		}
		return []register.Record{*q}, nil
	})
}

// Programme is the security programme kept in one register.
type Programme struct {
	Reg *register.Register
	// Approvals is the approvals module the programme's decisions are
	// approved through, over Reg. Nil is one with no access control, where
	// whoever is at the store is its owner and the one person eligible.
	Approvals *approval.Approvals
	// Now is the clock. Nil is the system's.
	Now func() time.Time
}

func (p *Programme) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func (p *Programme) approvals() *approval.Approvals {
	if p.Approvals != nil {
		return p.Approvals
	}
	return &approval.Approvals{Root: p.Reg.Store.Root(), Register: p.Reg, Audit: p.Reg.Audit, Now: p.Now}
}

// ReviewWithin is how soon a decision made alone is reviewed by somebody
// else, under the default separation policy. A team of one decides; a
// month later another person looks.
const ReviewWithin = 30 * 24 * time.Hour

// ErrWaits is a decision that waits for an approval that has not been
// given, by somebody else or by its raiser alone.
var ErrWaits = errors.New("the decision waits for its approval")

// Decided is what became of a decision raised or approved.
type Decided struct {
	// ID is the decision's record, in the register or waiting.
	ID register.ID `json:"id"`
	// Waits says it is on the proposals ref, for its approvers.
	Waits bool `json:"waits,omitempty"`
	// Surface is the hash of what its approvers are shown, which an
	// approval at the console types back and a passkey signs.
	Surface register.Digest `json:"surface,omitempty"`
	// Yours says the person who raised it is the only person eligible to
	// approve it, and so approves it alone.
	Yours bool `json:"yours,omitempty"`
	// Signed and Needed are the approvals given and how many the rule asks.
	Signed int `json:"signed,omitempty"`
	Needed int `json:"needed,omitempty"`
	// Alone says it was approved by the only person eligible.
	Alone   bool             `json:"alone,omitempty"`
	Receipt register.Receipt `json:"receipt"`
}

// Raise proposes a decision a person raises, to wait for its approval. What
// it brings is checked first, so a decision that could not be written is
// never asked of anybody.
func (p *Programme) Raise(by register.Actor, why string, rec register.Record) (Decided, error) {
	if by.Kind != audit.KindHuman || !by.Subject.Valid() {
		return Decided{}, fmt.Errorf("%w: a decision is raised by a person, named by their pseudonym", register.ErrModel)
	}
	rec = withApproval(rec, nil)
	if _, err := p.follows(rec); err != nil {
		return Decided{}, err
	}
	id, err := register.IDOf(rec)
	if err != nil {
		return Decided{}, err
	}
	rc, err := p.Reg.Propose(by, why, rec)
	if err != nil {
		return Decided{}, err
	}
	d := Decided{ID: id, Waits: true, Receipt: rc}
	if a, err := p.approvals().Ask(id); err == nil {
		d.Surface, d.Needed, d.Yours = a.Hash, a.Needed, a.Yours(by.Name, by.Subject)
	}
	return d, nil
}

// Approve is a person's approval of a decision that waits, through the
// approvals module, over the hash proof was given for. With as many
// approvals as the rule asks, the decision is written with what it brings
// in one commit; until then it waits, and Waits says so.
func (p *Programme) Approve(by approval.Person, id register.ID, proof approval.Proof) (Decided, error) {
	out, err := p.approvals().Sign(by, id, proof)
	if out == nil {
		return Decided{ID: id}, err
	}
	d := Decided{ID: id, Waits: !out.Done, Surface: out.Surface, Signed: out.Signed, Needed: out.Needed, Alone: out.Alone}
	if out.Receipt != nil {
		d.Receipt = *out.Receipt
	}
	return d, err
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
	return register.WithApproval(rec, a)
}
