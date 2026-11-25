// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/register"
)

// The check the register makes of every approval written to it.
//
// Sign builds an approval from evidence it has checked. The register checks
// it again, at its one write path, against nothing but the record, the
// store's declared separation policy and the evidence beside the store: the
// record as it will be written has the hash the approvers signed; the
// approval names the rule the policy decides the record by, and asks at
// least as many people as that rule does of it; each signer's evidence is
// kept under the digest the record names, is theirs, is for that hash (or
// for a batch whose record holds it), was given within the days a request
// waits for its approvers, and its signature holds. A writer that assembled
// an approval any other way, by hand, from an unfinished or a lapsed
// request, or for another record, is refused there, whichever surface it
// came through. Only the evidence was checked, so one genuine signature of
// a decision that takes two was an approval of it, put together by hand.
//
// It is held to the policy declared beside the store, or the default, and
// not to one a caller of the module set in memory (Approvals.Separation),
// which is for tests.

func init() {
	register.CheckApprovalsWith(func(r *register.Register) func(register.Record, register.ID, *register.Approval) error {
		return func(rec register.Record, id register.ID, a *register.Approval) error {
			return Verify(r, rec, id, a)
		}
	})
}

// Verify checks an approval's authentication evidence against the record it
// approves, in the register r, whose store's directory holds the evidence.
func Verify(r *register.Register, rec register.Record, id register.ID, a *register.Approval) error {
	if r == nil || r.Store == nil {
		return fmt.Errorf("there is no register to check the approval against")
	}
	root := r.Store.Root()
	s, err := SurfaceOf(r, rec, id)
	if err != nil {
		return err
	}
	if got := s.Digest(); got != a.Surface {
		return fmt.Errorf("it approves %s, and this record as it would be written is %s: what was approved is "+
			"not what is being written", a.Surface, got)
	}
	pol, _, err := LoadPolicy(root)
	if err != nil {
		return err
	}
	rule, ok := pol.RuleFor(rec)
	if !ok {
		return fmt.Errorf("no rule of the separation policy decides this %s, so nothing approves it",
			strings.ToLower(string(rec.Kind())))
	}
	if a.Rule != rule.Name || a.Atom != string(rule.Atom) {
		return fmt.Errorf("it says it was approved under the rule %s by %s, and the separation policy decides it under "+
			"%s by %s", clip(a.Rule), clip(a.Atom), rule.Name, rule.Atom)
	}
	need, _, err := (&Approvals{Root: root, Register: r}).needed(rule, rec)
	if err != nil {
		return err
	}
	if a.Needed < need {
		return fmt.Errorf("the separation policy asks %d approvers of it, and the approval says %d", need, a.Needed)
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	oldest := register.TimeOf(now.Add(-time.Duration(pol.WaitDays) * 24 * time.Hour))
	for _, sg := range a.Signers {
		ev, err := LoadEvidence(root, sg.Assertion)
		if err != nil {
			return err
		}
		if ev.At < oldest {
			return fmt.Errorf("the evidence %s was given more than %d days ago, in a request that has lapsed with "+
				"its signatures since: it is no longer anybody's agreement", sg.Assertion, pol.WaitDays)
		}
		method := sg.Method
		if method == "" {
			method = "passkey"
		}
		switch {
		case ev.Subject != sg.Subject:
			return fmt.Errorf("the evidence %s is somebody else's than the signer it is named for", sg.Assertion)
		case ev.Method != method:
			return fmt.Errorf("the signer is said to have approved by %s, and their evidence is a %s's", method, ev.Method)
		case sg.Batch == "" && (ev.Purpose != ForApproval || ev.For != a.Surface):
			return fmt.Errorf("the evidence %s is not an approval of this surface", sg.Assertion)
		case sg.Batch != "" && (ev.Purpose != ForBatch || ev.For != sg.Batch):
			return fmt.Errorf("the evidence %s is not an approval of the batch %s", sg.Assertion, sg.Batch)
		}
		if sg.Batch != "" {
			if err := batchHolds(r, sg.Batch, sg.Subject, id, a.Surface); err != nil {
				return err
			}
		}
		if err := ev.Check(); err != nil {
			return err
		}
	}
	return nil
}

// batchHolds refuses an approval given in a batch whose record, the
// approver's own, does not hold its surface among the leaves they signed
// the root of.
func batchHolds(r *register.Register, root register.Digest, approver, id register.ID, surface register.Digest) error {
	bid, err := register.IDOf(register.ApprovalBatch{Root: root, Approver: approver})
	if err != nil {
		return err
	}
	e, err := r.Get(bid)
	if err != nil {
		return fmt.Errorf("the batch %s it was approved in is not in the register: %w", root, err)
	}
	b, ok := e.Record.(register.ApprovalBatch)
	if !ok || !b.Covers(id, surface) {
		return fmt.Errorf("the batch %s it was approved in does not hold this record as approved", root)
	}
	return nil
}
