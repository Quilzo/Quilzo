// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/register"
)

// The check the register makes of every approval written to it.
//
// Sign builds an approval from evidence it has checked. The register checks
// it again, at its one write path, against nothing but the record and the
// evidence beside the store: the record as it will be written has the hash
// the approvers signed, each signer's evidence is kept under the digest the
// record names, is theirs, is for that hash (or for a batch whose record
// holds it), and its signature holds. A writer that assembled an approval
// any other way, by hand, from an old request or for another record, is
// refused there, whichever surface it came through.

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
	for _, sg := range a.Signers {
		ev, err := LoadEvidence(root, sg.Assertion)
		if err != nil {
			return err
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
			if err := batchHolds(r, sg.Batch, id, a.Surface); err != nil {
				return err
			}
		}
		if err := ev.Check(); err != nil {
			return err
		}
	}
	return nil
}

// batchHolds refuses an approval given in a batch whose record does not
// hold its surface among the leaves the approver signed the root of.
func batchHolds(r *register.Register, root register.Digest, id register.ID, surface register.Digest) error {
	bid, err := register.IDOf(register.ApprovalBatch{Root: root})
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
