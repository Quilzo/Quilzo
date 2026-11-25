// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"errors"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// A decision is proposed without an approval, because a proposal is what a
// person is asked to approve; one a proposer sends is not kept. Accepted
// with the records that follow from it, the decision and those records are
// one commit.
func TestADecisionWaitsWithoutAnApprovalAndIsAcceptedWithWhatItBrings(t *testing.T) {
	b := newBench(t)
	starter := Starter{Framework: "iso-27001", Version: "2022", Content: digest(3), Requirements: 1, Installed: true}
	if _, err := b.Propose(dana, "install the iso-27001 starter", starter); err != nil {
		t.Fatalf("a decision with no approval could not be proposed: %v", err)
	}
	sent := starter
	sent.Framework = "nis2"
	sent.Approval = signedBy(dana.Subject, dana.Subject)
	if _, err := b.Propose(model, "install the nis2 starter", sent); err != nil {
		t.Fatalf("a decision proposed with an approval was refused: %v", err)
	}
	waiting, err := b.Proposals()
	if err != nil || len(waiting) != 2 {
		t.Fatalf("%d proposals wait (%v)", len(waiting), err)
	}
	for _, p := range waiting {
		if p.Record.(Starter).Approval != nil {
			t.Errorf("the proposal %s keeps the approval its proposer sent", p.ID)
		}
	}

	req := Requirement{Framework: "iso-27001", Ref: "A.5.1", Title: "Security policies are written and kept"}
	id := mustID(t, starter)
	a := signedBy(dana.Subject, lee.Subject)
	a.Surface = shown(t, b, starter)
	rc, err := b.AcceptWith(lee, id, a, req)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Commit == "" || len(rc.Written) != 2 {
		t.Fatalf("accepting the starter with its requirement wrote %+v", rc.Written)
	}
	if _, err := b.Get(mustID(t, req)); err != nil {
		t.Errorf("the requirement the decision brought is not in the register: %v", err)
	}
	if left, _ := b.Proposals(); len(left) != 1 {
		t.Errorf("%d proposals wait after one of two was accepted", len(left))
	}
	// What follows is written with the accepter's own permissions.
	noEdit := lee
	noEdit.May = func(act auth.Action, resource string) error {
		if act == auth.ActEditDraft && resource == kinds[KindRequirement].Resource() {
			return deny(act, resource)
		}
		return nil
	}
	nis2 := sent
	nis2.Approval = nil
	b2 := signedBy(dana.Subject, lee.Subject)
	b2.Surface = shown(t, b, nis2)
	other := Requirement{Framework: "nis2", Ref: "Art. 21(2)(a)", Title: "Risk analysis and security policies"}
	if _, err := b.AcceptWith(noEdit, mustID(t, nis2), b2, other); !errors.Is(err, ErrRefused) {
		t.Errorf("an accepter who may not write requirements wrote one: %v", err)
	}
}
