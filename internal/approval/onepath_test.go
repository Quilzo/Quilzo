// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// Every decision the programme makes is approved here, over the one
// surface: the hash an approver is shown (Ask) is the hash the register
// holds the record to at Put (Register.Surface), the hash their passkey
// signed, and the hash in the receipt and the audit entry. A starter, a
// scope, a line of the statement and a control test are each approved by
// somebody other than whoever raised it, and each is written.
//
// The module's surface and the register's own hash of a record's fields
// were two hashes of one decision, and every decision the module approved
// was refused by the kind's own check.
func TestEveryProgrammeDecisionIsApprovedOverTheOneSurface(t *testing.T) {
	b := newBench(t, holds("lee", auth.ActApprove), holds("dana", auth.ActApprove))
	if !register.SurfaceInstalled() {
		t.Fatal("the approvals module is in the program and the register holds approvals to another surface")
	}
	starter := register.Starter{Framework: "iso-27001", Version: "2022", Content: register.Digest("sha256:" + strings.Repeat("ab", 32)),
		Requirements: 1, Installed: true}
	scope := register.Scope{Name: "group", Title: "The group", Domains: []register.Domain{"identity"}}
	sid, _ := register.IDOf(scope)
	line := register.Applicability{Requirement: "a0000000000000000000000000000001", Scope: sid, Applicable: true,
		Justification: register.Text("sha256:" + strings.Repeat("cd", 32))}
	test := register.ControlTest{Control: "a0000000000000000000000000000002", Name: "weekly", Population: "a0000000000000000000000000000003",
		Query: register.Digest("sha256:" + strings.Repeat("ef", 32)), Assertion: "all"}

	for _, rec := range []register.Record{starter, scope, line, test} {
		id := b.propose("dana", rec)
		a, err := b.m.Ask(id)
		if err != nil {
			t.Fatalf("a waiting %s is not asked of its approvers: %v", rec.Kind(), err)
		}
		held, err := b.reg.Surface(rec, id)
		if err != nil || held != a.Hash {
			t.Fatalf("the %s is shown as %s and the register holds it to %s (%v)", rec.Kind(), a.Hash, held, err)
		}
		if _, err := b.sign("dana", id); !errors.Is(err, ErrRefused) {
			t.Errorf("the person who raised the %s approved it: %v", rec.Kind(), err)
		}
		out, err := b.sign("lee", id)
		if err != nil || !out.Done {
			t.Fatalf("the %s approved by somebody else was not written: %+v %v", rec.Kind(), out, err)
		}
		if out.Surface != a.Hash || len(out.Receipt.Approved) != 1 || out.Receipt.Approved[0] != a.Hash {
			t.Errorf("the %s's receipt carries %v, and its approver was shown %s", rec.Kind(), out.Receipt.Approved, a.Hash)
		}
		e, err := b.reg.Get(id)
		if err != nil || register.ApprovalOf(e.Record).Surface != a.Hash {
			t.Errorf("the %s held is %+v (%v)", rec.Kind(), e.Record, err)
		}
	}
	found := false
	for _, r := range b.log {
		if r.Action == register.AuditAction && strings.Contains(r.Detail["kinds"], "starter") {
			found = true
		}
	}
	if !found {
		t.Error("the starter's write is not in the audit log")
	}
}

// A person's erasure is decided through the engine, as every decision is:
// entered by one person on the request of the person to be erased, it is
// refused to whoever entered it and to the person asking while anybody
// else may decide it, and decided by somebody else, with a passkey bound to
// what it shows, it erases them. The decider is named by pseudonym alone,
// and the record's approval is the engine's, under the erasure rule. A
// team of one decides it alone, marked so, with a review owed.
func TestAnErasureIsDecidedThroughTheEngine(t *testing.T) {
	b := newBench(t, holds("lee", auth.ActApprove), holds("dana", auth.ActApprove), holds("ada@example.com", auth.ActApprove))
	ada := b.subject("ada@example.com")
	allow := func(auth.Action, string) error { return nil }
	dana := register.Actor{Name: "dana", Subject: b.subject("dana"), Kind: audit.KindHuman, Verified: true, May: allow}
	if _, err := b.reg.PutText(dana, register.KindRisk, "Ada raised this after the review.", ada); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.reg.RaiseErasure(dana, register.ErasureRequest{Subject: ada, Basis: "request", RequestedBy: ada}); err != nil {
		t.Fatal(err)
	}
	id := register.ErasureID(ada)
	for _, who := range []string{"dana", "ada@example.com"} {
		if _, err := b.sign(who, id); !errors.Is(err, ErrRefused) {
			t.Errorf("%s, who asked for or entered the erasure, decided it: %v", who, err)
		}
	}
	if st := b.reg.SubjectState(ada); st.State != register.SubjectHeld {
		t.Fatalf("a refused decision erased the person: %+v", st)
	}
	out, err := b.sign("lee", id)
	if err != nil || !out.Done {
		t.Fatalf("lee deciding the erasure: %+v %v", out, err)
	}
	if st := b.reg.SubjectState(ada); st.State != register.SubjectErased {
		t.Errorf("the erasure lee decided left the person as %+v", st)
	}
	e, err := b.reg.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	rec := e.Record.(register.Erasure)
	if rec.Decider != b.subject("lee") || rec.Approval.Rule != "erasure" || rec.Approval.Raised != ada ||
		rec.EnteredBy != dana.Subject || rec.Approval.Signers[0].Method != "passkey" || rec.Approval.Surface != out.Surface {
		t.Errorf("the erasure is %+v with %+v", rec, rec.Approval)
	}
	if err := Verify(b.reg, rec, id, rec.Approval); err != nil {
		t.Errorf("the erasure's approval does not check again: %v", err)
	}

	// A team of one.
	one := newBench(t, holds("dana", auth.ActApprove))
	kim := one.subject("kim@example.com")
	solo := register.Actor{Name: "dana", Subject: one.subject("dana"), Kind: audit.KindHuman, Verified: true, May: allow}
	if _, _, err := one.reg.RaiseErasure(solo, register.ErasureRequest{Subject: kim, Basis: "request", RequestedBy: kim}); err != nil {
		t.Fatal(err)
	}
	out, err = one.sign("dana", register.ErasureID(kim))
	if err != nil || !out.Done || !out.Alone {
		t.Fatalf("the only person eligible deciding an erasure: %+v %v", out, err)
	}
	e, _ = one.reg.Get(register.ErasureID(kim))
	if a := e.Record.(register.Erasure).Approval; !a.Alone || a.ReviewDue == 0 {
		t.Errorf("an erasure decided alone is not marked so: %+v", a)
	}
}
