// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"errors"
	"strings"
	"testing"

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
