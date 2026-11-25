// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"errors"
	"strings"
	"testing"
)

// What an approver is shown is one hash, the approvals module's where it
// is part of the program, and Put holds every decision's approval to it
// and to nothing else, whatever the kind: a scope, a line of the statement,
// a control test and a starter as much as a risk. The record's own hash
// stands in only where no module said what an approver is shown, and once
// one has, an approval over the record's own hash is an approval of
// something nobody was shown.
func TestPutHoldsEveryApprovalToTheOneSurface(t *testing.T) {
	saved := surfaceOf
	defer func() { surfaceOf = saved }()
	surfaceOf = nil

	b := newBench(t)
	scope := Scope{Name: "group", Title: "The group", Domains: []Domain{"identity"}, Approval: signedBy(owner, lee.Subject)}
	scope.Approval.Surface = recordSurface(scope)
	if got := shown(t, b, scope); got != recordSurface(scope) {
		t.Fatalf("without the approvals module the surface is %s, and the record's own hash is %s", got, recordSurface(scope))
	}
	mustPut(t, b, dana, scope)

	// The module's surface names the record it is for, as the real one
	// does, so two records never share one.
	SurfaceWith(func(r *Register, rec Record, id ID) (Digest, error) {
		return probeDigest("shown "+string(rec.Kind()), int(id[0])), nil
	})
	if !SurfaceInstalled() {
		t.Fatal("a surface was installed and the register says none is")
	}
	sid := mustID(t, scope)
	recs := []Record{
		ControlTest{Control: mustID(t, control("AC-01")), Name: "weekly", Population: owner, Query: digest(7), Assertion: "all",
			Approval: signedBy(owner, lee.Subject)},
		Applicability{Requirement: owner, Scope: sid, Applicable: true, Justification: Text(digest(4)), Approval: signedBy(owner, lee.Subject)},
		Starter{Framework: "iso-27001", Version: "2022", Content: digest(3), Requirements: 1, Installed: true,
			Approval: signedBy(owner, lee.Subject)},
		Risk{Ref: "R-1", Title: "Supplier outage", Owner: owner, Raised: owner, Likelihood: 2, Impact: 2, Status: "accepted",
			Approval: signedBy(owner, lee.Subject)},
	}
	for _, rec := range recs {
		own := ApprovalOf(rec)
		own.Surface = recordSurface(rec)
		if _, err := b.Put(dana, "a test's write", rec); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not what is being written") {
			t.Errorf("a %s approved over its own fields' hash, which nobody was shown, was answered %v", rec.Kind(), err)
		}
		want, err := b.Surface(rec, mustID(t, rec))
		if err != nil {
			t.Fatal(err)
		}
		own.Surface = want
		if _, err := b.Put(dana, "a test's write", rec); err != nil {
			t.Errorf("a %s approved over what its approver was shown was refused: %v", rec.Kind(), err)
		}
	}
	// What the register holds, written again unchanged, writes nothing and
	// is not held to a surface it no longer shows.
	if rc, err := b.Put(dana, "a test's write", recs...); err != nil || rc.Commit != "" {
		t.Errorf("writing the decisions again unchanged was answered %+v, %v", rc, err)
	}
}
