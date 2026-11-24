// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"errors"
	"testing"
)

// The register at an old commit reads as it stood then, whatever was
// written since; a commit of the proposals ref is not the register.
func TestAViewReadsTheRegisterAsItStood(t *testing.T) {
	b := newBench(t)
	first := mustPut(t, b, dana, control("AC-01"))
	renamed := control("AC-01")
	renamed.Title = "Second factors everywhere"
	mustPut(t, b, dana, renamed, control("AC-02"))

	then, err := b.At(first.Commit)
	if err != nil {
		t.Fatal(err)
	}
	if then.Commit() != first.Commit {
		t.Errorf("the view reads %s, not %s", then.Commit(), first.Commit)
	}
	var titles []string
	if err := then.Each(KindControl, func(e Entry, fields map[string]any) error {
		titles = append(titles, fields["title"].(string))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(titles) != 1 || titles[0] != control("AC-01").Title {
		t.Errorf("the register at its first commit held %q", titles)
	}
	now, err := b.At("")
	if err != nil {
		t.Fatal(err)
	}
	if now.Commit() != b.Head() {
		t.Errorf("a view of the head reads %s, not %s", now.Commit(), b.Head())
	}
	e, err := now.Get(mustID(t, renamed))
	if err != nil || e.Record.(Control).Title != renamed.Title {
		t.Errorf("the head's AC-01 is %+v, %v", e.Record, err)
	}

	prop, err := b.Propose(model, "drafted", control("AC-03"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.At(prop.Commit); !errors.Is(err, ErrNotFound) {
		t.Errorf("a commit of the proposals ref was read as the register: %v", err)
	}
	if _, err := b.At("0000000000000000000000000000000000000000000000000000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a commit nobody made was read: %v", err)
	}
}

// A changed test carries an approval of itself, or it is refused.
func TestAControlTestsApprovalIsOfThatTest(t *testing.T) {
	b := newBench(t)
	test := ControlTest{Control: mustID(t, control("AC-01")), Name: "weekly", Population: owner,
		Query: digest(7), Assertion: "all"}
	a := signedBy(owner, "a0000000000000000000000000000009")
	a.Surface = SurfaceOf(test)
	test.Approval = a
	mustPut(t, b, dana, test)

	changed := test
	changed.Query = digest(8)
	if _, err := b.Put(dana, "a test's write", changed); !errors.Is(err, ErrInvalid) {
		t.Errorf("a test whose query changed under its old approval was answered %v", err)
	}
	again := *a
	again.Surface = SurfaceOf(changed)
	changed.Approval = &again
	mustPut(t, b, dana, changed)
	if SurfaceOf(changed) == SurfaceOf(test) {
		t.Error("two tests with different queries have one surface")
	}
}
