// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A run that cannot be paused, a program's, waits in its own process for a
// person instead of refusing what asks first: the record carries the
// question, marked live, and an approval performs exactly that action.
func TestARunThatCannotPauseWaitsForAPerson(t *testing.T) {
	p := &scripted{plan: []Action{{Op: "read_page"}, write}}
	d := &doer{}
	var kept []Trace
	var asked Pending
	beats := 0
	r := Runner{Decide: p.decide, Perform: d.perform,
		Checkpoint: func(t Trace) { kept = append(kept, t) },
		Hold: func(_ context.Context, w Pending, beat func()) (Verdict, error) {
			asked = w
			beat()
			beats++
			return Verdict{N: w.N, Approve: true, By: "dana"}, nil
		}}
	tr, err := r.Run(context.Background(), NewSession(drafter(), nil), "tidy the about page")
	if err != nil {
		t.Fatal(err)
	}
	if asked.Action.Op != "write_page" || !asked.Live || asked.N != 2 {
		t.Fatalf("the person was asked %+v", asked)
	}
	if len(d.did) != 2 || d.did[1] != "write_page about" {
		t.Fatalf("did %v, want the approved write", d.did)
	}
	if tr.Waiting != nil || !tr.Complete {
		t.Errorf("the run ended waiting=%v complete=%v", tr.Waiting, tr.Complete)
	}
	live := false
	for _, k := range kept {
		if k.Waiting != nil && k.Waiting.Live && k.Waiting.N == 2 {
			live = true
		}
	}
	if !live || beats != 1 {
		t.Errorf("the record never carried the live question (beats %d)", beats)
	}
}

// Declining, or nobody deciding in time, refuses the action and tells the
// program why; nothing is done.
func TestAHeldActionIsRefusedWhenDeclinedOrUndecided(t *testing.T) {
	for name, tc := range map[string]struct {
		v    Verdict
		err  error
		want string
	}{
		"declined":   {v: Verdict{Approve: false, By: "dana"}, want: "dana declined this"},
		"undecided":  {err: errors.New("nobody decided within 10m0s"), want: "(nobody decided within 10m0s)"},
		"wrong step": {v: Verdict{N: 7, Approve: true}, want: "answer was for step 7"},
	} {
		p := &scripted{plan: []Action{write}}
		d := &doer{}
		r := Runner{Decide: p.decide, Perform: d.perform,
			Hold: func(_ context.Context, w Pending, _ func()) (Verdict, error) {
				v := tc.v
				if v.N == 0 {
					v.N = w.N
				}
				return v, tc.err
			}}
		tr, err := r.Run(context.Background(), NewSession(drafter(), nil), "tidy")
		if err != nil {
			t.Fatal(err)
		}
		if len(d.did) != 0 {
			t.Errorf("%s: did %v", name, d.did)
		}
		if len(tr.Steps) == 0 || !strings.Contains(tr.Steps[0].Why, tc.want) {
			t.Errorf("%s: refused with %+v, want %q", name, tr.Steps, tc.want)
		}
		if len(p.shown) < 2 || !strings.Contains(p.shown[1][0].Body, tc.want) || !p.shown[1][0].Trusted {
			t.Errorf("%s: the program was not told why", name)
		}
	}
}

// An approval does not skip the gate: a capability withdrawn while the run
// waited is still refused.
func TestAHeldApprovalStillGoesThroughTheGate(t *testing.T) {
	p := &scripted{plan: []Action{write}}
	d := &doer{}
	s := NewSession(drafter(), nil)
	r := Runner{Decide: p.decide, Perform: d.perform,
		Hold: func(_ context.Context, w Pending, _ func()) (Verdict, error) {
			s.mu.Lock()
			delete(s.capabilities, "write_page")
			s.mu.Unlock()
			return Verdict{N: w.N, Approve: true}, nil
		}}
	if _, err := r.Run(context.Background(), s, "tidy"); err != nil {
		t.Fatal(err)
	}
	if len(d.did) != 0 {
		t.Errorf("a withdrawn capability was performed after approval: %v", d.did)
	}
}

// An action the performer says commits to something waits for a person,
// even though the declaration does not ask about it.
func TestAnActionThatCommitsWaitsForAPerson(t *testing.T) {
	p := &scripted{plan: []Action{{Op: "read_page"}, {Op: "read_page", Input: map[string]any{"page": "pay"}}}}
	d := &doer{}
	var asked []Pending
	r := Runner{Decide: p.decide, Perform: d.perform,
		Weighs: func(a Action) string {
			if a.Input["page"] == "pay" {
				return `it is called "Pay now"`
			}
			return ""
		},
		Hold: func(_ context.Context, w Pending, _ func()) (Verdict, error) {
			asked = append(asked, w)
			return Verdict{N: w.N, Approve: false, By: "dana"}, nil
		}}
	tr, err := r.Run(context.Background(), NewSession(drafter(), nil), "pay the invoice")
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0].N != 2 || !strings.Contains(asked[0].Why, "Pay now") {
		t.Fatalf("asked %+v", asked)
	}
	if len(d.did) != 1 || !strings.Contains(tr.Steps[1].Why, "dana declined this") {
		t.Errorf("did %v, steps %+v", d.did, tr.Steps)
	}
}
