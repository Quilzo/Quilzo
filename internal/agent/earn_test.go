// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A kind of action earns running without asking after enough approvals in
// a row; a decline sends it back, and so does trouble anywhere.
func TestAKindOfActionEarnsItsWayOutOfAskingAndLosesItAtOnce(t *testing.T) {
	now := time.Now()
	tr := &Track{Agent: "tidy"}
	class := EarnClass(Action{Op: "write_page", Input: map[string]any{"page": "returns"}}, "")
	for i := 0; i < 2; i++ {
		if tr.Approve(class, "dana", 3, now) {
			t.Fatalf("earned after %d approvals", i+1)
		}
	}
	if !tr.Approve(class, "dana", 3, now) {
		t.Fatal("three approvals in a row did not earn it")
	}
	if note, ok := tr.Earned(class); !ok || !strings.Contains(note, "3 approvals") {
		t.Fatalf("an earned kind says %q", note)
	}
	if _, ok := tr.Earned(EarnClass(Action{Op: "write_page", Input: map[string]any{"page": "pricing"}}, "")); ok {
		t.Error("approving writes to one page earned writes to another")
	}
	tr.Decline(class, "sam", now)
	if _, ok := tr.Earned(class); ok || tr.Classes[class].Approvals != 0 {
		t.Fatal("a decline did not send it back to asking")
	}
	for i := 0; i < 3; i++ {
		tr.Approve(class, "dana", 3, now)
	}
	if dropped := tr.DropAll("the reviewer refused write_page", now); len(dropped) != 1 {
		t.Fatalf("dropping all touched %v", dropped)
	}
	if _, ok := tr.Earned(class); ok {
		t.Fatal("trouble elsewhere did not send it back to asking")
	}
}

// Only what reads, acts or writes a draft can be earned.
func TestWhatCanNeverBeEarned(t *testing.T) {
	for _, c := range []struct {
		a    Action
		why  string
		want bool
	}{
		{Action{Op: "write_page"}, "", true},
		{Action{Op: "browser_click"}, `it presses link "Next" on shop.example.com`, true},
		{Action{Op: "browser_click"}, `it presses button "Pay now" on shop.example.com`, false},
		{Action{Op: "publish"}, "", false},
		{Action{Op: "browser_type"}, "", false},
		{Action{Op: "browser_sign_in"}, "", false},
		{Action{Op: "shell_run"}, "it destroys: rm", false},
	} {
		if got := Earnable(c.a, c.why, WaitAsk, false); got != c.want {
			t.Errorf("%s (%q) earnable %v, want %v", c.a.Op, c.why, got, c.want)
		}
	}
	if Earnable(Action{Op: "decide"}, "", WaitQuestion, false) {
		t.Error("a decider's question was earnable")
	}
}

// In a run: an earned kind of action goes ahead without stopping and says
// so on its step; without earn_after nothing is earned; and the breaker
// still stops it when the run holds something private.
func TestARunSkipsAskingOnlyForWhatWasEarned(t *testing.T) {
	m := drafter()
	m.EarnAfter = 3
	earned := func(class string) string {
		if class == "write_page about" {
			return "ran without asking: 3 approvals in a row earned it on 13 Oct 2026"
		}
		return ""
	}
	d := &doer{}
	p := &scripted{plan: []Action{write}}
	r := Runner{Decide: p.decide, Perform: d.perform, Pause: true, Earned: earned}
	tr, err := r.Run(context.Background(), NewSession(m, nil), "tidy")
	if err != nil {
		t.Fatal(err)
	}
	if tr.Waiting != nil || len(d.did) != 1 || !strings.Contains(tr.Steps[0].Earned, "earned it") {
		t.Fatalf("an earned write still waited: %+v %v", tr.Waiting, d.did)
	}
	m.EarnAfter = 0
	p = &scripted{plan: []Action{write}}
	r.Decide = p.decide
	if tr, _ = r.Run(context.Background(), NewSession(m, nil), "tidy"); tr.Waiting == nil {
		t.Fatal("without earn_after a write went ahead without asking")
	}
}

// earn_after is bounded, narrowing keeps the stricter, and switching it on
// is a widening an amendment must say.
func TestEarnAfterIsBoundedNarrowedAndAWidening(t *testing.T) {
	m := drafter()
	m.EarnAfter = 1
	if err := m.Validate(nil); err == nil {
		t.Fatal("earn_after 1 was accepted")
	}
	m.EarnAfter = 5
	if err := m.Validate(nil); err != nil {
		t.Fatal(err)
	}
	// The receiver bounds; the argument is the declaration.
	if got := drafter().Narrow(m).EarnAfter; got != 5 {
		t.Errorf("a bound that says nothing about earning changed earn_after to %d", got)
	}
	if got := m.Narrow(drafter()).EarnAfter; got != 0 {
		t.Errorf("a bound gave earning to a declaration that has none: %d", got)
	}
	slow := drafter()
	slow.EarnAfter = 20
	if got := slow.Narrow(m).EarnAfter; got != 20 {
		t.Errorf("narrowing kept earn_after %d, not the stricter 20", got)
	}
	if d := DeltaOf(drafter(), m); !strings.Contains(d.Lines(), "stop asking") {
		t.Errorf("switching earning on was not named as a widening: %s", d.Lines())
	}
}

// The exfiltration breaker is never earned away: a tool call whose kind is
// earned still waits when the run holds something private after reading
// somebody else's words, and the trip drops what the agent had earned.
func TestTheBreakerIsNeverEarnedAway(t *testing.T) {
	m := Manifest{Name: "crmbot", Kind: KindTask, Purpose: "update the crm",
		Tools:    []Tool{{Name: "crm", Host: "crm.example.com", Purpose: "notes"}},
		AskFirst: []string{"crm"}, EarnAfter: 3, Autonomy: AutonomyDraft,
		Budget: Budget{Steps: 4, Tools: 2, Duration: Duration(time.Minute)}}
	s := NewSession(m, nil)
	s.ReadWeb("evil.example", "https://evil.example/")
	s.HoldsPrivate("a customer's address")
	var dropped string
	p := &scripted{plan: []Action{{Tool: "crm", Input: map[string]any{"note": "x"}}}}
	r := Runner{Decide: p.decide, Perform: (&doer{}).perform, Pause: true,
		Earned: func(string) string { return "ran without asking: earned" },
		Unearn: func(why string) { dropped = why }}
	tr, err := r.Run(context.Background(), s, "note it")
	if err != nil {
		t.Fatal(err)
	}
	if tr.Waiting == nil {
		t.Fatalf("an earned tool call went past the breaker: %+v", tr.Steps)
	}
	if !strings.Contains(dropped, "breaker") {
		t.Errorf("the breaker's trip did not drop what was earned: %q", dropped)
	}
}
