// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"strings"
	"time"
)

// Progressive autonomy, earned.
//
// A declaration may say an agent earns its way out of asking: after
// earn_after approvals in a row of the same kind of action, with nothing
// declined in between, that kind of action stops waiting for a person, as
// long as the agent's evaluations still earn it its autonomy. A decline
// drops that kind of action back to asking; the reviewer refusing an
// action, or the exfiltration breaker stopping one, drops every kind the
// agent had earned, because either is the sign something is wrong.
//
// Only what reads, acts or writes a draft can be earned. Sending, paying,
// deleting, publishing, signing in and answering a decider's question ask
// every time, and the exfiltration breaker is never earned away: it is
// about what the run holds, not about the agent's record.

// Bounds on earn_after: below the minimum a lucky streak is a record, and
// above the maximum it is never reached and only reads as a promise.
const (
	MinEarnAfter = 3
	MaxEarnAfter = 100
)

// EarnClass is the kind of action an approval counts towards: what is
// done, and to what. A press is classed by the element and the host its
// reason names, a write by its page or path, a command by its program, and
// a tool by its name.
func EarnClass(a Action, why string) string {
	str := func(k string) string { v, _ := a.Input[k].(string); return strings.TrimSpace(v) }
	switch {
	case a.Tool != "":
		return "tool " + a.Tool
	case a.Delegate != "":
		return "delegate " + a.Delegate
	}
	switch a.Op {
	case "write_page", "read_page":
		return a.Op + " " + firstOf(str("page"), str("path"))
	case "file_write", "file_read":
		return a.Op + " " + str("path")
	case "shell_run":
		prog := ""
		if argv, ok := a.Input["argv"].([]any); ok && len(argv) > 0 {
			prog, _ = argv[0].(string)
		}
		return a.Op + " " + firstOf(prog, str("program"))
	case "browser_click", "browser_choose", "desktop_press", "desktop_key":
		// The reason names the element and where it is: "it presses link
		// \"Next\" on shop.example.com, and ...".
		target, _, _ := strings.Cut(why, ", and ")
		return a.Op + " " + strings.TrimSpace(target)
	}
	return a.Op
}

func firstOf(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// Earnable says whether a hold of this action may ever be earned away.
func Earnable(a Action, why, kind string, writes bool) bool {
	if kind != WaitAsk || a.Op == "browser_sign_in" {
		return false
	}
	switch CommitOf(a, why, kind, writes) {
	case "reads", "acts", "writes":
		return true
	}
	return false
}

// EarnRecord is one kind of action's record of approvals.
type EarnRecord struct {
	Class string `json:"class"`
	// Approvals is how many in a row, since it last dropped.
	Approvals int `json:"approvals"`
	// Earned is when it stopped asking, zero while it still asks.
	Earned time.Time `json:"earned,omitzero"`
	// Dropped is when it last went back to asking, and Why for what.
	Dropped time.Time `json:"dropped,omitzero"`
	Why     string    `json:"why,omitempty"`
	// Last is who approved it last.
	Last string `json:"last,omitempty"`
}

// Track is an agent's record, by kind of action.
type Track struct {
	Agent   string                 `json:"agent"`
	Classes map[string]*EarnRecord `json:"classes"`
}

func (t *Track) record(class string) *EarnRecord {
	if t.Classes == nil {
		t.Classes = map[string]*EarnRecord{}
	}
	r := t.Classes[class]
	if r == nil {
		r = &EarnRecord{Class: class}
		t.Classes[class] = r
	}
	return r
}

// Approve counts an approval, and says whether it has just earned the
// kind of action its freedom from asking.
func (t *Track) Approve(class, by string, after int, now time.Time) bool {
	r := t.record(class)
	r.Approvals++
	r.Last = by
	if after > 0 && r.Approvals >= after && r.Earned.IsZero() {
		r.Earned = now
		return true
	}
	return false
}

// Decline sends one kind of action back to asking.
func (t *Track) Decline(class, by string, now time.Time) {
	r := t.record(class)
	r.Approvals, r.Earned, r.Dropped = 0, time.Time{}, now
	r.Why = by + " declined it"
}

// DropAll sends every kind of action back to asking, for a reason.
func (t *Track) DropAll(why string, now time.Time) []string {
	var dropped []string
	for _, r := range t.Classes {
		if !r.Earned.IsZero() || r.Approvals > 0 {
			dropped = append(dropped, r.Class)
		}
		r.Approvals, r.Earned, r.Dropped, r.Why = 0, time.Time{}, now, why
	}
	return dropped
}

// Earned says whether a kind of action runs without asking, and the line
// a step records when it does.
func (t *Track) Earned(class string) (string, bool) {
	r, ok := t.Classes[class]
	if !ok || r.Earned.IsZero() {
		return "", false
	}
	return fmt.Sprintf("ran without asking: %d approvals in a row earned it on %s",
		r.Approvals, r.Earned.UTC().Format("2 Jan 2006")), true
}
