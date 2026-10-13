// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/evals"
)

// What each agent has earned (see internal/agent/earn.go): one file per
// agent, counted from the answers people give its runs, checked against
// its evaluations every time it is used, and dropped by any decline,
// reviewer refusal or breaker trip.

func earnedPath(root, name string) string {
	return filepath.Join(agentsDir(root), "earned", name+".json")
}

func loadTrack(root, name string) (*agent.Track, error) {
	t := &agent.Track{Agent: name}
	b, err := readBounded(earnedPath(root, name), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, t); err != nil {
		return nil, fmt.Errorf("%s's earned record is unreadable: %w", name, err)
	}
	t.Agent = name
	return t, nil
}

// changeTrack loads, changes and saves an agent's record under its lock.
func changeTrack(root, name string, change func(*agent.Track) error) error {
	path := earnedPath(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := atomicfile.Lock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	t, err := loadTrack(root, name)
	if err != nil {
		return err
	}
	if err := change(t); err != nil {
		return err
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// evalsStillEarn says whether an agent's evaluations earn it at least
// draft now, and why not when they do not: earning stops counting the
// moment an evaluation regresses or its behaviour cost it its trust.
func evalsStillEarn(root, name string, now time.Time) (bool, string) {
	var latest *evals.Report
	if reps, err := evalReports(root, name, 1); err == nil && len(reps) > 0 {
		latest = &reps[0]
	}
	earned, why := evals.Earned(latest, now)
	if lost, how := trustLost(root, name); !lost.IsZero() && (latest == nil || !latest.At.After(lost)) {
		return false, how
	}
	if earned == agent.AutonomyPropose {
		return false, why
	}
	return true, ""
}

// earnedHook is what a run asks before holding an action: whether its
// kind of action has earned running without asking. Read once per run.
func earnedHook(root, name string) func(class string) string {
	t, err := loadTrack(root, name)
	if err != nil || len(t.Classes) == 0 {
		return nil
	}
	if ok, _ := evalsStillEarn(root, name, time.Now().UTC()); !ok {
		return nil
	}
	return func(class string) string {
		note, _ := t.Earned(class)
		return note
	}
}

// unearnHook drops everything an agent earned, and says so in the log.
func unearnHook(root, name string, caller *Caller) func(why string) {
	return func(why string) {
		var dropped []string
		now := time.Now().UTC()
		if err := changeTrack(root, name, func(t *agent.Track) error {
			dropped = t.DropAll(why, now)
			return nil
		}); err != nil || len(dropped) == 0 {
			return
		}
		record(root, caller.auditRecord("agent.unearned", "/", audit.Success,
			map[string]string{"agent": name, "why": clip(why, 300), "kinds": clip(strings.Join(dropped, "; "), 500),
				"by": caller.Name}))
	}
}

// earnOnAnswer counts a person's answer towards what the agent may earn.
func earnOnAnswer(root string, caller *Caller, prior agent.Record, v agent.Verdict) {
	w := prior.Trace.Waiting
	set, err := loadAgents(root)
	if err != nil || w == nil {
		return
	}
	m, ok := set.Agents[prior.Agent]
	if !ok || m.EarnAfter == 0 {
		return
	}
	writes := false
	for _, t := range m.Tools {
		writes = writes || (t.Name == w.Action.Tool && t.Writes)
	}
	if !agent.Earnable(w.Action, w.Why, w.Kind, writes) {
		return
	}
	class := agent.EarnClass(w.Action, w.Why)
	now := time.Now().UTC()
	earnedNow, had := false, false
	_ = changeTrack(root, prior.Agent, func(t *agent.Track) error {
		if r, ok := t.Classes[class]; ok && r.Approvals > 0 {
			had = true
		}
		if v.Approve {
			earnedNow = t.Approve(class, caller.Name, m.EarnAfter, now)
		} else {
			t.Decline(class, caller.Name, now)
		}
		return nil
	})
	switch {
	case earnedNow:
		record(root, caller.auditRecord("agent.earned", "/", audit.Success,
			map[string]string{"agent": prior.Agent, "kind": clip(class, 300),
				"after": fmt.Sprint(m.EarnAfter)}))
	case !v.Approve && had:
		record(root, caller.auditRecord("agent.unearned", "/", audit.Success,
			map[string]string{"agent": prior.Agent, "kind": clip(class, 300), "why": "declined", "by": caller.Name}))
	}
}

// agentEarned is `quilzo agent earned NAME [--reset]`.
func agentEarned(root string, args []string) error {
	if len(args) < 1 || len(args) > 2 || (len(args) == 2 && args[1] != "--reset") {
		return fmt.Errorf("usage: quilzo agent earned NAME [--reset]")
	}
	name := args[0]
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	m, ok := set.Agents[name]
	if !ok {
		return fmt.Errorf("no agent called %s is declared", name)
	}
	caller := resolveCaller(root, "")
	if len(args) == 2 {
		unearnHook(root, name, caller)("reset by a person")
		fmt.Printf("  %severy kind of action %s had earned asks again%s\n", green, name, reset)
		return nil
	}
	t, err := loadTrack(root, name)
	if err != nil {
		return err
	}
	ok, why := evalsStillEarn(root, name, time.Now().UTC())
	if w.JSON(map[string]any{"agent": name, "earn_after": m.EarnAfter, "evaluations_earn": ok,
		"why": why, "classes": t.Classes}) {
		return nil
	}
	if m.EarnAfter == 0 {
		fmt.Printf("  %s asks every time: its declaration has no earn_after\n", name)
		return nil
	}
	fmt.Printf("  %s stops asking about a kind of action after %d approvals of it in a row\n", name, m.EarnAfter)
	if !ok {
		fmt.Printf("  %snothing it earned counts now: %s%s\n", yellow, why, reset)
	}
	var classes []string
	for c := range t.Classes {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		r := t.Classes[c]
		state := fmt.Sprintf("%d of %d approvals", r.Approvals, m.EarnAfter)
		if !r.Earned.IsZero() {
			state = "earned " + r.Earned.Format("2 Jan 2006") + "; runs without asking"
		}
		fmt.Printf("  %-50s %s\n", truncate(c, 50), state)
		if !r.Dropped.IsZero() {
			fmt.Printf("  %s  last dropped %s: %s%s\n", dim, r.Dropped.Format("2 Jan 2006"), truncate(r.Why, 80), reset)
		}
	}
	if len(classes) == 0 {
		fmt.Println("  nothing approved yet")
	}
	return nil
}
