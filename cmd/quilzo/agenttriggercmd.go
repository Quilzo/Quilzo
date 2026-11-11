// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/event"
)

// agentTriggerCmd lists, adds and removes what starts an agent on its own.
//
//	quilzo agent trigger NAME
//	quilzo agent trigger NAME add --on page.published --where /blog --goal "..."
//	quilzo agent trigger NAME add --every 24h --at 07:30 --zone Europe/London --goal "..."
//	quilzo agent trigger NAME remove N
//	quilzo agent trigger events
func agentTriggerCmd(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quilzo agent trigger NAME [add|remove N], or quilzo agent trigger events")
	}
	if args[0] == "events" {
		return agentTriggerEvents()
	}
	name, rest := args[0], args[1:]
	if len(rest) == 0 || rest[0] == "list" {
		return agentTriggerList(root, name)
	}
	switch rest[0] {
	case "add":
		return agentTriggerAdd(root, name, rest[1:])
	case "remove":
		return agentTriggerRemove(root, name, rest[1:])
	}
	return fmt.Errorf("unknown trigger command %q; try add, remove or list", rest[0])
}

func agentTriggerEvents() error {
	if w.JSON(event.Types()) {
		return nil
	}
	w.Human("what can start an agent:\n")
	for _, t := range event.Types() {
		w.Human("  %-20s when %s\n", t, event.Describe(t))
	}
	w.Human("  %-20s at times: --every 24h, and --at 07:30 --zone Europe/London\n", agent.OnSchedule)
	return nil
}

func agentTriggerAdd(root, name string, args []string) error {
	fs := flag.NewFlagSet("trigger add", flag.ContinueOnError)
	on := fs.String("on", "", "an event (quilzo agent trigger events), by its name or a webhook's (published), or schedule with --every")
	where := fs.String("where", "", "a page path, collection, form, chatbot or service the event is about")
	every := fs.Duration("every", 0, "how often a schedule repeats (15m at least)")
	at := fs.String("at", "", "a schedule's time of day, 07:30")
	zone := fs.String("zone", "", "the time zone of --at, Europe/London (UTC when not given)")
	goal := fs.String("goal", "", "what each run is to do")
	perDay := fs.Int("per-day", 0, fmt.Sprintf("the most runs it starts in a day (%d when not given)", agent.DefaultPerDay))
	if err := fs.Parse(args); err != nil {
		return err
	}
	t := agent.Trigger{On: *on, Where: *where, Every: agent.Duration(*every), At: *at, Zone: *zone,
		Goal: *goal, PerDay: *perDay}
	if t.On == "" && *every > 0 {
		t.On = agent.OnSchedule
	}
	if err := t.Validate(); err != nil {
		return errBlocked{err}
	}
	caller := resolveCaller(root, flagToken)
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	m, ok := set.Agents[name]
	if !ok {
		return fmt.Errorf("no agent called %q; `quilzo agent list`", name)
	}
	m.Triggers = append(append([]agent.Trigger(nil), m.Triggers...), t)
	if err := declareAgent(root, m, false, true, caller); err != nil {
		return errBlocked{err}
	}
	if w.JSON(t) {
		return nil
	}
	w.Human("%s now starts on its own %s\n", name, t.Describe())
	who := "its sponsor"
	if id := set.identityOf(name); id != nil && id.Sponsor != "" {
		who = id.Sponsor
	}
	w.Human("  %seach run is %s's, checked when it starts, and drafts and proposes at most; "+
		"%d runs a day at the most%s\n", dim, who, t.PerDayOrDefault(), reset)
	if m, _ := agentRunModel(root, name); m == nil {
		w.Human("  %sit has no model to decide with yet, so nothing starts until one is set up "+
			"(quilzo gateway)%s\n", yellow, reset)
	}
	if !mustConfig(root).Bool("agents.triggers") {
		w.Human("  %sagents.triggers is off on this store, so nothing starts on its own until it is on%s\n",
			yellow, reset)
	}
	return nil
}

func agentTriggerRemove(root, name string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo agent trigger %s remove N (the number in the list)", name)
	}
	n, err := strconv.Atoi(args[0])
	set, lerr := loadAgents(root)
	if lerr != nil {
		return lerr
	}
	m, ok := set.Agents[name]
	if !ok {
		return fmt.Errorf("no agent called %q; `quilzo agent list`", name)
	}
	if err != nil || n < 1 || n > len(m.Triggers) {
		return fmt.Errorf("%q is not one of %s's triggers, numbered 1 to %d", args[0], name, len(m.Triggers))
	}
	gone := m.Triggers[n-1]
	m.Triggers = append(append([]agent.Trigger(nil), m.Triggers[:n-1]...), m.Triggers[n:]...)
	if err := declareAgent(root, m, false, false, resolveCaller(root, flagToken)); err != nil {
		return errBlocked{err}
	}
	w.Human("%s no longer starts on its own %s\n", name, gone.Describe())
	return nil
}

// triggerView is one trigger as the list shows it.
type triggerView struct {
	N       int           `json:"n"`
	Trigger agent.Trigger `json:"trigger"`
	Means   string        `json:"means"`
	Today   int           `json:"today"`
	Last    time.Time     `json:"last,omitzero"`
	Next    time.Time     `json:"next,omitzero"`
}

func triggerViews(root, name string, m agent.Manifest, now time.Time) []triggerView {
	var st triggerState
	if err := loadJSON(triggerStatePath(root), &st); err != nil && !errors.Is(err, os.ErrNotExist) {
		st = triggerState{}
	}
	views := make([]triggerView, 0, len(m.Triggers))
	for i, t := range m.Triggers {
		v := triggerView{N: i + 1, Trigger: t, Means: t.Describe()}
		if f := st.Fired[firedKey(name, t)]; f != nil {
			if f.Day == now.UTC().Format("2006-01-02") {
				v.Today = f.Count
			}
			v.Last, v.Next = f.Last, f.Next
		}
		views = append(views, v)
	}
	return views
}

func agentTriggerList(root, name string) error {
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	m, ok := set.Agents[name]
	if !ok {
		return fmt.Errorf("no agent called %q; `quilzo agent list`", name)
	}
	views := triggerViews(root, name, m, time.Now())
	if w.JSON(views) {
		return nil
	}
	if len(views) == 0 {
		w.Human("%s starts only when somebody runs it\n", name)
		w.Human("  %squilzo agent trigger %s add --on page.published --goal \"...\"%s\n", dim, name, reset)
		return nil
	}
	for _, v := range views {
		w.Human("  %d  %s\n", v.N, v.Means)
		w.Human("     %s%s%s\n", dim, clip(strings.ReplaceAll(v.Trigger.Goal, "\n", " "), 100), reset)
		line := fmt.Sprintf("%d of %d runs today", v.Today, v.Trigger.PerDayOrDefault())
		if !v.Last.IsZero() {
			line += ", last " + v.Last.UTC().Format("15:04 on 2 Jan")
		}
		if !v.Next.IsZero() {
			line += ", next " + v.Next.UTC().Format("15:04 on 2 Jan") + " UTC"
		}
		w.Human("     %s%s%s\n", dim, line, reset)
	}
	return nil
}
