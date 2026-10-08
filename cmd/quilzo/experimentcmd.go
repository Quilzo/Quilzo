// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/experiment"
)

// A/B tests from the command line and for the admin. See internal/experiment.

func experimentsPath(root string) string { return filepath.Join(root, "experiments.json") }

func cmdExperiment(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return experimentList(root)
	case "add":
		return experimentAdd(root, args[1:])
	case "start", "stop", "remove":
		return experimentState(root, args[0], args[1:])
	case "report":
		return experimentReport(root, args[1:])
	}
	return fmt.Errorf("unknown experiment command %q; try list, add, start, stop, report or remove", args[0])
}

func experimentList(root string) error {
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	set, err := experiment.Load(experimentsPath(root))
	if err != nil {
		return err
	}
	if w.JSON(set.Experiments) {
		return nil
	}
	if len(set.Experiments) == 0 {
		w.Human("no experiments; declare one with quilzo experiment add NAME --page P --variant b=PAGE --goal G\n")
	}
	for _, e := range set.Experiments {
		state := "stopped"
		if e.Running {
			state = "running"
		}
		w.Human("%s%s%s  on /%s  %s, goal %s\n", bold, e.Name, reset, e.Page, state, e.Goal)
	}
	return nil
}

// changeExperiments edits the declarations. Each caller authorises publish
// on the pages the experiment touches, not on the whole site: it serves one
// page's content at another's address, and a grant or a deny scoped to either
// page has to bind.
func changeExperiments(root string, caller *Caller, change, name string,
	edit func(*experiment.Set) error) error {

	set, err := experiment.Load(experimentsPath(root))
	if err != nil {
		return err
	}
	if err := edit(set); err != nil {
		return err
	}
	if err := experiment.Save(experimentsPath(root), set); err != nil {
		return err
	}
	record(root, audit.Record{Action: "experiment." + change, Resource: "/experiment/" + name,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: map[string]string{"experiment": name}})
	return nil
}

// parseVariant reads NAME=PAGE or NAME=PAGE:WEIGHT.
func parseVariant(s string) (experiment.Variant, error) {
	name, rest, ok := strings.Cut(s, "=")
	if !ok {
		return experiment.Variant{}, fmt.Errorf("%q is not NAME=PAGE[:WEIGHT]", s)
	}
	page, weight := rest, 50
	if p, wt, has := strings.Cut(rest, ":"); has {
		n, err := strconv.Atoi(wt)
		if err != nil {
			return experiment.Variant{}, fmt.Errorf("%q: the weight is not a number", s)
		}
		page, weight = p, n
	}
	return experiment.Variant{Name: name, Page: page, Weight: weight}, nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func experimentAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	page := fs.String("page", "", "the page being tested; its own content is the control")
	goal := fs.String("goal", "", "form:NAME, chatbot:NAME or page:/path")
	var variants multi
	fs.Var(&variants, "variant", "NAME=PAGE[:WEIGHT], once per variant beyond the control")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || *page == "" || len(variants) == 0 {
		return fmt.Errorf("usage: quilzo experiment add NAME --page P --variant b=P-B --goal form:contact")
	}
	e := experiment.Experiment{Name: pos[0], Page: *page, Goal: *goal,
		Variants: []experiment.Variant{{Name: "control", Page: *page, Weight: 50}}}
	for _, v := range variants {
		pv, err := parseVariant(v)
		if err != nil {
			return err
		}
		e.Variants = append(e.Variants, pv)
	}
	caller := resolveCaller(root, flagToken)
	if err := changeExperiments(root, caller, "declare", e.Name, func(s *experiment.Set) error {
		if err := authorisePages(root, caller, e); err != nil {
			return err
		}
		return s.Put(e)
	}); err != nil {
		return err
	}
	w.Human("%s%s%s declared, not running; start it with quilzo experiment start %s\n",
		bold, e.Name, reset, e.Name)
	return nil
}

func experimentState(root, verb string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo experiment %s NAME", verb)
	}
	caller := resolveCaller(root, flagToken)
	return changeExperiments(root, caller, verb, args[0], func(s *experiment.Set) error {
		e, ok := s.Get(args[0])
		if !ok {
			return fmt.Errorf("no experiment called %s", args[0])
		}
		if err := authorisePages(root, caller, e); err != nil {
			return err
		}
		switch verb {
		case "remove":
			s.Remove(e.Name)
			return nil
		case "start":
			e.Running = true
		case "stop":
			e.Running = false
		}
		return s.Put(e)
	})
}

func experimentReport(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	days := fs.Int("days", 90, "how many days back to count")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo experiment report NAME [--days N]")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	set, err := experiment.Load(experimentsPath(root))
	if err != nil {
		return err
	}
	e, ok := set.Get(pos[0])
	if !ok {
		return fmt.Errorf("no experiment called %s", pos[0])
	}
	d, err := analytics.Read(analyticsDir(root), *days, time.Now())
	if err != nil {
		return err
	}
	rep := experiment.Measure(e, d)
	if w.JSON(rep) {
		return nil
	}
	for _, a := range rep.Arms {
		w.Human("  %-10s /%-20s %5d seen  %4d converted  %5.1f%%\n", a.Variant, a.Page,
			a.Seen, a.Won, a.Rate*100)
	}
	w.Human("%s\n", rep.Verdict)
	return nil
}

func experimentsCapability(root string) *admin.Experiments {
	return &admin.Experiments{
		Load: func() (*experiment.Set, error) { return experiment.Load(experimentsPath(root)) },
		Save: func(s *experiment.Set, by, change, name string) error {
			if err := experiment.Save(experimentsPath(root), s); err != nil {
				return err
			}
			record(root, audit.Record{Action: "experiment." + change, Resource: "/experiment/" + name,
				Outcome: audit.Success, Principal: by, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"experiment": name}})
			return nil
		},
		Days: func(n int) ([]analytics.Day, error) {
			return analytics.Read(analyticsDir(root), n, time.Now())
		},
	}
}

// authorisePages checks publish on every page an experiment touches.
func authorisePages(root string, caller *Caller, e experiment.Experiment) error {
	for _, v := range e.Variants {
		if err := authorise(root, caller, auth.ActPublish, "/"+v.Page); err != nil {
			return err
		}
	}
	return nil
}
