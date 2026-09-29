// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/decide"
)

// Typed decisions with a confidence gate, from the command line, the admin's
// Decisions screen and the machine interface. See internal/decide.

func decidersPath(root string) string { return filepath.Join(root, "deciders.json") }

func cmdDecide(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return decideList(root)
	case "set":
		return decideSet(root, args[1:])
	case "remove":
		return decideRemove(root, args[1:])
	case "ask":
		return decideAsk(root, args[1:])
	case "eval":
		return decideEval(root, args[1:])
	}
	return fmt.Errorf("unknown decide command %q; try list, set, remove, ask or eval", args[0])
}

func decideList(root string) error {
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	set, err := decide.Load(decidersPath(root))
	if err != nil {
		return err
	}
	if w.JSON(set.Deciders) {
		return nil
	}
	if len(set.Deciders) == 0 {
		w.Human("no deciders; declare one with quilzo decide set FILE.json\n")
	}
	for _, d := range set.Deciders {
		w.Human("%s%s%s  %s  %s(%d question(s))%s\n", bold, d.Name, reset, d.Title,
			dim, len(d.Questions), reset)
	}
	return nil
}

// changeDeciders edits the declarations under the audit log. Publish: a
// decider's answers drive what other parts of the site do with no person in
// the loop above its threshold.
func changeDeciders(root string, caller *Caller, change, name string,
	edit func(*decide.Set) error) error {

	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	set, err := decide.Load(decidersPath(root))
	if err != nil {
		return err
	}
	if err := edit(set); err != nil {
		return err
	}
	if err := decide.Save(decidersPath(root), set); err != nil {
		return err
	}
	record(root, audit.Record{Action: "decider." + change, Resource: "/decide/" + name,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: map[string]string{"decider": name}})
	return nil
}

func decideSet(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo decide set FILE.json   (one decider, as JSON)")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var d decide.Decider
	if err := json.Unmarshal(b, &d); err != nil {
		return fmt.Errorf("%s is not a decider: %w", args[0], err)
	}
	caller := resolveCaller(root, flagToken)
	if err := changeDeciders(root, caller, "declare", d.Name, func(s *decide.Set) error {
		return s.Put(d)
	}); err != nil {
		return err
	}
	w.Human("%s%s%s declared\n", bold, d.Name, reset)
	return nil
}

func decideRemove(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo decide remove NAME")
	}
	caller := resolveCaller(root, flagToken)
	return changeDeciders(root, caller, "remove", args[0], func(s *decide.Set) error {
		if !s.Remove(args[0]) {
			return fmt.Errorf("no decider called %s", args[0])
		}
		return nil
	})
}

// deciderModel is the gateway as "decider:NAME" when one is declared, the
// configured model otherwise, and nil — everything escalates — when neither.
func deciderModel(root, name string) (decide.Model, string) {
	gw, _, err := modelGateway(root)
	if err != nil {
		return nil, "the model gateway could not be read: " + err.Error()
	}
	if gw != nil {
		return gw.For("decider:" + name), ""
	}
	m, err := assist.NewHTTPModel()
	if err != nil {
		return nil, "no model configured"
	}
	return m, ""
}

func loadDecider(root, name string) (decide.Decider, error) {
	set, err := decide.Load(decidersPath(root))
	if err != nil {
		return decide.Decider{}, err
	}
	d, ok := set.Get(name)
	if !ok {
		return d, fmt.Errorf("no decider called %s", name)
	}
	return d, nil
}

// readState takes JSON inline, or @FILE.
func readState(arg string) (any, error) {
	raw := []byte(arg)
	if strings.HasPrefix(arg, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(arg, "@"))
		if err != nil {
			return nil, err
		}
		raw = b
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("the state is not JSON: %w", err)
	}
	return v, nil
}

func decideAsk(root string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: quilzo decide ask NAME '{\"json\": \"state\"}' | @FILE")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	d, err := loadDecider(root, args[0])
	if err != nil {
		return err
	}
	state, err := readState(args[1])
	if err != nil {
		return err
	}
	m, _ := deciderModel(root, d.Name)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := decide.Decide(ctx, d, m, state)
	if err != nil {
		return err
	}
	if w.JSON(res) {
		return nil
	}
	for _, a := range res.Answers {
		if a.Escalate {
			w.Human("%s%s%s  a person decides — %s\n", yellow, a.Question, reset, a.Why)
			continue
		}
		w.Human("%s%s%s  %s  %s(confidence %.2f, agreement %.2f)%s\n", bold,
			a.Question, reset, a.Value, dim, a.Confidence, a.Agreement, reset)
	}
	return nil
}

func decideEval(root string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: quilzo decide eval NAME CASES.jsonl\n" +
			"  one case per line: {\"state\": {...}, \"expect\": {\"question\": \"answer\"}}")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	d, err := loadDecider(root, args[0])
	if err != nil {
		return err
	}
	var cases []decide.Case
	if err := loadJSONL(args[1], func(b []byte) error {
		var c decide.Case
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		cases = append(cases, c)
		return nil
	}); err != nil {
		return err
	}
	m, _ := deciderModel(root, d.Name)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	rep, err := decide.Evaluate(ctx, d, m, cases)
	if err != nil {
		return err
	}
	if w.JSON(rep) {
		return nil
	}
	w.Human("%s%d answer(s): %d decided alone, %d to a person%s\n", bold,
		rep.Answers, rep.Auto, rep.Escalated, reset)
	w.Human("  decided alone   %.0f%%\n", rep.Coverage*100)
	w.Human("  right when alone %.0f%%\n", rep.AutoAccuracy*100)
	for _, b := range rep.Calibration {
		if b.N > 0 {
			w.Human("  confidence %.1f–%.1f: %d of %d right\n", b.From, b.To, b.Right, b.N)
		}
	}
	for _, x := range rep.Wrong {
		w.Human("  %s%s%s\n", yellow, x, reset)
	}
	return nil
}

// decidersCapability is the admin's Decisions screen.
func decidersCapability(root string) *admin.Deciders {
	return &admin.Deciders{
		Load: func() (*decide.Set, error) { return decide.Load(decidersPath(root)) },
		Save: func(set *decide.Set, by, change, name string) error {
			if err := decide.Save(decidersPath(root), set); err != nil {
				return err
			}
			record(root, audit.Record{Action: "decider." + change, Resource: "/decide/" + name,
				Outcome: audit.Success, Principal: by, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"decider": name}})
			return nil
		},
		Model: func(name string) (decide.Model, string) { return deciderModel(root, name) },
	}
}
