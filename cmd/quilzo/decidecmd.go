// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
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
		if err := noArguments(args[1:]); err != nil {
			return err
		}
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
	if w.JSON(listedDeciders(root, set)) {
		return nil
	}
	if len(set.Deciders) == 0 {
		w.Human("no deciders; declare one with quilzo decide set FILE.json\n")
	}
	for _, d := range set.Deciders {
		w.Human("%s%s%s  %s  %s(%d question(s))%s\n", bold, d.Name, reset, d.Title,
			dim, len(d.Questions), reset)
		if m, ok := lastMeasurement(root, "decider", d.Name); ok {
			w.Human("  %s%s%s\n", dim, m, reset)
		} else {
			w.Human("  %snever evaluated: quilzo decide eval %s CASES.jsonl%s\n", dim, d.Name, reset)
		}
	}
	return nil
}

// listedDecider is a decider as a list gives it to a program: its
// declaration, and when it was last measured and on which model.
type listedDecider struct {
	decide.Decider
	Measured *measuredOn `json:"measured,omitempty"`
}

// listedDeciders is every decider for a list, the command line's and the
// machine interface's alike.
func listedDeciders(root string, set *decide.Set) []listedDecider {
	out := make([]listedDecider, 0, len(set.Deciders))
	for _, d := range set.Deciders {
		out = append(out, listedDecider{Decider: d, Measured: listedMeasurement(root, "decider", d.Name)})
	}
	return out
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
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
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
//
// Charged as well to payers, each against its own budget: an agent's run
// asks a decider for the person who started it, and a decider asked with
// nobody else charged was a way to spend past that person's limit.
func deciderModel(root, name string, payers ...string) (decide.Model, string) {
	gw, _, err := modelGateway(root)
	if err != nil {
		return nil, "the model gateway could not be read: " + err.Error()
	}
	if gw != nil {
		return gw.For("decider:"+name, payers...), ""
	}
	m, err := directModel(root)
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
	recordAsk(root, caller, res, state)
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
	// Named before it is measured, and measured through that route alone
	// (onlyThrough), as a chatbot's evaluation is.
	served := servedBy(m)
	if only := onlyThrough(root, served.Route, "decider:"+d.Name); only != nil {
		m = only
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	rep, err := decide.Evaluate(ctx, d, m, cases)
	if err != nil {
		return err
	}
	// Kept, with the model it measured and when, and on the record. It
	// kept nothing: what a decider's confidence means is a property of the
	// model answering, and nobody could say when a decider was last
	// measured, or whether on the model answering now. The counts, never
	// the states, which are somebody's tickets.
	at := time.Now().UTC()
	if err := keepMeasurement(root, "decider", d.Name, caller.Name, served, at, rep); err != nil {
		return fmt.Errorf("the evaluation of %s could not be kept: %w", d.Name, err)
	}
	record(root, caller.auditRecord("decider.evaluated", "/decide/"+d.Name, audit.Success, map[string]string{
		"decider": d.Name, "answers": fmt.Sprint(rep.Answers), "auto": fmt.Sprint(rep.Auto),
		"auto_right": fmt.Sprint(rep.AutoRight), "escalated": fmt.Sprint(rep.Escalated),
		"model": served.Model, "route": served.Route}))
	if w.JSON(rep) {
		return nil
	}
	w.Human("%s%d answer(s): %d decided alone, %d to a person%s\n", bold,
		rep.Answers, rep.Auto, rep.Escalated, reset)
	w.Human("  %s\n", measurement{At: at, Model: served.Model, Route: served.Route})
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

// recordAsk writes down what a decider answered somebody who asked it, from
// the command line, the Decisions screen or the agent interface.
//
// A single ask wrote nothing: declaring a decider was on the record and
// every answer it gave was not, so what was decided, how sure it was and
// who asked could not be told afterwards, which is what keeping records of
// automated decisions asks for. Inside an agent's run the run's step is the
// record, and this is not called there. The state is never written, since
// it is somebody's ticket or comment, nor what the model gave as its
// reasons, which may quote it; only the state's digest, which says the same
// state was asked about twice without saying what it was.
func recordAsk(root string, caller *Caller, res decide.Result, state any) {
	answers := make([]string, 0, len(res.Answers))
	lowest := 1.0
	for _, a := range res.Answers {
		lowest = min(lowest, a.Confidence)
		if a.Escalate {
			answers = append(answers, fmt.Sprintf("%s: a person decides (%.2f)", a.Question, a.Confidence))
			continue
		}
		answers = append(answers, fmt.Sprintf("%s=%s (%.2f)", a.Question, a.Value, a.Confidence))
	}
	if len(res.Answers) == 0 {
		lowest = 0
	}
	raw, _ := json.Marshal(state)
	sum := sha256.Sum256(raw)
	record(root, audit.Record{Action: "decide.asked", Resource: "/decide/" + res.Decider,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
		Verified: caller.Verified, Detail: map[string]string{
			"decider": res.Decider, "answers": strings.Join(answers, "; "),
			"confidence": fmt.Sprintf("%.2f", lowest), "escalated": strconv.FormatBool(res.Escalate),
			"state_sha256": hex.EncodeToString(sum[:]),
		}})
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
		Asked: func(by string, res decide.Result, state any) {
			recordAsk(root, &Caller{Name: by, Kind: audit.KindHuman, Verified: true}, res, state)
		},
		Measured: func(name string) string {
			if m, ok := lastMeasurement(root, "decider", name); ok {
				return m.String()
			}
			return ""
		},
	}
}
