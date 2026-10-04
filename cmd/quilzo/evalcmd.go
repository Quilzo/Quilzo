// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evals"
	"github.com/quilzo/quilzo/internal/shield"
)

// Evaluations: test sets kept beside the agents, run k times, with
// instructions planted. See internal/evals for what is measured.
//
//	evals/agents/NAME.jsonl         the test set, one case a line
//	evals/results/NAME/STAMP.json   each evaluation's report
//	evals/results/NAME/running      present while one is running
//	agents/evalruns/                the runs they made, kept apart

func evalsDir(root string) string { return filepath.Join(root, "evals") }

// reEvalAgent is what an agent's name must be to become a file name here:
// it arrives from a command line or a form, and reaches a path.
var reEvalAgent = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

func evalAgentOK(name string) error {
	if !reEvalAgent.MatchString(name) {
		return fmt.Errorf("%q is not an agent's name", name)
	}
	return nil
}

func evalCasesPath(root, name string) string {
	return filepath.Join(evalsDir(root), "agents", name+".jsonl")
}

func evalResultsDir(root, name string) string {
	return filepath.Join(evalsDir(root), "results", name)
}

// MaxEvalReports is how many reports are kept per agent.
const MaxEvalReports = 50

// evalMode turns a run into an evaluation's: nothing it does is real but
// reading, and what it reads carries the plant, if there is one.
//
// Reads is an allow-list, taken from the machine interface's own word on
// which operations write. A deny-list of writes is what agent.IsWrite is,
// and it names three operations of the five the interface marks as writes:
// harmless for a run, whose executor implements nothing else, and exactly
// the gap an evaluation must not have the day it does.
type evalMode struct {
	Plant string
	Reads map[string]bool
}

func (e *evalMode) perform(real agent.Perform) agent.Perform {
	return func(ctx context.Context, a agent.Action) (string, error) {
		switch {
		case a.Tool != "":
			return "(evaluation: the tool " + a.Tool + " was not called)", nil
		case a.Delegate != "":
			return "(evaluation: " + a.Delegate + " was not started)", nil
		case a.Op != "" && !e.Reads[a.Op]:
			return "(evaluation: " + a.Op + " changes something, so nothing was written)", nil
		}
		res, err := real(ctx, a)
		if err == nil && e.Plant != "" {
			res += "\n\n" + e.Plant
		}
		return res, err
	}
}

func loadEvalCases(root, name string) ([]evals.Case, error) {
	if err := evalAgentOK(name); err != nil {
		return nil, err
	}
	f, err := os.Open(evalCasesPath(root, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []evals.Case
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var c evals.Case
		if err := json.Unmarshal(line, &c); err != nil {
			return nil, fmt.Errorf("%s: %w", evalCasesPath(root, name), err)
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

func saveEvalCases(root, name string, cases []evals.Case) error {
	if err := evalAgentOK(name); err != nil {
		return err
	}
	var b bytes.Buffer
	for _, c := range cases {
		line, err := json.Marshal(c)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(evalCasesPath(root, name)), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(evalCasesPath(root, name), b.Bytes(), 0o600)
}

func addEvalCase(root, name string, c evals.Case) (evals.Case, error) {
	if err := c.Validate(); err != nil {
		return c, err
	}
	cases, err := loadEvalCases(root, name)
	if err != nil {
		return c, err
	}
	if len(cases) >= evals.MaxCases {
		return c, fmt.Errorf("%s already has %d cases; remove one first", name, evals.MaxCases)
	}
	c.ID, c.Added = evals.NewID(), time.Now().UTC()
	return c, saveEvalCases(root, name, append(cases, c))
}

func removeEvalCase(root, name, id string) error {
	cases, err := loadEvalCases(root, name)
	if err != nil {
		return err
	}
	for i, c := range cases {
		if c.ID == id {
			return saveEvalCases(root, name, append(cases[:i], cases[i+1:]...))
		}
	}
	return fmt.Errorf("%s has no case %s", name, id)
}

// evalLocks keeps one evaluation of an agent at a time in this process; the
// running file says so to every other.
var evalLocks sync.Map

func evalRunning(root, name string) (time.Time, bool) {
	if evalAgentOK(name) != nil {
		return time.Time{}, false
	}
	fi, err := os.Stat(filepath.Join(evalResultsDir(root, name), "running"))
	if err != nil {
		return time.Time{}, false
	}
	// A marker older than any evaluation could take was left by a process
	// that died.
	if time.Since(fi.ModTime()) > 2*time.Hour {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

// runEvaluation evaluates an agent: every case k times, and with a model,
// once per plant. The report is kept and returned.
func runEvaluation(root, name string, k int, withModel bool, caller *Caller) (evals.Report, error) {
	rep := evals.Report{Agent: name, By: caller.Name, K: k, At: time.Now().UTC()}
	if err := evalAgentOK(name); err != nil {
		return rep, err
	}
	if _, busy := evalLocks.LoadOrStore(name, true); busy {
		return rep, fmt.Errorf("%s is being evaluated already", name)
	}
	defer evalLocks.Delete(name)
	if _, running := evalRunning(root, name); running {
		return rep, fmt.Errorf("%s is being evaluated already", name)
	}
	cases, err := loadEvalCases(root, name)
	if err != nil {
		return rep, err
	}
	if len(cases) == 0 {
		return rep, fmt.Errorf("%s has no test cases. Keep a run as one: quilzo eval keep RUN-ID", name)
	}
	if withModel {
		m, why := agentRunModel(root, name)
		if m == nil {
			return rep, fmt.Errorf("evaluating with a model needs one configured: %s", why)
		}
		rep.Model = m.Name()
	}
	dir := evalResultsDir(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return rep, err
	}
	marker := filepath.Join(dir, "running")
	if err := os.WriteFile(marker, []byte(caller.Name+"\n"), 0o600); err != nil {
		return rep, err
	}
	defer os.Remove(marker)

	tag := "eval-" + rep.At.Format("20060102T150405")
	reads := readOperations(root)
	start := time.Now()
	run := func(goal, plant string) (string, agent.Trace, error) {
		ctx, cancel := context.WithTimeout(context.Background(), agentRunTime)
		defer cancel()
		started := time.Now().UTC()
		id, err := newAgentRunID(started)
		if err != nil {
			return "", agent.Trace{}, err
		}
		kr := &keptRun{root: root, rec: agent.Record{ID: id, Agent: name, Goal: goal,
			By: caller.Name, Started: started, Model: rep.Model, Eval: tag, Plant: plant}}
		out, runErr := executeAgentFrom(ctx, root, name, goal, withModel, caller,
			&agentResume{Checkpoint: kr.checkpoint, Eval: &evalMode{Plant: plant, Reads: reads}})
		if out.Manifest.Name == "" {
			return "", agent.Trace{}, runErr
		}
		if err := kr.finish(out); err != nil {
			return id, out.Trace, err
		}
		return id, out.Trace, runErr
	}
	rep.Results = evals.Evaluate(cases, k, withModel, run)
	rep.Tally()
	rep.Took = time.Since(start).Round(time.Second).String()
	if err := saveEvalReport(root, rep); err != nil {
		return rep, err
	}
	outcome := audit.Success
	if rep.Verdict() != "passing" {
		outcome = audit.Failure
	}
	record(root, caller.auditRecord("agent.evaluated", "/agents/"+name, outcome, map[string]string{
		"agent": name, "cases": fmt.Sprint(rep.Cases), "k": fmt.Sprint(rep.K),
		"reliable": fmt.Sprint(rep.Reliable), "planted": fmt.Sprint(rep.Planted),
		"hijacked": fmt.Sprint(rep.Hijacked), "model": rep.Model, "verdict": rep.Verdict()}))
	// An agent that followed a planted instruction is the shield's to act
	// on, as its playbook says: by default it is paused until somebody
	// narrows what it may do.
	if rep.Hijacked > 0 {
		newShieldHost(root).engine.Observe(shield.Signal{Name: "agent-hijacked", Subject: name})
	}
	return rep, nil
}

// readOperations are the operations the machine interface says change
// nothing.
func readOperations(root string) map[string]bool {
	out := map[string]bool{}
	s, err := open(root)
	if err != nil {
		return out
	}
	for _, op := range buildMCP(root, s, resolveCaller(root, ""), "templates").Operations() {
		if !op.Writes {
			out[op.Name] = true
		}
	}
	return out
}

func saveEvalReport(root string, rep evals.Report) error {
	dir := evalResultsDir(root, rep.Agent)
	b, err := json.MarshalIndent(rep, "", " ")
	if err != nil {
		return err
	}
	if err := atomicfile.Write(filepath.Join(dir, rep.At.Format("20060102T150405")+".json"), b, 0o600); err != nil {
		return err
	}
	names, _ := evalReportNames(root, rep.Agent)
	for len(names) > MaxEvalReports {
		_ = os.Remove(filepath.Join(dir, names[0]))
		names = names[1:]
	}
	return nil
}

func evalReportNames(root, name string) ([]string, error) {
	if err := evalAgentOK(name); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(evalResultsDir(root, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") && e.Type().IsRegular() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// evalReports are an agent's reports, newest first.
func evalReports(root, name string, limit int) ([]evals.Report, error) {
	names, err := evalReportNames(root, name)
	if err != nil {
		return nil, err
	}
	var out []evals.Report
	for i := len(names) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		b, err := readBounded(filepath.Join(evalResultsDir(root, name), names[i]), 8<<20)
		if err != nil {
			continue
		}
		var r evals.Report
		if json.Unmarshal(b, &r) == nil {
			out = append(out, r)
		}
	}
	return out, nil
}

func evalUsage() error {
	return errors.New("usage: quilzo eval cases AGENT | keep RUN-ID [expectations] | " +
		"add AGENT --goal G [expectations] | remove AGENT CASE-ID | " +
		"run AGENT [--k 3] [--model] | show AGENT\n" +
		"  expectations: --finishes --uses a,b --avoids c --asks-before d " +
		"--answer-has \"text\" --max-steps N --no-refusals")
}

// expectFlags are the closed list a case may say, as flags.
func expectFlags(fs *flag.FlagSet) func() (evals.Expect, bool) {
	finishes := fs.Bool("finishes", false, "the run ends with an answer")
	uses := fs.String("uses", "", "capabilities or tools it must use, comma-separated")
	avoids := fs.String("avoids", "", "capabilities or tools it must never attempt")
	asks := fs.String("asks-before", "", "the action it must stop and ask a person about")
	has := fs.String("answer-has", "", "words the answer must contain, | between phrases")
	steps := fs.Int("max-steps", 0, "the most steps it may take")
	norefuse := fs.Bool("no-refusals", false, "nothing it tries is refused")
	return func() (evals.Expect, bool) {
		split := func(s, sep string) []string {
			var out []string
			for _, p := range strings.Split(s, sep) {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
			return out
		}
		e := evals.Expect{Finishes: *finishes, Uses: split(*uses, ","), Avoids: split(*avoids, ","),
			AsksBefore: strings.TrimSpace(*asks), AnswerHas: split(*has, "|"), MaxSteps: *steps,
			NoRefusals: *norefuse}
		return e, !e.Empty()
	}
}

func cmdEval(root string, args []string) error {
	if len(args) == 0 {
		return evalUsage()
	}
	caller := resolveCaller(root, flagToken)
	// Changing a test set or running one is changing how an agent is
	// judged, which is the studio's: administrators.
	admin := func() error {
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return fmt.Errorf("evaluations are kept by an administrator: %w", err)
		}
		return nil
	}
	known := func(name string) error {
		set, err := loadAgents(root)
		if err != nil {
			return err
		}
		if _, ok := set.Agents[name]; !ok {
			return fmt.Errorf("no agent called %q; quilzo agent list", name)
		}
		return nil
	}
	switch args[0] {
	case "cases":
		if len(args) != 2 {
			return evalUsage()
		}
		cases, err := loadEvalCases(root, args[1])
		if err != nil {
			return err
		}
		if w.JSON(cases) {
			return nil
		}
		if len(cases) == 0 {
			w.Human("%s has no test cases\n", args[1])
		}
		for _, c := range cases {
			w.Human("%s%s%s  %s\n    %s\n", bold, c.ID, reset, c.Goal, describeExpect(c.Expect))
		}
		return nil
	case "keep", "add":
		if err := admin(); err != nil {
			return err
		}
		if len(args) < 2 {
			return evalUsage()
		}
		fs := flag.NewFlagSet("eval "+args[0], flag.ContinueOnError)
		goal := fs.String("goal", "", "what the agent is asked")
		expect := expectFlags(fs)
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		var c evals.Case
		var name string
		if args[0] == "keep" {
			rec, err := loadAgentRun(root, args[1])
			if err != nil {
				return err
			}
			if rec.Eval != "" {
				return errors.New("that run was made by an evaluation; keep a run a person started")
			}
			c, name = evals.FromRun(rec), rec.Agent
			if *goal != "" {
				c.Goal = *goal
			}
			if e, said := expect(); said {
				c.Expect = e
			}
		} else {
			name = args[1]
			e, said := expect()
			if !said || *goal == "" {
				return evalUsage()
			}
			c = evals.Case{Goal: *goal, Expect: e}
		}
		if err := known(name); err != nil {
			return err
		}
		c.By = caller.Name
		c, err := addEvalCase(root, name, c)
		if err != nil {
			return err
		}
		w.Human("kept %s for %s: %s\n  %s\n", c.ID, name, c.Goal, describeExpect(c.Expect))
		return recordE(root, caller.auditRecord("agent.case-added", "/agents/"+name, audit.Success,
			map[string]string{"agent": name, "case": c.ID, "from": c.From}))
	case "remove":
		if err := admin(); err != nil {
			return err
		}
		if len(args) != 3 || !evals.ValidID(args[2]) {
			return evalUsage()
		}
		if err := removeEvalCase(root, args[1], args[2]); err != nil {
			return err
		}
		w.Human("removed %s\n", args[2])
		return recordE(root, caller.auditRecord("agent.case-removed", "/agents/"+args[1], audit.Success,
			map[string]string{"agent": args[1], "case": args[2]}))
	case "run":
		if err := admin(); err != nil {
			return err
		}
		if len(args) < 2 {
			return evalUsage()
		}
		fs := flag.NewFlagSet("eval run", flag.ContinueOnError)
		k := fs.Int("k", 3, "how many times each case is run")
		model := fs.Bool("model", false, "let the configured model choose, and plant instructions")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if err := known(args[1]); err != nil {
			return err
		}
		rep, err := runEvaluation(root, args[1], *k, *model, caller)
		if err != nil {
			return err
		}
		printEvalReport(rep)
		if rep.Verdict() == "hijacked" {
			return fmt.Errorf("%d case(s) followed a planted instruction", rep.Hijacked)
		}
		return nil
	case "show":
		if len(args) != 2 {
			return evalUsage()
		}
		reps, err := evalReports(root, args[1], 1)
		if err != nil {
			return err
		}
		if len(reps) == 0 {
			w.Human("%s has not been evaluated\n", args[1])
			return nil
		}
		printEvalReport(reps[0])
		return nil
	}
	return evalUsage()
}

func describeExpect(e evals.Expect) string {
	var parts []string
	if e.Finishes {
		parts = append(parts, "finishes")
	}
	if len(e.Uses) > 0 {
		parts = append(parts, "uses "+strings.Join(e.Uses, ", "))
	}
	if len(e.Avoids) > 0 {
		parts = append(parts, "never tries "+strings.Join(e.Avoids, ", "))
	}
	if e.AsksBefore != "" {
		parts = append(parts, "asks before "+e.AsksBefore)
	}
	for _, h := range e.AnswerHas {
		parts = append(parts, fmt.Sprintf("says %q", h))
	}
	if e.MaxSteps > 0 {
		parts = append(parts, fmt.Sprintf("at most %d steps", e.MaxSteps))
	}
	if e.NoRefusals {
		parts = append(parts, "nothing refused")
	}
	return strings.Join(parts, "; ")
}

func printEvalReport(r evals.Report) {
	if w.JSON(r) {
		return
	}
	how := "the manifest walked; nothing planted, as no model chooses"
	if r.Model != "" {
		how = r.Model + " choosing"
	}
	w.Human("%s%s%s, %s, %s, k=%d (%s)\n", bold, r.Agent, reset, r.Verdict(),
		r.At.Format("2 Jan 15:04"), r.K, how)
	w.Human("  pass^%d   %d of %d cases (%.0f%%)\n", r.K, r.Reliable, r.Cases, r.PassK*100)
	if r.Planted > 0 {
		w.Human("  planted  %d of %d cases followed an instruction planted in what they read\n", r.Hijacked, r.Planted)
	}
	for _, c := range r.Results {
		if c.Reliable && !c.Hijacked {
			continue
		}
		w.Human("  %s%s%s %s\n", yellow, c.ID, reset, c.Goal)
		for _, rr := range c.Runs {
			if !rr.Pass {
				w.Human("    %s: %s%s\n", rr.Run, strings.Join(rr.Why, "; "), rr.Error)
			}
		}
		for _, rr := range c.Planted {
			if rr.Hijacked != "" {
				w.Human("    %s (planted): %s\n", rr.Run, rr.Hijacked)
			}
		}
	}
}
