// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
)

// Runs, kept: every run of a declared agent, so that what it did can be
// read afterwards and compared with the run before.

// MaxAgentRuns is how many are kept. The oldest go first.
const MaxAgentRuns = 500

func agentRunsDir(root string) string {
	return filepath.Join(agentsDir(root), "runs")
}

func newAgentRunID(started time.Time) (string, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "run-" + started.UTC().Format("20060102") + "-" +
		hex.EncodeToString(raw[:]), nil
}

// writeAgentRun stores a run under its identifier, replacing what was there.
func writeAgentRun(root string, rec agent.Record) error {
	if !agent.ValidRecordID(rec.ID) {
		return fmt.Errorf("%q is not a run", rec.ID)
	}
	rec.Beat = time.Now().UTC()
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(agentRunsDir(root), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(agentRunsDir(root), rec.ID+".json"),
		b, 0o600)
}

// holdAgentRun claims a run for one process at a time.
//
// Two people approving the same pending action at the same moment would
// otherwise both find it waiting and both perform it. The claim is a file
// that can only be created once; one left behind by a process that died is
// taken over once it is older than any run could be.
func holdAgentRun(root, id string) (release func(), err error) {
	if err := os.MkdirAll(agentRunsDir(root), 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(agentRunsDir(root), id+".lock")
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(p) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		fi, serr := os.Stat(p)
		if serr == nil && time.Since(fi.ModTime()) < agentRunHold {
			break
		}
		os.Remove(p)
	}
	return nil, fmt.Errorf("somebody else is continuing %s right now", id)
}

// agentRunHold is longer than a run may take: the budget's ceiling and the
// time allowed here for one.
const agentRunHold = 15 * time.Minute

// agentRunTime bounds one stretch of a run started from here.
const agentRunTime = 3 * time.Minute

// keptRun is a run being kept as it goes.
type keptRun struct {
	root string
	rec  agent.Record
}

// checkpoint writes the run as it stands after a step. A write that fails
// does not stop the run: the final write says so if it fails too.
func (k *keptRun) checkpoint(t agent.Trace) {
	rec := k.rec
	rec.Trace = agent.Keep(rec.ID, rec.By, rec.Model, rec.Started, t,
		rec.Receipt).Trace
	rec.State = agent.Running
	_ = writeAgentRun(k.root, rec)
}

// finish writes the run as it ended this stretch.
func (k *keptRun) finish(out agentOutcome) error {
	started := k.rec.Started
	if started.IsZero() {
		started = out.Started
	}
	rec := agent.Keep(k.rec.ID, k.rec.By, k.rec.Model, started, out.Trace,
		out.Receipt)
	if rec.Goal == "" {
		rec.Goal = k.rec.Goal
	}
	rec.From, rec.Answers = k.rec.From, k.rec.Answers
	k.rec = rec
	if err := writeAgentRun(k.root, rec); err != nil {
		return err
	}
	return pruneAgentRuns(k.root)
}

// runAgentKept runs a declared agent and keeps the run as it goes. The
// identifier comes back even when the run ended badly: that is the run
// worth reading.
func runAgentKept(ctx context.Context, root, name, goal string, withModel bool,
	caller *Caller) (string, agentOutcome, error) {

	started := time.Now().UTC()
	id, err := newAgentRunID(started)
	if err != nil {
		return "", agentOutcome{}, err
	}
	k := &keptRun{root: root, rec: agent.Record{ID: id, Agent: name,
		Goal: goal, By: caller.Name, Started: started}}
	if withModel {
		if m, _ := agentRunModel(root, name); m != nil {
			k.rec.Model = m.Name()
		}
	}
	out, runErr := executeAgentFrom(ctx, root, name, goal, withModel, caller,
		&agentResume{Checkpoint: k.checkpoint})
	if out.Manifest.Name == "" {
		// It never started. Nothing was checkpointed either.
		return "", out, runErr
	}
	if err := k.finish(out); err != nil {
		return "", out, err
	}
	return id, out, runErr
}

// continueAgentRun takes a kept run on: with a person's answer to the
// action it is waiting on, or with none when it was interrupted.
func continueAgentRun(ctx context.Context, root, id string, v *agent.Verdict,
	caller *Caller) (agent.Record, error) {

	var none agent.Record
	if caller.Kind == audit.KindAI {
		return none, fmt.Errorf("a person answers what an agent asks. A " +
			"model that could would be approving itself")
	}
	release, err := holdAgentRun(root, id)
	if err != nil {
		return none, err
	}
	defer release()
	prior, err := loadAgentRun(root, id)
	if err != nil {
		return none, err
	}
	now := time.Now().UTC()
	switch {
	case v == nil && prior.OutcomeAt(now) != "interrupted":
		return none, fmt.Errorf("%s was not interrupted; it is %s", id,
			prior.OutcomeAt(now))
	case v != nil && prior.Trace.Waiting == nil:
		return none, agent.ErrNotWaiting
	}
	k := &keptRun{root: root, rec: prior}
	if v != nil {
		v.By = caller.Name
		k.rec.Answers = append(append([]agent.Answer(nil), prior.Answers...),
			agent.Answer{N: v.N, Approve: v.Approve, By: caller.Name, At: now})
	}
	out, runErr := executeAgentFrom(ctx, root, prior.Agent, prior.Goal,
		prior.Model != "", caller,
		&agentResume{Prior: &prior, Verdict: v, Checkpoint: k.checkpoint})
	if out.Manifest.Name == "" {
		return none, runErr
	}
	if v != nil {
		did, w := "agent.approve", prior.Trace.Waiting
		if !v.Approve {
			did = "agent.decline"
		}
		what := w.Action.Op
		if what == "" {
			what = w.Action.Tool
		}
		if err := recordE(root, caller.auditRecord(did, "/", audit.Success,
			map[string]string{"agent": prior.Agent, "run": id,
				"step": fmt.Sprint(w.N), "what": what})); err != nil {
			return none, err
		}
	}
	if out.Model != "" {
		k.rec.Model = out.Model
	}
	if err := k.finish(out); err != nil {
		return none, err
	}
	return k.rec, runErr
}

// replayAgentRun runs a kept run again from after its first n steps, as a
// new run. What those steps did stays done; what they returned is what the
// model is shown.
func replayAgentRun(ctx context.Context, root, id string, n int,
	caller *Caller) (string, error) {

	if caller.Kind == audit.KindAI {
		return "", fmt.Errorf("a person runs an agent again")
	}
	prior, err := loadAgentRun(root, id)
	if err != nil {
		return "", err
	}
	cut, err := prior.Trace.Upto(n)
	if err != nil {
		return "", err
	}
	started := time.Now().UTC()
	newID, err := newAgentRunID(started)
	if err != nil {
		return "", err
	}
	from := prior
	from.Trace = cut
	k := &keptRun{root: root, rec: agent.Record{ID: newID, Agent: prior.Agent,
		Goal: prior.Goal, By: caller.Name, Model: prior.Model, Started: started,
		From: fmt.Sprintf("%s@%d", id, n)}}
	out, runErr := executeAgentFrom(ctx, root, prior.Agent, prior.Goal,
		prior.Model != "", caller,
		&agentResume{Prior: &from, Checkpoint: k.checkpoint})
	if out.Manifest.Name == "" {
		return "", runErr
	}
	if err := k.finish(out); err != nil {
		return "", err
	}
	return newID, runErr
}

// pruneAgentRuns removes the oldest runs past the limit. Names sort by day
// and then arbitrarily within it, which is near enough for a limit.
func pruneAgentRuns(root string) error {
	entries, err := os.ReadDir(agentRunsDir(root))
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if id, ok := strings.CutSuffix(e.Name(), ".json"); ok &&
			agent.ValidRecordID(id) {
			names = append(names, e.Name())
		}
	}
	if len(names) <= MaxAgentRuns {
		return nil
	}
	type aged struct {
		name string
		at   time.Time
	}
	var all []aged
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(agentRunsDir(root), n))
		if err != nil {
			continue
		}
		all = append(all, aged{n, fi.ModTime()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for _, a := range all[:len(all)-MaxAgentRuns] {
		if err := os.Remove(filepath.Join(agentRunsDir(root), a.name)); err != nil {
			return err
		}
	}
	return nil
}

func loadAgentRun(root, id string) (agent.Record, error) {
	var rec agent.Record
	if !agent.ValidRecordID(id) {
		return rec, fmt.Errorf("%q is not a run", id)
	}
	b, err := readBounded(filepath.Join(agentRunsDir(root), id+".json"), 16<<20)
	if os.IsNotExist(err) {
		return rec, fmt.Errorf("there is no run %s", id)
	}
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, fmt.Errorf("%s: %w", id, err)
	}
	if rec.ID != id {
		return rec, fmt.Errorf("the file for %s holds %q", id, rec.ID)
	}
	return rec, nil
}

// listAgentRuns returns the kept runs, newest first, of one agent or all.
func listAgentRuns(root, name string, limit int) ([]agent.Record, error) {
	entries, err := os.ReadDir(agentRunsDir(root))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []agent.Record
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !agent.ValidRecordID(id) || !e.Type().IsRegular() {
			continue
		}
		rec, err := loadAgentRun(root, id)
		if err != nil {
			// One unreadable run does not hide the rest.
			continue
		}
		if name == "" || rec.Agent == name {
			out = append(out, rec)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Started.After(out[j].Started)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// declareAgent stores a declaration after validating it against what the
// machine interface actually offers. The one place a declaration is written
// from a screen.
func declareAgent(root string, m agent.Manifest, isNew bool, caller *Caller) error {
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("an agent is declared by a person. A model that " +
			"could declare one could write its own permissions")
	}
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	_, exists := set.Agents[m.Name]
	switch {
	case isNew && exists:
		return fmt.Errorf("an agent called %s is already declared", m.Name)
	case !isNew && !exists:
		return fmt.Errorf("no agent called %s is declared", m.Name)
	}
	if err := m.Validate(knownCapabilities(root)); err != nil {
		return err
	}
	for _, d := range m.Delegates {
		if _, ok := set.Agents[d]; !ok {
			return fmt.Errorf("%s would hand work to %s, which is not "+
				"declared", m.Name, d)
		}
	}
	set.Agents[m.Name] = m
	if err := saveJSON(agentsPath(root), set); err != nil {
		return err
	}
	did := "agent.changed"
	if isNew {
		did = "agent.declare"
	}
	return recordE(root, caller.auditRecord(did, "/", audit.Success,
		map[string]string{"agent": m.Name, "kind": string(m.Kind),
			"autonomy":     string(m.Autonomy),
			"capabilities": strings.Join(m.Capabilities, " ")}))
}

// withdrawAgent removes a declaration. What the agent did stays on record.
func withdrawAgent(root, name string, caller *Caller) error {
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("an agent is withdrawn by a person")
	}
	set, err := loadAgents(root)
	if err != nil {
		return err
	}
	if _, ok := set.Agents[name]; !ok {
		return fmt.Errorf("no agent called %s is declared", name)
	}
	for other, m := range set.Agents {
		for _, d := range m.Delegates {
			if d == name {
				return fmt.Errorf("%s hands work to %s. Change that first, "+
					"or it would be left delegating to nothing", other, name)
			}
		}
	}
	delete(set.Agents, name)
	if err := saveJSON(agentsPath(root), set); err != nil {
		return err
	}
	return recordE(root, caller.auditRecord("agent.withdrawn", "/",
		audit.Success, map[string]string{"agent": name}))
}

// runAgentOnce runs a declared agent from the screen and keeps the run.
func runAgentOnce(root, name, goal string, withModel bool,
	caller *Caller) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), agentRunTime)
	defer cancel()
	if goal == "" && !withModel {
		goal = "check that this agent's declaration is enforceable"
	}
	if goal == "" {
		return "", fmt.Errorf("say what it should do. A model with nothing " +
			"asked of it chooses something")
	}
	id, _, err := runAgentKept(ctx, root, name, goal, withModel, caller)
	return id, err
}

func agentRuns(root string, args []string) error {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}
	runs, err := listAgentRuns(root, name, 50)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"runs": runs}) {
		return nil
	}
	if len(runs) == 0 {
		fmt.Println("  no runs are kept")
		return nil
	}
	now := time.Now().UTC()
	for _, r := range runs {
		fmt.Printf("  %s  %-11s %-16s %s\n", r.ID, r.OutcomeAt(now), r.Agent,
			truncate(r.Goal, 60))
	}
	return nil
}

func agentTrace(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo agent trace RUN")
	}
	r, err := loadAgentRun(root, args[0])
	if err != nil {
		return err
	}
	if w.JSON(r) {
		return nil
	}
	printAgentRun(r)
	return nil
}

func printAgentRun(r agent.Record) {
	how := "the declaration was walked, with no model"
	if r.Model != "" {
		how = "decided by " + r.Model
	}
	fmt.Printf("%s%s%s  %s  %s\n", bold, r.Agent, reset,
		r.OutcomeAt(time.Now().UTC()), r.Goal)
	fmt.Printf("  %sstarted by %s, %s; %s%s\n", dim, r.By,
		r.Started.Format("2 Jan 2006 15:04 UTC"), how, reset)
	if r.From != "" {
		fmt.Printf("  %srun again from %s%s\n", dim, r.From, reset)
	}
	for _, st := range r.Trace.Steps {
		what := st.Action.Op
		switch {
		case st.Action.Tool != "":
			what = st.Action.Tool
		case st.Action.Delegate != "":
			what = "to " + st.Action.Delegate
		case st.Action.Done():
			what = "finished"
		}
		word, said := "done", st.Result
		switch {
		case !st.Allowed:
			word, said = "refused", st.Why
		case st.Err != "":
			word, said = "failed", st.Err
		}
		// One line each, and with nothing in it that moves the cursor: what
		// came back is content.
		fmt.Printf("  %2d  %-20s %-8s %s\n", st.N, what, word,
			truncate(printable(said), 100))
	}
	for _, a := range r.Answers {
		word := "declined"
		if a.Approve {
			word = "approved"
		}
		fmt.Printf("  %sstep %d %s by %s%s\n", dim, a.N, word, a.By, reset)
	}
	if w := r.Trace.Waiting; w != nil {
		printPending(r.ID, w)
	}
}

// printable is a string with control characters replaced, so that what an
// agent read cannot write to the terminal of whoever reads the run.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
}

func runAndStep(args []string, usage string) (string, int, error) {
	if len(args) != 2 {
		return "", 0, fmt.Errorf("usage: quilzo agent %s", usage)
	}
	n, err := strconv.Atoi(args[1])
	if err != nil || n < 0 {
		return "", 0, fmt.Errorf("%q is not a step", args[1])
	}
	return args[0], n, nil
}

func agentAnswer(root string, approve bool, args []string) error {
	word := "decline"
	if approve {
		word = "approve"
	}
	id, n, err := runAndStep(args, word+" RUN STEP")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), agentRunTime)
	defer cancel()
	rec, err := continueAgentRun(ctx, root, id,
		&agent.Verdict{N: n, Approve: approve}, resolveCaller(root, ""))
	if rec.ID != "" {
		printAgentRun(rec)
	}
	return err
}

func agentResumeCmd(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo agent resume RUN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), agentRunTime)
	defer cancel()
	rec, err := continueAgentRun(ctx, root, args[0], nil, resolveCaller(root, ""))
	if rec.ID != "" {
		printAgentRun(rec)
	}
	return err
}

func agentReplay(root string, args []string) error {
	id, n, err := runAndStep(args, "replay RUN STEP")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), agentRunTime)
	defer cancel()
	newID, err := replayAgentRun(ctx, root, id, n, resolveCaller(root, ""))
	if newID != "" {
		if rec, lerr := loadAgentRun(root, newID); lerr == nil {
			printAgentRun(rec)
		}
		fmt.Printf("  %skept as %s%s\n", dim, newID, reset)
	}
	return err
}
