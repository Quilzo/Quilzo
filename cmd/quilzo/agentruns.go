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

// saveAgentRun keeps one run and returns its identifier.
func saveAgentRun(root string, out agentOutcome, goal string, withModel bool,
	by string) (string, error) {

	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := "run-" + out.Started.UTC().Format("20060102") + "-" +
		hex.EncodeToString(raw[:])
	model := ""
	if withModel {
		model = out.Model
	}
	rec := agent.Keep(id, by, model, out.Started, out.Trace, out.Receipt)
	if rec.Goal == "" {
		rec.Goal = goal
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(agentRunsDir(root), 0o700); err != nil {
		return "", err
	}
	if err := atomicfile.Write(filepath.Join(agentRunsDir(root), id+".json"),
		b, 0o600); err != nil {
		return "", err
	}
	return id, pruneAgentRuns(root)
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

// runAgentOnce runs a declared agent and keeps the run.
func runAgentOnce(root, name, goal string, withModel bool,
	caller *Caller) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if goal == "" && !withModel {
		goal = "check that this agent's declaration is enforceable"
	}
	if goal == "" {
		return "", fmt.Errorf("say what it should do. A model with nothing " +
			"asked of it chooses something")
	}
	out, runErr := executeAgent(ctx, root, name, goal, withModel, caller)
	if out.Manifest.Name == "" {
		return "", runErr
	}
	id, err := saveAgentRun(root, out, goal, withModel, caller.Name)
	if err != nil {
		return "", err
	}
	return id, runErr
}
