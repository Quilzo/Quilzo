// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
)

func reader(name string) agent.Manifest {
	return agent.Manifest{Name: name, Kind: agent.KindRetrieval,
		Purpose:      "Answer questions from what is published",
		Capabilities: []string{"list_pages", "read_page"},
		Autonomy:     agent.AutonomyPropose,
		Budget: agent.Budget{Steps: 6, Tools: 2,
			Duration: agent.Duration(time.Minute)}}
}

func TestAnAgentDeclaredFromAScreenIsValidatedStoredAndOnRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	dana := human("dana")

	if err := declareAgent(root, reader("answers"), true, dana); err != nil {
		t.Fatal(err)
	}
	set, err := loadAgents(root)
	if err != nil || set.Agents["answers"].Purpose == "" {
		t.Fatalf("the declaration was not stored: %v", err)
	}

	// A capability the machine interface does not offer is a typo or a wish.
	bad := reader("other")
	bad.Capabilities = append(bad.Capabilities, "shell_exec")
	if err := declareAgent(root, bad, true, dana); err == nil {
		t.Error("a capability nothing offers was declared")
	}
	// Propose-only and holding a write reads as safe and is not.
	bad = reader("other")
	bad.Capabilities = append(bad.Capabilities, "write_page")
	if err := declareAgent(root, bad, true, dana); err == nil {
		t.Error("a propose-only agent holding a write was declared")
	}
	// Declaring twice is not a way to replace one, and changing one that is
	// not there is not a way to declare it.
	if err := declareAgent(root, reader("answers"), true, dana); err == nil {
		t.Error("a second declaration of the same name was accepted")
	}
	if err := declareAgent(root, reader("ghost"), false, dana); err == nil {
		t.Error("changing an undeclared agent declared it")
	}
	// A supervisor that hands work to nobody declared.
	sup := reader("lead")
	sup.Kind, sup.Delegates = agent.KindSupervisor, []string{"nobody"}
	if err := declareAgent(root, sup, true, dana); err == nil {
		t.Error("an agent delegating to an undeclared one was declared")
	}
	// A model does not write its own permissions.
	ai := &Caller{Name: "agent/answers", Kind: audit.KindAI,
		Verified: true}
	wide := reader("answers")
	wide.Autonomy = agent.AutonomyPublish
	wide.Capabilities = append(wide.Capabilities, "publish")
	if err := declareAgent(root, wide, false, ai); err == nil {
		t.Error("a model widened an agent's declaration")
	}
	if err := withdrawAgent(root, "answers", ai); err == nil {
		t.Error("a model withdrew an agent")
	}
	set, _ = loadAgents(root)
	if len(set.Agents) != 1 || set.Agents["answers"].Autonomy != agent.AutonomyPropose {
		t.Fatalf("a refused declaration changed what is stored: %+v", set.Agents)
	}

	changed := reader("answers")
	changed.Budget.Steps = 9
	if err := declareAgent(root, changed, false, dana); err != nil {
		t.Fatal(err)
	}
	events, _ := audit.Read(auditPath(root))
	var seen []string
	for _, e := range events {
		if strings.HasPrefix(e.Action, "agent.") {
			seen = append(seen, e.Action+":"+e.Detail["agent"])
		}
	}
	if strings.Join(seen, " ") != "agent.declare:answers agent.changed:answers" {
		t.Errorf("the log says %v", seen)
	}
}

func TestAnAgentOthersHandWorkToIsNotWithdrawnFromUnderThem(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	dana := human("dana")
	if err := declareAgent(root, reader("answers"), true, dana); err != nil {
		t.Fatal(err)
	}
	sup, _ := agent.For(agent.KindSupervisor)
	lead := sup.Manifest
	lead.Name, lead.Delegates = "lead", []string{"answers"}
	if err := declareAgent(root, lead, true, dana); err != nil {
		t.Fatal(err)
	}
	if err := withdrawAgent(root, "answers", dana); err == nil {
		t.Fatal("an agent a supervisor delegates to was withdrawn")
	}
	if err := withdrawAgent(root, "lead", dana); err != nil {
		t.Fatal(err)
	}
	if err := withdrawAgent(root, "answers", dana); err != nil {
		t.Fatal(err)
	}
	if err := withdrawAgent(root, "answers", dana); err == nil {
		t.Error("withdrawing what is not declared succeeded")
	}
	if set, _ := loadAgents(root); len(set.Agents) != 0 {
		t.Errorf("still declared: %v", set.Agents)
	}
}

func TestARunIsKeptAndCanBeReadBack(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	dana := human("dana")
	dana.Role = "admin"
	if err := declareAgent(root, reader("answers"), true, dana); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "answers", "", false, dana)
	if err != nil {
		t.Fatal(err)
	}
	if !agent.ValidRecordID(id) {
		t.Fatalf("the run is called %q", id)
	}
	rec, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Agent != "answers" || rec.By != "dana" || rec.Model != "" ||
		len(rec.Trace.Steps) != 3 || rec.Trace.Steps[0].Action.Op != "list_pages" ||
		rec.Receipt.Kind != agent.KindRetrieval {
		t.Errorf("the kept run is %+v", rec)
	}
	for _, st := range rec.Trace.Steps {
		if len(st.Result) > agent.MaxStored+8 {
			t.Errorf("step %d kept %d bytes of what it read", st.N, len(st.Result))
		}
	}
	fi, err := os.Stat(filepath.Join(agentRunsDir(root), id+".json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the run file is %v %v", fi, err)
	}
	mine, _ := listAgentRuns(root, "answers", 0)
	none, _ := listAgentRuns(root, "somebody-else", 0)
	if len(mine) != 1 || len(none) != 0 {
		t.Errorf("listed %d of its own and %d of another's", len(mine), len(none))
	}

	// A model with nothing asked of it is not run, and an agent that is not
	// declared leaves no run behind.
	if _, err := runAgentOnce(root, "answers", "", true, dana); err == nil {
		t.Error("a model was run with no goal")
	}
	if id, err := runAgentOnce(root, "ghost", "anything", false, dana); err == nil || id != "" {
		t.Errorf("an undeclared agent ran as %q", id)
	}
	if all, _ := listAgentRuns(root, "", 0); len(all) != 1 {
		t.Errorf("%d runs are kept", len(all))
	}

	// An identifier is a file name.
	for _, bad := range []string{"../agents", "run-20260930-zzzzzzzz", "",
		id + "/../../agents"} {
		if _, err := loadAgentRun(root, bad); err == nil {
			t.Errorf("%q was read as a run", bad)
		}
	}
	// A file that says it is a different run is not served as this one.
	b, _ := os.ReadFile(filepath.Join(agentRunsDir(root), id+".json"))
	other := "run-20260101-0000beef"
	if err := os.WriteFile(filepath.Join(agentRunsDir(root), other+".json"), b,
		0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAgentRun(root, other); err == nil {
		t.Error("a run file copied under another name was read")
	}
	if all, _ := listAgentRuns(root, "", 0); len(all) != 1 {
		t.Errorf("one bad file changed the list to %d", len(all))
	}
}

func TestOldRunsGoFirstWhenThereAreTooMany(t *testing.T) {
	root := t.TempDir()
	dir := agentRunsDir(root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < MaxAgentRuns+3; i++ {
		p := filepath.Join(dir, fmt.Sprintf("run-20260901-%08x.json", i))
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		at := old.Add(time.Duration(i) * time.Second)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	// Something that is not a run is not counted and not removed.
	keep := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pruneAgentRuns(root); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != MaxAgentRuns+1 {
		t.Fatalf("%d files remain", len(entries))
	}
	for i := 0; i < 3; i++ {
		if _, err := os.Stat(filepath.Join(dir,
			fmt.Sprintf("run-20260901-%08x.json", i))); err == nil {
			t.Errorf("the oldest run %d was kept", i)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("a file that is not a run was removed")
	}
}
