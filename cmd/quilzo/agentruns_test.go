// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/evals"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/site"
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

// asker reads and may write a draft, and asks before it writes.
func asker(name string) agent.Manifest {
	return agent.Manifest{Name: name, Kind: agent.KindTask,
		Purpose:      "Tidy pages, asking before each change",
		Capabilities: []string{"list_pages", "write_page"},
		Autonomy:     agent.AutonomyDraft, AskFirst: []string{"write_page"},
		Retrieval: agent.Retrieval{Ref: "draft"},
		Budget: agent.Budget{Steps: 6, Tools: 2,
			Duration: agent.Duration(time.Minute)}}
}

func asAdmin(name string) *Caller {
	c := human(name)
	c.Role = "admin"
	return c
}

// waitingRun declares an agent that asks first and walks it until it asks.
func waitingRun(t *testing.T) (root, id string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root = demoStore(t)
	if err := declareAgent(root, asker("tidy"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "tidy", "", false, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Trace.Waiting == nil || rec.Trace.Waiting.Action.Op != "write_page" ||
		rec.OutcomeAt(time.Now()) != "waiting" || rec.State != "" {
		t.Fatalf("the run did not stop to ask: %+v", rec.Trace)
	}
	return root, id
}

func agentLog(root string) []string {
	events, _ := audit.Read(auditPath(root))
	var out []string
	for _, e := range events {
		if e.Action == "agent.approve" || e.Action == "agent.decline" {
			out = append(out, e.Action+" "+e.Detail["run"]+
				" "+e.Detail["step"]+" "+e.Detail["what"])
		}
	}
	return out
}

func TestAKeptRunWaitsForAPersonAndTheirAnswerIsOnRecord(t *testing.T) {
	root, id := waitingRun(t)
	before, _ := loadAgentRun(root, id)
	n := before.Trace.Waiting.N
	ctx := context.Background()
	yes := func() *agent.Verdict { return &agent.Verdict{N: n, Approve: true} }

	// A model does not answer for a person.
	ai := &Caller{Name: "agent/tidy", Kind: audit.KindAI, Verified: true, Role: "admin"}
	if _, err := continueAgentRun(ctx, root, id, yes(), ai); err == nil {
		t.Fatal("a model approved an agent's action")
	}
	// An answer to another step is not an answer to this one.
	if _, err := continueAgentRun(ctx, root, id,
		&agent.Verdict{N: n + 1, Approve: true}, asAdmin("sam")); err == nil {
		t.Fatal("an answer to another step was taken")
	}
	// Nor is "continue" an answer.
	if _, err := continueAgentRun(ctx, root, id, nil, asAdmin("sam")); err == nil {
		t.Fatal("a waiting run was continued without an answer")
	}
	after, _ := loadAgentRun(root, id)
	if after.Trace.Waiting == nil || len(after.Trace.Steps) != len(before.Trace.Steps) ||
		len(after.Answers) != 0 || len(agentLog(root)) != 0 {
		t.Fatalf("a refused answer changed the run: %+v %v", after.Trace, agentLog(root))
	}

	rec, err := continueAgentRun(ctx, root, id, yes(), asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID != id || rec.Trace.Waiting != nil || !rec.Trace.Complete {
		t.Fatalf("the approved run is %+v", rec.Trace)
	}
	step := rec.Trace.Steps[n-1]
	if step.Action.Op != "write_page" || !step.Allowed {
		t.Errorf("step %d after approval is %+v", n, step)
	}
	if len(rec.Answers) != 1 || rec.Answers[0].By != "sam" || !rec.Answers[0].Approve {
		t.Errorf("the answer is kept as %+v", rec.Answers)
	}
	if got := agentLog(root); len(got) != 1 ||
		got[0] != fmt.Sprintf("agent.approve %s %d write_page", id, n) {
		t.Errorf("the log says %v", got)
	}
	// It is the same run, kept under the same name, and who started it has
	// not changed.
	stored, _ := loadAgentRun(root, id)
	if stored.By != "dana" || len(stored.Trace.Steps) != len(rec.Trace.Steps) {
		t.Errorf("the stored run is by %s with %d steps", stored.By, len(stored.Trace.Steps))
	}
	// Answered once. A second click finds nothing waiting.
	if _, err := continueAgentRun(ctx, root, id, yes(), asAdmin("sam")); err == nil {
		t.Error("the same question was answered twice")
	}
	if len(agentLog(root)) != 1 {
		t.Errorf("the second answer is on record: %v", agentLog(root))
	}
	if _, err := os.Stat(filepath.Join(agentRunsDir(root), id+".lock")); err == nil {
		t.Error("the claim on the run was left behind")
	}
}

func TestADeclinedActionIsNotDoneAndTheRunCarriesOn(t *testing.T) {
	root, id := waitingRun(t)
	before, _ := loadAgentRun(root, id)
	n := before.Trace.Waiting.N
	rec, err := continueAgentRun(context.Background(), root, id,
		&agent.Verdict{N: n}, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	step := rec.Trace.Steps[n-1]
	if step.Allowed || step.Why != "sam declined this" || !rec.Trace.Complete {
		t.Errorf("the declined step is %+v, complete=%v", step, rec.Trace.Complete)
	}
	if got := agentLog(root); len(got) != 1 || !strings.HasPrefix(got[0], "agent.decline "+id) {
		t.Errorf("the log says %v", got)
	}
}

// Approval is not a way around the declaration, as it stands when the run
// is continued.
func TestAnApprovalDoesNotOutliveTheCapability(t *testing.T) {
	root, id := waitingRun(t)
	before, _ := loadAgentRun(root, id)
	n := before.Trace.Waiting.N
	narrowed := asker("tidy")
	narrowed.Capabilities, narrowed.AskFirst = []string{"list_pages"}, nil
	narrowed.Autonomy = agent.AutonomyPropose
	if err := declareAgent(root, narrowed, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	rec, err := continueAgentRun(context.Background(), root, id,
		&agent.Verdict{N: n, Approve: true}, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if step := rec.Trace.Steps[n-1]; step.Allowed || step.Action.Op != "write_page" {
		t.Fatalf("an approved write went through a declaration that no "+
			"longer holds it: %+v", step)
	}
}

func TestOnlyOneProcessContinuesARunAtATime(t *testing.T) {
	root, id := waitingRun(t)
	before, _ := loadAgentRun(root, id)
	release, err := holdAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := continueAgentRun(context.Background(), root, id,
		&agent.Verdict{N: before.Trace.Waiting.N, Approve: true}, asAdmin("sam")); err == nil {
		t.Fatal("a run somebody else holds was continued")
	}
	if after, _ := loadAgentRun(root, id); after.Trace.Waiting == nil {
		t.Fatal("the held run changed")
	}
	release()
	// A claim left by a process that died is taken over once it is old.
	lock := filepath.Join(agentRunsDir(root), id+".lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-agentRunHold - time.Minute)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := continueAgentRun(context.Background(), root, id,
		&agent.Verdict{N: before.Trace.Waiting.N, Approve: true}, asAdmin("sam")); err != nil {
		t.Fatalf("a stale claim blocked the run: %v", err)
	}
}

func TestAnInterruptedRunIsContinuedAndOthersAreNot(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := declareAgent(root, reader("answers"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "answers", "", false, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Finished: nothing to continue.
	if _, err := continueAgentRun(ctx, root, id, nil, asAdmin("sam")); err == nil {
		t.Fatal("a finished run was continued")
	}
	// As the process left it after its first step, some time ago.
	rec, _ := loadAgentRun(root, id)
	whole := len(rec.Trace.Steps)
	rec.Trace.Steps, rec.Trace.Complete, rec.Trace.Answer = rec.Trace.Steps[:1], false, ""
	rec.State = agent.Running
	b, _ := json.Marshal(rec)
	p := filepath.Join(agentRunsDir(root), id+".json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	// Still being written: somebody is working on it.
	if _, err := continueAgentRun(ctx, root, id, nil, asAdmin("sam")); err == nil {
		t.Fatal("a run in progress was continued by somebody else")
	}
	rec.Beat = time.Now().Add(-time.Hour)
	b, _ = json.Marshal(rec)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := continueAgentRun(ctx, root, id, nil, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Trace.Complete || len(got.Trace.Steps) != whole || got.State != "" ||
		got.Trace.Steps[1].Action.Op != "read_page" {
		t.Errorf("continued to %+v", got.Trace)
	}
}

func TestRunningAgainFromAStepIsANewRunThatSaysWhereItCameFrom(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := declareAgent(root, reader("answers"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, _ := runAgentOnce(root, "answers", "", false, asAdmin("dana"))
	first, _ := loadAgentRun(root, id)
	ctx := context.Background()

	newID, err := replayAgentRun(ctx, root, id, 1, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	again, _ := loadAgentRun(root, newID)
	if newID == id || again.From != id+"@1" || again.By != "sam" ||
		len(again.Trace.Steps) != len(first.Trace.Steps) || !again.Trace.Complete {
		t.Errorf("the new run is %+v", again)
	}
	// The step it kept is the one from the earlier run, not done again.
	if !again.Trace.Steps[0].At.Equal(first.Trace.Steps[0].At) {
		t.Error("the first step was performed again")
	}
	if same, _ := loadAgentRun(root, id); len(same.Trace.Steps) != len(first.Trace.Steps) || same.From != "" {
		t.Error("running again changed the earlier run")
	}
	for _, n := range []int{-1, len(first.Trace.Steps), 99} {
		if got, err := replayAgentRun(ctx, root, id, n, asAdmin("sam")); err == nil {
			t.Errorf("run again from step %d as %s", n, got)
		}
	}
	ai := &Caller{Name: "agent/answers", Kind: audit.KindAI, Verified: true, Role: "admin"}
	if _, err := replayAgentRun(ctx, root, id, 1, ai); err == nil {
		t.Error("a model ran an agent again")
	}
	if all, _ := listAgentRuns(root, "", 0); len(all) != 2 {
		t.Errorf("%d runs are kept", len(all))
	}
}

// A run is written as it goes, and says it is still going, so that one the
// process never finished can be told from one that ended.
func TestARunIsKeptAfterEveryStepAndSaysItIsStillGoing(t *testing.T) {
	root := t.TempDir()
	k := &keptRun{root: root, rec: agent.Record{ID: "run-20260930-0000beef",
		Agent: "answers", Goal: "g", By: "dana", Started: time.Now().UTC()}}
	k.checkpoint(agent.Trace{Agent: "answers", Goal: "g", Steps: []agent.Step{
		{N: 1, Action: agent.Action{Op: "read_page"}, Allowed: true,
			Result: strings.Repeat("x", agent.MaxStored*2)}}})
	rec, err := loadAgentRun(root, k.rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if rec.State != agent.Running || rec.OutcomeAt(now) != "running" ||
		len(rec.Trace.Steps) != 1 || rec.By != "dana" {
		t.Fatalf("mid-run it is kept as %+v", rec)
	}
	if len(rec.Trace.Steps[0].Result) > agent.MaxStored+8 {
		t.Error("a checkpoint kept the whole of what a step read")
	}
	if rec.OutcomeAt(now.Add(agent.StaleAfter+time.Minute)) != "interrupted" {
		t.Error("a run nobody has written for a while is not called interrupted")
	}
}

// standInModel answers as a model that wants to write one page and then
// says it is finished. It counts how often it was asked.
// declaredAutonomy has a store's model-driven agents act at the autonomy
// their manifests declare, for tests about something other than earning it.
func declaredAutonomy(t *testing.T, root string) {
	t.Helper()
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("agents.earned_autonomy", "false", "a test about approving writes, not about earning them", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
}

func standInModel(t *testing.T) *int {
	t.Helper()
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		asked++
		choice := `{"op":"done","say":"finished"}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			choice = `{"op":"write_page","input":{"page":"welcome","fields":` +
				`{"title":"Welcome","body":"Open nine to five."}}}`
		}
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("QUILZO_MODEL_URL", srv.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")
	return &asked
}

func draftPage(t *testing.T, root, name string) (map[string]any, bool) {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := pages[name].(map[string]any)
	return p, ok
}

// The whole of it, against a real store: a model proposes a write, nothing
// is written until a person agrees, and what is written is what was shown.
func TestAModelsWriteWaitsForAPersonAndThenIsExactlyWhatWasShown(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	asked := standInModel(t)
	declaredAutonomy(t, root)
	if err := declareAgent(root, asker("tidy"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := loadAgentRun(root, id)
	w := rec.Trace.Waiting
	if w == nil || w.Action.Op != "write_page" || rec.Model != "stand-in" {
		t.Fatalf("the run did not stop at the write: %+v", rec.Trace)
	}
	shown, _ := w.Action.Input["fields"].(map[string]any)
	if shown["body"] != "Open nine to five." {
		t.Fatalf("what is shown to the person is %#v", w.Action.Input)
	}
	if _, there := draftPage(t, root, "welcome"); there {
		t.Fatal("the page was written before anybody agreed")
	}
	before := *asked

	done, err := continueAgentRun(context.Background(), root, id,
		&agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	page, there := draftPage(t, root, "welcome")
	if !there || page["title"] != "Welcome" || page["body"] != "Open nine to five." {
		t.Fatalf("after approval the draft holds %#v", page)
	}
	if st := done.Trace.Steps[w.N-1]; !st.Allowed || st.Err != "" ||
		!strings.HasPrefix(st.Result, "wrote welcome") {
		t.Errorf("the approved step is %+v", st)
	}
	// The model was asked what comes next, and not asked again what to write.
	if *asked != before+1 || !done.Trace.Complete {
		t.Errorf("the model was asked %d more times", *asked-before)
	}
	// Still a draft: approving the write is not publishing it.
	s, _ := open(root)
	if live, _ := site.PagesAt(s, site.RefLive); live["welcome"] != nil {
		t.Error("an approved draft write is live")
	}
}

func TestADeclinedWriteLeavesTheDraftAlone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	standInModel(t)
	declaredAutonomy(t, root)
	if err := declareAgent(root, asker("tidy"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, _ := runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	rec, _ := loadAgentRun(root, id)
	if rec.Trace.Waiting == nil {
		t.Fatal("the run did not stop")
	}
	done, err := continueAgentRun(context.Background(), root, id,
		&agent.Verdict{N: rec.Trace.Waiting.N}, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if _, there := draftPage(t, root, "welcome"); there || !done.Trace.Complete {
		t.Fatal("a declined write was written")
	}
}

// `agent run NAME --model "goal"` uses the model, as the help shows it.
//
// The flags were parsed from the front only, so with the name first --model
// was taken as the goal and the run walked the manifest without a model —
// a run that looked like it had worked and had asked nobody.
func TestTheModelFlagWorksAfterTheAgentsName(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	asked := standInModel(t)
	declaredAutonomy(t, root)
	if err := declareAgent(root, asker("tidy"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", "")
	for _, args := range [][]string{
		{"tidy", "--model", "write a welcome page"},
		{"--model", "tidy", "write a welcome page"},
	} {
		before := *asked
		// Run with no identity, the agent is narrowed to reading, so the
		// stand-in's write is refused; what matters here is that it was
		// asked at all.
		_ = agentCheckRun(root, args)
		if *asked == before {
			t.Errorf("%q ran without asking the model", args)
		}
	}
	// A goal that was not quoted, or a flag after it, is refused rather
	// than half-read.
	for _, args := range [][]string{
		{"tidy", "--model", "write", "a", "page"},
		{"tidy", "write a page", "--model"},
	} {
		before := *asked
		err := agentCheckRun(root, args)
		if err == nil || !strings.Contains(err.Error(), "quote it") || *asked != before {
			t.Errorf("%q: %v, model asked %d time(s)", args, err, *asked-before)
		}
	}
}

// A page an agent wrote says a model wrote it, and who approved it.
//
// The write was stored with no provenance, so the one writer certain to have
// used a model left the page unmarked, and the publish gate refused it until
// somebody recorded its origin by hand.
func TestAnAgentsWriteIsMarkedAsModelWritten(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	standInModel(t)
	declaredAutonomy(t, root)
	if err := declareAgent(root, asker("tidy"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := loadAgentRun(root, id)
	if _, err := continueAgentRun(context.Background(), root, id,
		&agent.Verdict{N: rec.Trace.Waiting.N, Approve: true}, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	idx, err := loadProvenance(root)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := idx.Get("welcome")
	if !ok {
		t.Fatal("the page the agent wrote has no provenance")
	}
	if got.SourceType != provenance.TrainedAlgorithmicMedia || got.Model != "stand-in" ||
		got.Author != "sam" || got.ReviewedBy != "sam" ||
		!strings.Contains(got.Note, "tidy") || got.Instruction != "write a welcome page" {
		t.Errorf("the record is %+v", got)
	}
	// And it describes the bytes that were written, so the gate sees a mark
	// rather than a gap.
	s, _ := open(root)
	ids, _ := site.PageIDsAt(s, site.RefDraft)
	if got.ContentHash != ids["welcome"] {
		t.Errorf("the record names %s and the page is %s", got.ContentHash, ids["welcome"])
	}
}

// A model drives an agent only as far as its evaluations have earned: with
// none, its writes are not offered, and the run says why.
func TestAModelDrivesOnlyAsFarAsEvaluationsEarned(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	standInModel(t)
	if err := declareAgent(root, asker("tidy"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	out, _ := executeAgentFrom(context.Background(), root, "tidy", "write a welcome page", true, asAdmin("dana"), nil)
	if !strings.Contains(out.Earned, "never been evaluated") || out.Manifest.Autonomy != agent.AutonomyPropose {
		t.Fatalf("earned %q, autonomy %s", out.Earned, out.Manifest.Autonomy)
	}
	for _, c := range out.Manifest.Capabilities {
		if c == "write_page" {
			t.Fatal("an unevaluated model was offered a write")
		}
	}
	if _, ok := draftPage(t, root, "welcome"); ok {
		t.Fatal("an unevaluated model wrote")
	}
	// Walking the manifest decides nothing, and is not held back.
	walk, _ := executeAgentFrom(context.Background(), root, "tidy", "", false, asAdmin("dana"), nil)
	if walk.Earned != "" || walk.Manifest.Autonomy != agent.AutonomyDraft {
		t.Fatalf("a walk was capped: %q %s", walk.Earned, walk.Manifest.Autonomy)
	}
	// A clean evaluation earns drafting.
	rep := evals.Report{Agent: "tidy", At: time.Now(), Model: "stand-in", K: 3, Cases: 3, Reliable: 3, Planted: 3}
	if err := os.MkdirAll(filepath.Join(root, "evals", "results", "tidy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveEvalReport(root, rep); err != nil {
		t.Fatal(err)
	}
	out, _ = executeAgentFrom(context.Background(), root, "tidy", "write a welcome page", true, asAdmin("dana"), nil)
	if out.Earned != "" || out.Manifest.Autonomy != agent.AutonomyDraft {
		t.Fatalf("an earned draft was still capped: %q %s", out.Earned, out.Manifest.Autonomy)
	}
}

// Autonomy earned in evaluations is lost in behaviour: once the shield
// paused an agent, or agentwatch flagged it, a model drives it only to
// propose until it is evaluated again. A pause a person judged a mistake
// costs it nothing.
func TestAutonomyEarnedInEvaluationsIsLostInBehaviour(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	standInModel(t)
	if err := declareAgent(root, asker("tidy"), true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	evaluated := func(at time.Time) {
		t.Helper()
		rep := evals.Report{Agent: "tidy", At: at, Model: "stand-in", K: 3, Cases: 3, Reliable: 3, Planted: 3}
		if err := os.MkdirAll(filepath.Join(root, "evals", "results", "tidy"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := saveEvalReport(root, rep); err != nil {
			t.Fatal(err)
		}
	}
	run := func() agentOutcome {
		t.Helper()
		out, _ := executeAgentFrom(context.Background(), root, "tidy", "write a welcome page", true, asAdmin("dana"), nil)
		return out
	}
	evaluated(time.Now().Add(-2 * time.Hour))
	if out := run(); out.Manifest.Autonomy != agent.AutonomyDraft {
		t.Fatalf("evaluated, not drafting: %q", out.Earned)
	}

	// Paused by the shield an hour ago, and lifted since.
	p, _, err := shield.Apply(root, shield.Protection{Kind: shield.Agent, Target: "tidy", Reason: "followed a planted instruction",
		By: "shield", Auto: true, Until: time.Now().Add(time.Hour)}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shield.Lift(root, p.ID, "dana", time.Now()); err != nil {
		t.Fatal(err)
	}
	out := run()
	if out.Manifest.Autonomy != agent.AutonomyPropose || !strings.Contains(out.Earned, "the shield paused it") {
		t.Fatalf("after a pause: %s %q", out.Manifest.Autonomy, out.Earned)
	}
	evaluated(time.Now())
	if out := run(); out.Manifest.Autonomy != agent.AutonomyDraft {
		t.Fatalf("evaluated again after the pause, still capped: %q", out.Earned)
	}

	// Flagged by agentwatch after that evaluation.
	if err := noteFlagged(root, "tidy", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if out := run(); out.Manifest.Autonomy != agent.AutonomyPropose || !strings.Contains(out.Earned, "agentwatch flagged it") {
		t.Fatalf("after a flag: %s %q", out.Manifest.Autonomy, out.Earned)
	}
}

// A pause somebody judged a mistake is not held against the agent.
func TestAPauseJudgedAMistakeCostsNothing(t *testing.T) {
	root := shieldRoot(t)
	at := time.Now().Add(-time.Hour)
	p, _, err := shield.Apply(root, shield.Protection{Kind: shield.Agent, Target: "tidy", Reason: "x", By: "shield",
		Auto: true, Until: at.Add(time.Hour)}, at)
	if err != nil {
		t.Fatal(err)
	}
	if lost, _ := trustLost(root, "tidy"); !lost.Equal(p.At) {
		t.Fatalf("a pause was not counted: %v", lost)
	}
	if lost, _ := trustLost(root, "other"); !lost.IsZero() {
		t.Fatal("another agent's pause was held against it")
	}
	if _, err := shield.Judge(root, p.ID, shield.Mistake, "dana", time.Now()); err != nil {
		t.Fatal(err)
	}
	if lost, _ := trustLost(root, "tidy"); !lost.IsZero() {
		t.Fatalf("a mistaken pause was held against it: %v", lost)
	}
	if lost, _ := trustLost(root, "other"); !lost.IsZero() {
		t.Fatal("another agent's pause was held against it")
	}
}
