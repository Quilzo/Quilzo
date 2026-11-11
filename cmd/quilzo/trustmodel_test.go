// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/decide"
	"github.com/quilzo/quilzo/internal/evals"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/store"
)

// finishingModel is a provider that answers every turn by finishing, so a
// model-driven evaluation of an agent passes every case it is given.
func finishingModel(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"op\":\"done\",\"say\":\"finished\"}"}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1"
}

// routeTo declares the model gateway with one route.
func routeTo(t *testing.T, root, url, route, model string) {
	t.Helper()
	if err := gateway.Save(gatewayPath(root), &gateway.Config{
		Routes: []gateway.Route{{Name: route, URL: url, Model: model, Personal: true}}}); err != nil {
		t.Fatal(err)
	}
}

// humanOut collects what the commands print for a person.
func humanOut(t *testing.T) *bytes.Buffer {
	t.Helper()
	saved := w
	var b bytes.Buffer
	w = out.New(false)
	w.Out = &b
	t.Cleanup(func() { w = saved })
	return &b
}

// Trust earned on one model does not carry to another. An agent evaluated
// clean while one model drove it, through the gateway or the one model an
// install configures, kept its earned autonomy when the operator pointed
// its route at a model nobody had measured: the evaluation named the
// gateway's caller, "gateway:agent:NAME", which stays the same whatever
// the route reaches, and the check never asked which model was driving.
func TestAutonomyEarnedOnOneModelDoesNotCarryToAnother(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	url := finishingModel(t)
	routeTo(t, root, url, "main", "model-a")
	if err := declareAgent(root, asker("tidy"), true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < evals.DraftCases; i++ {
		if _, err := addEvalCase(root, "tidy", evals.Case{Goal: fmt.Sprintf("tidy page %d", i),
			Expect: evals.Expect{Finishes: true}}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := runEvaluation(root, "tidy", evals.DraftRuns, true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Model != "model-a" || rep.Route != "main" {
		t.Errorf("the evaluation says it measured %q through %q, not model-a through main", rep.Model, rep.Route)
	}
	run := func() agentOutcome {
		t.Helper()
		o, _ := executeAgentFrom(context.Background(), root, "tidy", "tidy the pages", true, asAdmin("dana"), nil)
		return o
	}
	if o := run(); o.Manifest.Autonomy != agent.AutonomyDraft {
		t.Fatalf("on the model it was measured on it does not draft: %s %q", o.Manifest.Autonomy, o.Earned)
	}

	// The operator points the same route at another model.
	routeTo(t, root, url, "main", "model-b")
	o := run()
	if o.Manifest.Autonomy != agent.AutonomyPropose {
		t.Fatalf("driven by a model nobody measured, it acts at %s", o.Manifest.Autonomy)
	}
	if !strings.Contains(o.Earned, "evaluated on model-a (route main); model-b (route main) is driving") {
		t.Errorf("the trace does not say why: %q", o.Earned)
	}
	if ok, why := evalsStillEarn(root, "tidy", time.Now().UTC()); ok || !strings.Contains(why, "model-b (route main) is driving") {
		t.Errorf("what it earned by approvals still counts: %v %q", ok, why)
	}
	if due := evalDue(root, "tidy", time.Now().UTC()); !strings.Contains(due, "model-b (route main)") {
		t.Errorf("it is not due to be measured again: %q", due)
	}
	b := humanOut(t)
	if err := cmdEval(root, []string{"show", "tidy"}); err != nil {
		t.Fatal(err)
	}
	if s := b.String(); !strings.Contains(s, "measured on model-a (route main), "+rep.At.Format("2 Jan 2006")) ||
		!strings.Contains(s, "model-b (route main) drives it now") {
		t.Errorf("eval show does not say what it measured and what drives it now:\n%s", s)
	}
	st, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	got, e := callTool(t, buildMCP(root, st, asAdmin("dana"), "templates"), "quilzo_read", "eval_results", map[string]any{})
	if e != nil {
		t.Fatal(e.Message)
	}
	var res struct {
		Agents []struct{ Model, Route, Due string }
	}
	if err := json.Unmarshal([]byte(got), &res); err != nil || len(res.Agents) != 1 ||
		res.Agents[0].Model != "model-a" || res.Agents[0].Route != "main" ||
		!strings.Contains(res.Agents[0].Due, "model-b (route main) is driving") {
		t.Errorf("eval_results does not name the model measured and what is due: %s", got)
	}

	// Measured again on the new model, it earns its autonomy back.
	if _, err := runEvaluation(root, "tidy", evals.DraftRuns, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if o := run(); o.Manifest.Autonomy != agent.AutonomyDraft {
		t.Fatalf("measured on model-b, it still does not draft: %q", o.Earned)
	}
	if due := evalDue(root, "tidy", time.Now().UTC()); due != "" {
		t.Errorf("measured on the model driving it, it is still due: %q", due)
	}

	// The one model an install configures without the gateway, the same.
	if err := os.Remove(gatewayPath(root)); err != nil {
		t.Fatal(err)
	}
	standInModel(t)
	rep = evals.Report{Agent: "tidy", At: time.Now(), Model: "stand-in", K: 3, Cases: 3, Reliable: 3, Planted: 3}
	if err := saveEvalReport(root, rep); err != nil {
		t.Fatal(err)
	}
	if o := run(); o.Manifest.Autonomy != agent.AutonomyDraft {
		t.Fatalf("on its own model it does not draft: %q", o.Earned)
	}
	t.Setenv("QUILZO_MODEL", "stand-in-2")
	if o := run(); o.Manifest.Autonomy != agent.AutonomyPropose ||
		!strings.Contains(o.Earned, "evaluated on stand-in; stand-in-2 is driving") {
		t.Fatalf("another configured model kept the autonomy: %s %q", o.Manifest.Autonomy, o.Earned)
	}
}

// lastAudited is the latest audit record of an action, nil for none.
func lastAudited(t *testing.T, root, action string) *audit.Event {
	t.Helper()
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var last *audit.Event
	for i := range evs {
		if evs[i].Action == action {
			last = &evs[i]
		}
	}
	return last
}

// A chatbot's evaluation names the model it measured. It was audited
// without one, so a public chatbot measured on one model counted as
// measured once it was moved to another nobody had measured, and nothing
// could say which model its figures were taken on.
func TestAChatbotEvaluationNamesItsModel(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	url := finishingModel(t)
	routeTo(t, root, url, "main", "model-a")
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help", "--public", "--model"}); err != nil {
		t.Fatal(err)
	}
	cases := filepath.Join(t.TempDir(), "cases.jsonl")
	if err := os.WriteFile(cases, []byte(`{"question": "can I return opened ink", "page": "returns"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := humanOut(t)
	// What the stand-in model answers is not what is measured here.
	_ = cmdAssistant(root, []string{"eval", "help", cases})
	if !strings.Contains(b.String(), "measured on model-a (route main), ") {
		t.Errorf("the evaluation does not say what it measured:\n%s", b)
	}
	if e := lastAudited(t, root, "assistant.evaluated"); e == nil || e.Detail["model"] != "model-a" || e.Detail["route"] != "main" {
		t.Fatalf("the record does not name the model measured: %+v", e)
	}
	if got := assistantsCapability(root).Measured("help"); !strings.HasPrefix(got, "measured on model-a (route main), ") {
		t.Errorf("the Chatbots screen is told %q", got)
	}
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if c := observeAI(root, "", evs).Chatbots; len(c) != 1 || c[0].EvalModel != "model-a (route main)" || c[0].Model != c[0].EvalModel {
		t.Errorf("posture is not told the model measured and the one answering: %+v", c)
	}
	// The operator points the route at another model.
	routeTo(t, root, url, "main", "model-b")
	if c := observeAI(root, "", evs).Chatbots; len(c) != 1 || c[0].EvalModel != "model-a (route main)" || c[0].Model != "model-b (route main)" {
		t.Errorf("posture is not told another model answers now: %+v", c)
	}
}

// A decider's evaluation is kept, with the model it measured and when. It
// kept nothing and left no record: what a decider's confidence means is a
// property of the model answering, and nobody could say when a decider
// was last measured, or on which model.
func TestADeciderEvaluationIsKept(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":` +
			`"{\"answers\": {\"queue\": {\"value\": \"returns\", \"confidence\": 0.9}}}"}}]}`))
	}))
	t.Cleanup(model.Close)
	routeTo(t, root, model.URL+"/v1", "main", "model-a")
	file := filepath.Join(t.TempDir(), "d.json")
	if err := os.WriteFile(file, []byte(ticketDecider), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDecide(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	cases := filepath.Join(t.TempDir(), "cases.jsonl")
	if err := os.WriteFile(cases, []byte(`{"state": {"body": "refund please"}, "expect": {"queue": "returns"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := humanOut(t)
	if err := cmdDecide(root, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "never evaluated") {
		t.Errorf("decide list does not say it was never evaluated:\n%s", b)
	}
	if err := cmdDecide(root, []string{"eval", "ticket", cases}); err != nil {
		t.Fatal(err)
	}
	m, ok := lastMeasurement(root, "decider", "ticket")
	if !ok || m.Model != "model-a" || m.Route != "main" || time.Since(m.At) > time.Minute || len(m.Report) == 0 {
		t.Fatalf("the evaluation was not kept with its model and date: %+v", m)
	}
	var rep decide.Report
	if err := json.Unmarshal(m.Report, &rep); err != nil || rep.Answers != 1 || rep.AutoRight != 1 {
		t.Errorf("the report kept is not the evaluation's: %+v %v", rep, err)
	}
	if e := lastAudited(t, root, "decider.evaluated"); e == nil || e.Detail["model"] != "model-a" || e.Detail["answers"] != "1" {
		t.Errorf("the evaluation is not on the record with its model: %+v", e)
	}
	want := "measured on model-a (route main), " + m.At.Format("2 Jan 2006")
	b.Reset()
	if err := cmdDecide(root, []string{"list"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), want) {
		t.Errorf("decide list does not say %q:\n%s", want, b)
	}
	if got := decidersCapability(root).Measured("ticket"); got != want {
		t.Errorf("the Decisions screen is told %q", got)
	}
	st, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	got, e := callTool(t, buildMCP(root, st, asAdmin("dana"), "templates"), "quilzo_read", "list_deciders", map[string]any{})
	if e != nil {
		t.Fatal(e.Message)
	}
	var listed []struct {
		Name     string
		Measured *struct{ At, By, Model, Route string }
	}
	if err := json.Unmarshal([]byte(got), &listed); err != nil || len(listed) != 1 || listed[0].Name != "ticket" ||
		listed[0].Measured == nil || listed[0].Measured.Model != "model-a" || listed[0].Measured.Route != "main" ||
		listed[0].Measured.At == "" {
		t.Errorf("list_deciders does not say when and on which model it was measured: %s", got)
	}
}

// twoRoutes declares the gateway with two routes in the order it falls
// back in: main, serving model-a, which finishes every run until it is told
// to fail and then answers as a provider that is down does; and backup,
// serving model-b, which writes a page on its first turn and counts what it
// is asked.
func twoRoutes(t *testing.T, root string) (mainDown *atomic.Bool, backupAsked *atomic.Int32) {
	t.Helper()
	mainDown, backupAsked = new(atomic.Bool), new(atomic.Int32)
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mainDown.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"op\":\"done\",\"say\":\"finished\"}"}}]}`))
	}))
	t.Cleanup(main.Close)
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		backupAsked.Add(1)
		choice := `{"op":"done","say":"finished"}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			choice = `{"op":"write_page","input":{"page":"welcome","fields":` +
				`{"title":"Welcome","body":"Written by a model nobody measured."}}}`
		}
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(backup.Close)
	if err := gateway.Save(gatewayPath(root), &gateway.Config{Routes: []gateway.Route{
		{Name: "main", URL: main.URL + "/v1", Model: "model-a", Personal: true},
		{Name: "backup", URL: backup.URL + "/v1", Model: "model-b", Personal: true},
	}}); err != nil {
		t.Fatal(err)
	}
	return mainDown, backupAsked
}

// eagerTidy is an agent that drafts without asking first, so what earned it
// draft is all that stands between a model and the draft.
func eagerTidy(t *testing.T, root string) {
	t.Helper()
	m := asker("tidy")
	m.AskFirst = nil
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < evals.DraftCases; i++ {
		if _, err := addEvalCase(root, "tidy", evals.Case{Goal: fmt.Sprintf("tidy page %d", i),
			Expect: evals.Expect{Finishes: true}}); err != nil {
			t.Fatal(err)
		}
	}
}

// A model the gateway falls back to does not drive an agent on what
// another earned. The run was bound at what the evaluation of model-a
// earned while model-a's route answered, and when that route stopped
// answering part way, the gateway asked the next, so model-b, which nobody
// had measured, chose the agent's actions at draft and wrote the page.
func TestAModelFallenBackToDoesNotDriveOnWhatAnotherEarned(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	mainDown, backupAsked := twoRoutes(t, root)
	eagerTidy(t, root)
	rep, err := runEvaluation(root, "tidy", evals.DraftRuns, true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Model != "model-a" || rep.Route != "main" || rep.Verdict() != "passing" || backupAsked.Load() != 0 {
		t.Fatalf("the evaluation did not measure model-a alone: %s, %s, backup asked %d time(s)",
			rep.Served(), rep.Verdict(), backupAsked.Load())
	}

	// model-a's provider goes down after the run is bound.
	mainDown.Store(true)
	o, _ := executeAgentFrom(context.Background(), root, "tidy", "tidy the pages", true, asAdmin("dana"), nil)
	if o.Manifest.Autonomy != agent.AutonomyDraft {
		t.Fatalf("bound while model-a answered, it does not draft: %s %q", o.Manifest.Autonomy, o.Earned)
	}
	if n := backupAsked.Load(); n != 0 {
		t.Errorf("model-b chose %d action(s) of a run at what model-a earned", n)
	}
	for _, st := range o.Trace.Steps {
		if st.Action.Op == "write_page" && st.Allowed {
			t.Errorf("a model nobody measured wrote at draft: %+v", st)
		}
	}
	if p, ok := draftPage(t, root, "welcome"); ok && strings.Contains(fmt.Sprint(p), "nobody measured") {
		t.Errorf("the draft holds what model-b wrote: %v", p)
	}
	if !strings.Contains(o.Trace.Stopped, "held to the route main") {
		t.Errorf("the run does not say why it did not go on with another model: %q", o.Trace.Stopped)
	}
}

// An evaluation measures the model it names and no other. Its report named
// the route the gateway would ask first, and every case whose call that
// route did not answer was answered by the next: model-a was reported
// passing, and earned draft, on what model-b did.
func TestAnEvaluationMeasuresOnlyTheModelItNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	mainDown, backupAsked := twoRoutes(t, root)
	eagerTidy(t, root)
	mainDown.Store(true)
	rep, err := runEvaluation(root, "tidy", evals.DraftRuns, true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if n := backupAsked.Load(); n != 0 || rep.Verdict() == "passing" {
		t.Errorf("the evaluation says %s was %s, and model-b answered %d call(s) of it",
			rep.Served(), rep.Verdict(), n)
	}
	if earned, why := evalsEarn(root, "tidy", time.Now()); earned != agent.AutonomyPropose {
		t.Errorf("model-a earned %s on what model-b did: %s", earned, why)
	}
}

// mainDownBackupCounted declares the gateway with a first route, main, serving model-a,
// whose provider is down, and a second, backup, serving model-b, which
// answers every call with content and counts them.
func mainDownBackupCounted(t *testing.T, root, content string) *atomic.Int32 {
	t.Helper()
	asked := new(atomic.Int32)
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(main.Close)
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": content}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(backup.Close)
	if err := gateway.Save(gatewayPath(root), &gateway.Config{Routes: []gateway.Route{
		{Name: "main", URL: main.URL + "/v1", Model: "model-a", Personal: true},
		{Name: "backup", URL: backup.URL + "/v1", Model: "model-b", Personal: true},
	}}); err != nil {
		t.Fatal(err)
	}
	return asked
}

// A chatbot's evaluation measures the model it names and no other. It
// named the route the gateway would ask first, and was answered by the
// next whenever that one did not answer, so the figures kept as model-a's
// were model-b's.
func TestAChatbotEvaluationMeasuresOnlyTheModelItNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	humanOut(t)
	asked := mainDownBackupCounted(t, root, "You can return it within thirty days.")
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help", "--public", "--model"}); err != nil {
		t.Fatal(err)
	}
	cases := filepath.Join(t.TempDir(), "cases.jsonl")
	if err := os.WriteFile(cases, []byte(`{"question": "can I return opened ink", "page": "returns"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = cmdAssistant(root, []string{"eval", "help", cases})
	m, ok := lastMeasurement(root, "chatbot", "help")
	if !ok || m.Model != "model-a" || m.Route != "main" {
		t.Fatalf("the evaluation is not kept as model-a's: %+v", m)
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("kept as model-a's, and model-b answered %d call(s) of it", n)
	}
}

// A decider's evaluation, the same.
func TestADeciderEvaluationMeasuresOnlyTheModelItNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	humanOut(t)
	asked := mainDownBackupCounted(t, root, `{"answers": {"queue": {"value": "returns", "confidence": 0.9}}}`)
	file := filepath.Join(t.TempDir(), "d.json")
	if err := os.WriteFile(file, []byte(ticketDecider), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdDecide(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	cases := filepath.Join(t.TempDir(), "cases.jsonl")
	if err := os.WriteFile(cases, []byte(`{"state": {"body": "refund please"}, "expect": {"queue": "returns"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = cmdDecide(root, []string{"eval", "ticket", cases})
	if m, ok := lastMeasurement(root, "decider", "ticket"); ok && (m.Model != "model-a" || m.Route != "main") {
		t.Fatalf("the evaluation is not kept as model-a's: %+v", m)
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("an evaluation of model-a, and model-b answered %d call(s) of it", n)
	}
}
