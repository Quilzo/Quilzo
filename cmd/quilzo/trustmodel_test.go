// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
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
