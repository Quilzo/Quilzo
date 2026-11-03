// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/decide"
)

const ticketDecider = `{"name": "ticket", "title": "Ticket triage", "questions": [
  {"name": "queue", "ask": "Which team?", "kind": "choice", "options": ["billing", "returns"]}]}`

// TestADecisionGoesThroughTheGatewayOverHTTP.
func TestADecisionGoesThroughTheGatewayOverHTTP(t *testing.T) {
	root := publishedShop(t)
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":` +
			`"{\"answers\": {\"queue\": {\"value\": \"returns\", \"confidence\": 0.9}}}"}}]}`))
	}))
	defer model.Close()
	if err := cmdGateway(root, []string{"route", "add", "local", "--url", model.URL + "/v1", "--model", "m"}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "d.json")
	os.WriteFile(file, []byte(ticketDecider), 0o600)
	if err := cmdDecide(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	d, err := loadDecider(root, "ticket")
	if err != nil {
		t.Fatal(err)
	}
	m, why := deciderModel(root, "ticket")
	if m == nil {
		t.Fatal(why)
	}
	res, err := decide.Decide(context.Background(), d, m, map[string]any{"body": "refund please"})
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := res.Get("queue"); a.Escalate || a.Value != "returns" {
		t.Fatalf("%+v", res)
	}
	if err := cmdDecide(root, []string{"ask", "ticket", `{"body": "refund please"}`}); err != nil {
		t.Fatal(err)
	}
	// Recorded against the decider's own budget line.
	b, _ := os.ReadFile(usagePath(root))
	if !strings.Contains(string(b), `"consumer":"decider:ticket"`) {
		t.Fatalf("usage not recorded for the decider: %s", b)
	}
}

// pricedModels is a model server for a whole run: it answers an agent with
// what choose says, a reviewer yes, and a decider sure of its answer, and
// reports 1000 tokens for every call, which a route priced at 100 a million
// charges 0.10.
type pricedModels struct {
	mu     sync.Mutex
	choose func(prompt string) string
	// review answers the reviewer instead of yes, when set; reviews are the
	// prompts it was asked.
	review  func(prompt string) string
	reviews []string
	calls   map[string]int
}

func (p *pricedModels) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		prompt := string(b)
		who, content := "agent", ""
		switch {
		case strings.Contains(prompt, "You review one action"):
			who, content = "reviewer", "yes - it serves the goal"
		case strings.Contains(prompt, "You answer typed questions"):
			who, content = "decider", `{"answers":{"eligible":{"value":"yes","confidence":0.95}}}`
		}
		p.mu.Lock()
		if p.calls == nil {
			p.calls = map[string]int{}
		}
		p.calls[who]++
		switch {
		case who == "agent":
			content = p.choose(prompt)
		case who == "reviewer":
			p.reviews = append(p.reviews, prompt)
			if p.review != nil {
				content = p.review(prompt)
			}
		}
		p.mu.Unlock()
		out, _ := json.Marshal(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": content}}},
			"usage":   map[string]any{"prompt_tokens": 1000, "completion_tokens": 0}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1"
}

func (p *pricedModels) count(who string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[who]
}

func (p *pricedModels) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.calls {
		n += c
	}
	return n
}

// pricedGateway declares the actor's route and the reviewer's, both through
// models, each call at 0.10, and names the reviewer when asked to.
func pricedGateway(t *testing.T, root string, models *pricedModels, reviewed bool) {
	t.Helper()
	url := models.serve(t)
	for _, args := range [][]string{
		{"currency", "USD"},
		{"route", "add", "actor", "--url", url, "--model", "stand-in", "--price-in", "100", "--price-out", "100"},
		{"route", "add", "second-opinion", "--url", url, "--model", "another", "--price-in", "100", "--price-out", "100"},
	} {
		if err := cmdGateway(root, args); err != nil {
			t.Fatal(err)
		}
	}
	if !reviewed {
		return
	}
	if err := cmdConfig(root, []string{"set", "agent.reviewer", "second-opinion"}); err != nil {
		t.Fatal(err)
	}
}

// chargedTo reads the usage ledger for the calls made as consumer, and says
// how many there were and how many were charged to also as well.
func chargedTo(t *testing.T, root, consumer, also string) (calls, alsoCharged int) {
	t.Helper()
	f, err := os.Open(usagePath(root))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var u struct {
			Consumer string   `json:"consumer"`
			Also     []string `json:"also"`
		}
		if json.Unmarshal(sc.Bytes(), &u) != nil || u.Consumer != consumer {
			continue
		}
		calls++
		if slices.Contains(u.Also, also) {
			alsoCharged++
		}
	}
	return calls, alsoCharged
}

// What a decider and the reviewer cost is the run's, and was charged to
// nothing: a decide step of five samples cost five calls that the run's
// money budget never saw and its record priced at nothing, and the person
// who started the run was not charged for them either.
func TestADecidersAndTheReviewersCallsAreChargedToTheRunAndItsPerson(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	models := &pricedModels{choose: func(string) string {
		return `{"op":"decide","input":{"name":"refunds","state":"order 12 arrived broken"}}`
	}}
	pricedGateway(t, root, models, true)
	file := filepath.Join(t.TempDir(), "d.json")
	os.WriteFile(file, []byte(`{"name": "refunds", "title": "Refunds", "samples": 5, "questions": [
  {"name": "eligible", "ask": "Is the order eligible for a refund?", "kind": "yesno"}]}`), 0o600)
	if err := cmdDecide(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	triage := agent.Manifest{Name: "triage", Kind: agent.KindTask, Purpose: "Triage refund tickets",
		Capabilities: []string{"decide"}, Autonomy: agent.AutonomyDraft,
		Budget: agent.Budget{Steps: 3, Tools: 1, Duration: agent.Duration(time.Minute), Money: "0.30"}}
	if err := declareAgent(root, triage, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "triage", "triage ticket 12", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := loadAgentRun(root, id)
	if models.count("decider") == 0 || models.count("reviewer") == 0 {
		t.Fatalf("the run asked no decider or no reviewer: %v %+v", models.calls, rec.Trace)
	}
	if want := int64(models.total()) * 100_000; rec.Trace.Spent.Cost != want {
		t.Errorf("%d calls at 0.10 (%v) are recorded as a run that cost %d micros",
			models.total(), models.calls, rec.Trace.Spent.Cost)
	}
	if models.count("decider") > 5 {
		t.Errorf("with a money budget of 0.30, the decider was asked %d times at 0.10", models.count("decider"))
	}
	for _, consumer := range []string{"decider:refunds", "reviewer:triage"} {
		if calls, dana := chargedTo(t, root, consumer, "person:dana"); calls == 0 || dana != calls {
			t.Errorf("of %d calls as %s, %d were charged to the person who started the run", calls, consumer, dana)
		}
	}
}
