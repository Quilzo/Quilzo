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
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/decide"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/store"
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
	// The run's step is the record of what its decider answered.
	if asked := auditFor(t, root, "decide.asked"); len(asked) != 0 {
		t.Errorf("a decide step in a run was recorded twice: %+v", asked)
	}
}

// An agent looking for the right operation in plain words is sent to the
// deciders when what it wants is a judgement. Asked for "triage a support
// ticket", quilzo_find put agent_activity first: every query word was
// matched as a substring, so "a" scored on almost every operation, and
// twice over on one whose name has an "a" in it.
func TestFindingADecisionInPlainWordsFindsTheDeciders(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, asAdmin("dana"), "templates")
	first := regexp.MustCompile(`(?m)^(\S+) — `)
	for query, want := range map[string]string{
		"triage a support ticket":     "decide",
		"classify a comment":          "decide",
		"route an incoming request":   "decide",
		"score a lead":                "decide",
		"which deciders are there":    "list_deciders",
		"what agents have been doing": "agent_activity",
		"list the pages":              "list_pages",
	} {
		params, _ := json.Marshal(map[string]any{"name": "quilzo_find", "arguments": map[string]any{"query": query}})
		resp := srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params})
		if resp.Error != nil {
			t.Fatal(resp.Error.Message)
		}
		b, _ := json.Marshal(resp.Result)
		var r struct{ Content []struct{ Text string } }
		_ = json.Unmarshal(b, &r)
		var got []string
		for _, m := range first.FindAllStringSubmatch(r.Content[0].Text, 3) {
			got = append(got, m[1])
		}
		if len(got) == 0 || got[0] != want {
			t.Errorf("%q found %v first, not %s", query, got, want)
		}
	}
}

// A decision asked for outside an agent's run is on the record: which
// decider, what it answered and how sure it was, whether a person has to
// decide, and who asked, from the command line, the Decisions screen and
// the agent interface alike. A single ask wrote nothing, so an automated
// decision about somebody's ticket left no trace. The state is somebody's
// words and is never written, only its digest; inside a run, the run's
// step is the record and nothing is written twice.
func TestADecisionAskedIsOnTheRecord(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
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
	const state = `{"body": "Refund please, Jo Bloggs, 07700 900123"}`
	if err := cmdDecide(root, []string{"ask", "ticket", state}); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	var st any
	_ = json.Unmarshal([]byte(state), &st)
	srv := buildMCP(root, s, asAdmin("dana"), "templates")
	if _, e := callTool(t, srv, "quilzo_read", "decide", map[string]any{"name": "ticket", "state": st}); e != nil {
		t.Fatal(e.Message)
	}
	screen := decidersCapability(root)
	d, _ := loadDecider(root, "ticket")
	m, _ := screen.Model("ticket")
	res, err := decide.Decide(context.Background(), d, m, st)
	if err != nil {
		t.Fatal(err)
	}
	screen.Asked("dana", res, st)

	got := auditFor(t, root, "decide.asked")
	if len(got) != 3 {
		t.Fatalf("%d asks are on the record, not 3: %+v", len(got), got)
	}
	digest := got[0].Detail["state_sha256"]
	for _, r := range got {
		if r.Resource != "/decide/ticket" || r.Detail["decider"] != "ticket" ||
			!strings.Contains(r.Detail["answers"], "queue=returns") || r.Detail["confidence"] != "0.90" ||
			r.Detail["escalated"] != "false" || r.Principal == "" || len(digest) != 64 || r.Detail["state_sha256"] != digest {
			t.Errorf("the record says %+v", r)
		}
		for _, k := range []string{"Refund", "Bloggs", "07700"} {
			for _, v := range r.Detail {
				if strings.Contains(v, k) {
					t.Errorf("the record holds the state: %+v", r.Detail)
				}
			}
		}
	}
}
