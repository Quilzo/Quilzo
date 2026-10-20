// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/posture"
)

// capturing is a chat completions server that keeps what it was sent, and
// answers with status when it is not zero.
type capturing struct {
	mu     sync.Mutex
	got    []map[string]any
	status int
}

func (c *capturing) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		c.mu.Lock()
		c.got = append(c.got, m)
		status := c.status
		c.mu.Unlock()
		if status != 0 {
			http.Error(w, "overloaded", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"{\"allow\": true}"}}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1"
}

func (c *capturing) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func (c *capturing) last() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.got[len(c.got)-1]
}

// A route added with no fields sends nothing beyond the conversation; one
// added with them sends them, under the names given, and says so.
func TestARouteSendsWhatItIsToldAndNothingElse(t *testing.T) {
	root := publishedShop(t)
	plain, reasoner := &capturing{}, &capturing{}
	for _, args := range [][]string{
		{"route", "add", "plain", "--url", plain.serve(t), "--model", "claude-opus-5-5"},
		{"route", "add", "reasoner", "--url", reasoner.serve(t), "--model", "o-big",
			"--max-tokens-field", "max_completion_tokens", "--temperature", "1", "--timeout", "300s", "--auto-tool-choice"},
	} {
		if err := cmdGateway(root, args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	for _, bad := range [][]string{
		{"route", "add", "x", "--url", "https://api.example/v1", "--model", "m", "--temperature", "warm"},
		{"route", "add", "x", "--url", "https://api.example/v1", "--model", "m", "--top-p", "0"},
		{"route", "add", "x", "--url", "https://api.example/v1", "--model", "m", "--max-tokens-field", "max_output"},
		{"route", "add", "x", "--url", "https://api.example/v1", "--model", "m", "--timeout", "1ms"},
	} {
		if err := cmdGateway(root, bad); err == nil {
			t.Errorf("%v was accepted", bad[6:])
		}
	}
	gw, cfg, err := modelGateway(root)
	if err != nil || gw == nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 2 || cfg.Routes[1].Params.Timeout != "300s" {
		t.Fatalf("%+v", cfg.Routes)
	}
	if _, err := gw.For("assist").Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"temperature", "top_p", "max_tokens", "max_completion_tokens"} {
		if _, ok := plain.last()[k]; ok {
			t.Errorf("a route that asked for nothing was sent %s", k)
		}
	}
	chat := gw.ForRoute("reasoner", "agent:x").(assist.Chatter)
	_, err = chat.Chat(context.Background(), assist.ChatRequest{MaxTokens: 50, ToolChoice: "required",
		Messages: []assist.ChatMessage{{Role: "user", Content: []assist.Part{{Type: "text", Text: "go"}}}},
		Tools:    []assist.ChatTool{{Type: "function", Function: assist.ToolFunction{Name: "click", Parameters: json.RawMessage(`{"type":"object"}`)}}}})
	if err != nil {
		t.Fatal(err)
	}
	got := reasoner.last()
	if got["max_completion_tokens"] != float64(50) || got["max_tokens"] != nil || got["temperature"] != float64(1) ||
		got["tool_choice"] != "auto" {
		t.Errorf("the reasoner was sent %v", got)
	}
}

// The reviewer is asked through the route the store names and no other:
// when that route cannot answer the run stops, rather than the first
// route, the agents' own model, quietly judging its own actions.
func TestTheReviewerIsTheRouteItNamesAndNoOther(t *testing.T) {
	root := publishedShop(t)
	first, second := &capturing{}, &capturing{status: http.StatusServiceUnavailable}
	for _, args := range [][]string{
		{"route", "add", "first", "--url", first.serve(t), "--model", "big"},
		{"route", "add", "second", "--url", second.serve(t), "--model", "other"},
	} {
		if err := cmdGateway(root, args); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdConfig(root, []string{"set", "agent.reviewer", "nowhere"}); err == nil ||
		!strings.Contains(err.Error(), "no route called nowhere") {
		t.Errorf("a reviewer naming no route was accepted: %v", err)
	}
	if err := cmdConfig(root, []string{"set", "agent.reviewer", "second"}); err != nil {
		t.Fatal(err)
	}
	m, why := reviewerModel(root, "second", "triage", personConsumer(human("dana"))...)
	if m == nil {
		t.Fatal(why)
	}
	if _, err := m.Complete(context.Background(), "s", "u"); !errors.Is(err, gateway.ErrNoRoute) {
		t.Fatalf("err = %v", err)
	}
	if first.calls() != 0 || second.calls() == 0 {
		t.Errorf("the review went to the first route (%d calls) instead of the one named (%d)", first.calls(), second.calls())
	}
	if m, why := reviewerModel(root, "nowhere", "triage"); m != nil || !strings.Contains(why, "nowhere") {
		t.Errorf("an undeclared reviewer: %v %q", m, why)
	}
	events, _ := audit.Read(auditPath(root))
	facts := observeAI(root, "", events)
	if facts.Reviewer != "second" || facts.ReviewerFirst || facts.ReviewerMissing {
		t.Errorf("%+v", facts)
	}
	if err := cmdConfig(root, []string{"set", "agent.reviewer", "first"}); err != nil {
		t.Fatal(err)
	}
	if facts := observeAI(root, "", events); !facts.ReviewerFirst {
		t.Error("a reviewer on the route every agent tries first was not seen")
	}
	if err := cmdGateway(root, []string{"route", "remove", "first"}); err != nil {
		t.Fatal(err)
	}
	if facts := observeAI(root, "", events); !facts.ReviewerMissing {
		t.Error("a reviewer naming a removed route was not seen")
	}
}

// A model call somebody set off is charged to them as well as to its
// caller, so a budget on person:NAME bounds drafts as well as runs; a
// service, a model or an agent acting as itself is nobody's person.
func TestAModelCallIsChargedToThePersonWhoAskedForIt(t *testing.T) {
	ai := human("model-x")
	ai.Kind = audit.KindAI
	svc := human("ci")
	svc.Kind = audit.KindService
	unverified := human("dana")
	unverified.Verified = false
	unrecorded := human("lee")
	unrecorded.Kind = ""
	for c, want := range map[*Caller]string{human("dana"): "person:dana", ai: "", svc: "",
		human(agent.PrincipalPrefix + "triage"): "", unverified: "", unrecorded: "person:lee", nil: ""} {
		if got := strings.Join(personConsumer(c), ","); got != want {
			t.Errorf("%+v: %q, want %q", c, got, want)
		}
	}
	root := publishedShop(t)
	up := &capturing{}
	for _, args := range [][]string{
		{"route", "add", "up", "--url", up.serve(t), "--model", "m"},
		{"budget", "person:dana", "--chars-per-day", "10"},
	} {
		if err := cmdGateway(root, args); err != nil {
			t.Fatal(err)
		}
	}
	m, why := draftModelFor(root, human("dana"), "draft")
	if m == nil {
		t.Fatal(why)
	}
	if _, err := m.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Complete(context.Background(), "s", "u"); !errors.Is(err, gateway.ErrBudget) {
		t.Errorf("a draft was not charged to the person who asked for it: %v", err)
	}
}

// The posture rule names a reviewer that is not a second model.
func TestPostureNamesAReviewerThatIsNotASecondModel(t *testing.T) {
	var rule posture.Rule
	for _, r := range posture.Rules() {
		if r.ID == "agent.reviewer-not-second" {
			rule = r
		}
	}
	if rule.Check == nil {
		t.Fatal("no rule")
	}
	for _, c := range []struct {
		facts posture.AIFacts
		want  string
	}{
		{posture.AIFacts{Reviewer: "first", ReviewerFirst: true}, "tries first"},
		{posture.AIFacts{Reviewer: "gone", ReviewerMissing: true}, "no route by that name"},
		{posture.AIFacts{Reviewer: "second"}, ""},
		{posture.AIFacts{}, ""},
	} {
		got := rule.Check(posture.State{AI: c.facts})
		if c.want == "" && len(got) != 0 || c.want != "" && (len(got) != 1 || !strings.Contains(got[0].Detail, c.want)) {
			t.Errorf("%+v: %+v", c.facts, got)
		}
	}
}

// On the demonstration store, the whole of it: an agent's actions are
// chosen through the first route and reviewed through the route the store
// names, never the other way round; with the reviewer's route down, the
// run stops instead of the agent's own model reviewing its own action.
func TestOnTheDemoARunIsReviewedBySecondRouteOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	const reviewPrompt = "You review one action"
	var mu sync.Mutex
	actorReviewed, reviews, reviewerDown := 0, 0, false
	actor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		if strings.Contains(string(b), reviewPrompt) {
			actorReviewed++
		}
		mu.Unlock()
		choice := `{"op":"done","say":"finished"}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			choice = `{"op":"write_page","input":{"page":"welcome","fields":{"title":"Welcome","body":"Open nine to five."}}}`
		}
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(actor.Close)
	reviewer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		down := reviewerDown
		if strings.Contains(string(b), reviewPrompt) {
			reviews++
		}
		mu.Unlock()
		if down {
			http.Error(w, "overloaded", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"yes - a welcome page serves the goal"}}]}`)
	}))
	t.Cleanup(reviewer.Close)
	for _, args := range [][]string{
		{"route", "add", "actor", "--url", actor.URL + "/v1", "--model", "stand-in"},
		{"route", "add", "second-opinion", "--url", reviewer.URL + "/v1", "--model", "another"},
	} {
		if err := cmdGateway(root, args); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdConfig(root, []string{"set", "agent.reviewer", "second-opinion"}); err != nil {
		t.Fatal(err)
	}
	if err := declareAgent(root, asker("tidy"), true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := loadAgentRun(root, id)
	if w := rec.Trace.Waiting; w == nil || w.Action.Op != "write_page" {
		t.Fatalf("the reviewed write did not reach the person: %+v", rec.Trace)
	}
	mu.Lock()
	if reviews == 0 || actorReviewed != 0 {
		t.Errorf("reviews through the second route %d, through the actor's %d", reviews, actorReviewed)
	}
	reviewerDown = true
	mu.Unlock()

	id, err = runAgentOnce(root, "tidy", "write a welcome page", true, asAdmin("dana"))
	stopped := err != nil && strings.Contains(err.Error(), "reviewer")
	if err == nil {
		rec, _ := loadAgentRun(root, id)
		b, _ := json.Marshal(rec.Trace)
		stopped = rec.Trace.Waiting == nil && strings.Contains(string(b), "reviewer could not be reached")
	}
	if !stopped {
		t.Errorf("a run went on with its reviewer down: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if actorReviewed != 0 {
		t.Error("with the reviewer down, the agent's own model reviewed its action")
	}
	if _, there := draftPage(t, root, "welcome"); there {
		t.Error("a page was written without a review")
	}
}
