// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// notForAgents are the agent interface's operations a run does not
// perform, each with why: an administrator's reports, and what a run does
// another way.
var notForAgents = map[string]string{
	"agent_activity": "an administrator's report on agents themselves",
	"eval_results":   "an administrator's report on agents themselves",
	"inventory":      "an administrator's report",
	"policy_status":  "an administrator's report",
	"scan_content":   "an administrator's report",
	"shield_status":  "an administrator's report",
	"site_report":    "an administrator's report",
	"verify_store":   "an administrator's report",
	"export_site":    "the whole site at once; a run reads it page by page",
	"site_import":    "reaches another site, which a run does through the browser or the web it declares",
}

// Every operation of the agent interface is one a run performs, itself or
// through the interface, or is said here not to be and why: a new one is a
// decision, not something agents gain or miss by accident.
func TestEveryOperationIsAnAgentsOrSaysWhyNot(t *testing.T) {
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	native := map[string]bool{}
	for _, op := range agentexec.Performs() {
		native[op] = true
	}
	for _, op := range buildMCP(root, s, &Caller{Name: "test"}, "templates").Operations() {
		_, bridged := agentexec.Bridged[op.Name]
		_, refused := agentexec.Refuses()[op.Name]
		_, not := notForAgents[op.Name]
		switch {
		case native[op.Name] && bridged:
			t.Errorf("%s is performed twice over", op.Name)
		case native[op.Name] || bridged || refused || not:
		default:
			t.Errorf("%s is neither performed for an agent nor said not to be", op.Name)
		}
		if bridged && op.Publishes {
			t.Errorf("%s publishes, and a run publishes only by proposing", op.Name)
		}
		if w, ok := agentexec.Bridged[op.Name]; ok && w != op.Writes {
			t.Errorf("%s writes=%v there and %v here", op.Name, op.Writes, w)
		}
	}
	// And a declaration naming one that is not an agent's is refused when
	// it is written.
	m := agent.Manifest{Name: "nosy", Kind: agent.KindTask, Purpose: "look around",
		Capabilities: []string{"inventory"}, Autonomy: agent.AutonomyPropose,
		Budget: agent.Budget{Steps: 5, Tools: 1, Duration: agent.Duration(time.Minute)}}
	if err := m.Validate(knownCapabilities(root)); err == nil || !strings.Contains(err.Error(), "nothing an agent runs performs") {
		t.Errorf("%v", err)
	}
}

// A gardener: an agent reads what a chatbot could not answer, through the
// agent interface, and drafts the page that answers it.
func TestAGardenerDraftsWhatAChatbotCouldNotAnswer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	declaredAutonomy(t, root)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help"}); err != nil {
		t.Fatal(err)
	}
	keepGaps(t, root)
	cfg, _ := loadConfig(root)
	if err := cfg.Set("chatbot.gaps_agents", "true", "a gardener drafts the missing pages", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	gapKeeper(root)("help", "Do you engrave pens?")

	plan := []string{
		`{"op":"list_chatbot_gaps","input":{"name":"help"}}`,
		`{"op":"write_page","input":{"page":"engraving","fields":{"title":"Engraving","body":"We engrave pens with up to twelve letters, for £8."}}}`,
	}
	var mu sync.Mutex
	turn := 0
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		choice := `{"op":"done","say":"drafted the engraving page"}`
		if turn < len(plan) {
			choice = plan[turn]
		}
		turn++
		mu.Unlock()
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(model.Close)
	t.Setenv("QUILZO_MODEL_URL", model.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")

	m := agent.Manifest{Name: "gardener", Kind: agent.KindTask, Purpose: "Write the pages the chatbot is missing",
		Capabilities: []string{"list_chatbot_gaps", "write_page"}, Autonomy: agent.AutonomyDraft,
		Budget: agent.Budget{Steps: 6, Tools: 1, Duration: agent.Duration(time.Minute)}}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	_, out, err := runAgentKeptBy(context.Background(), root, "gardener", "draft what the help chatbot cannot answer",
		true, false, asAdmin("dana"))
	if err != nil || !out.Trace.Complete {
		t.Fatalf("%v\n%s", err, describeRun(out.Trace))
	}
	if r := out.Trace.Steps[0].Result; !strings.Contains(r, "Do you engrave pens?") {
		t.Fatalf("the gaps were not read: %q\n%s", r, describeRun(out.Trace))
	}
	s, _ := store.Open(root)
	draft, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := draft["engraving"]; !ok {
		t.Fatalf("no draft page: %s", describeRun(out.Trace))
	}
	live, _ := site.PagesAt(s, site.RefLive)
	if _, ok := live["engraving"]; ok {
		t.Fatal("the page went live without a person")
	}
}

// An agent that proposes does not write through the interface either,
// except to propose.
func TestAProposingAgentProposesThroughTheInterface(t *testing.T) {
	m := agent.Manifest{Name: "p", Kind: agent.KindTask, Purpose: "x",
		Capabilities: []string{"write_record", "propose_issue"}, Autonomy: agent.AutonomyPropose,
		Budget: agent.Budget{Steps: 5, Tools: 1, Duration: agent.Duration(time.Minute)}}
	sess := agent.NewSession(m, nil)
	var called []string
	perform := agentexec.WithPlatform(agentexec.Platform{Call: func(_ context.Context, op string, _ bool, _ map[string]any) (string, error) {
		called = append(called, op)
		return "ok", nil
	}}, sess, func(context.Context, agent.Action) (string, error) { return "", nil })
	if _, err := perform(context.Background(), agent.Action{Op: "write_record"}); err == nil {
		t.Error("a proposing agent wrote a record")
	}
	if _, err := perform(context.Background(), agent.Action{Op: "propose_issue"}); err != nil {
		t.Errorf("a proposing agent could not propose: %v", err)
	}
	if strings.Join(called, ",") != "propose_issue" {
		t.Errorf("%v", called)
	}
}

// A chatbot an agent asks in its run is the run's spending, and the
// person's who started it.
//
// ask_assistant is the one operation a run performs through the agent
// interface that asks a model (site_build drafts without one there, and the
// research operations read and compute). Its model was charged to the
// chatbot alone: a run with a money budget could ask a chatbot past it,
// its receipt priced the agent's own calls only, and the person who started
// it was not charged either.
func TestAChatbotAskedInARunIsChargedToTheRunAndItsPerson(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	var chatbot int
	models := &pricedModels{choose: func(prompt string) string {
		if strings.Contains(prompt, "You answer questions for visitors") {
			chatbot++
			return `{"answer": "", "action": null}`
		}
		return `{"op":"ask_assistant","input":{"name":"help","question":"can I return opened ink"}}`
	}}
	pricedGateway(t, root, models, false)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help", "--model"}); err != nil {
		t.Fatal(err)
	}
	asker := agent.Manifest{Name: "asker", Kind: agent.KindTask, Purpose: "Ask the help chatbot",
		Capabilities: []string{"ask_assistant"}, Autonomy: agent.AutonomyDraft,
		Budget: agent.Budget{Steps: 6, Tools: 6, Duration: agent.Duration(time.Minute), Money: "0.30"}}
	if err := declareAgent(root, asker, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	id, err := runAgentOnce(root, "asker", "see what the help chatbot says about returns", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := loadAgentRun(root, id)
	if chatbot == 0 {
		t.Fatalf("control: the run asked no chatbot: %v %+v", models.calls, rec.Trace)
	}
	if want := int64(models.total()) * 100_000; rec.Trace.Spent.Cost != want {
		t.Errorf("%d calls at 0.10 (%d of them the chatbot's) are recorded as a run that cost %d micros",
			models.total(), chatbot, rec.Trace.Spent.Cost)
	}
	if models.total() > 4 {
		t.Errorf("with a money budget of 0.30, the run made %d calls at 0.10", models.total())
	}
	if calls, dana := chargedTo(t, root, "chatbot:help", "person:dana"); calls == 0 || dana != calls {
		t.Errorf("of %d calls as chatbot:help, %d were charged to the person who started the run", calls, dana)
	}
}
