// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/chatact"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/evals"
	"github.com/quilzo/quilzo/internal/event"
	"github.com/quilzo/quilzo/internal/fetch"
)

// postingStore is the identity store (dana and sam administer) with a
// social account's REST API, whose post_update operation posts the text
// it is given, and an
// agent dana answers for that may call it and is not declared to ask
// first. What reached the far side is counted in posted.
func postingStore(t *testing.T) (root string, posted *[]string) {
	t.Helper()
	root, _ = identityStore(t)
	in := agent.Integration{Name: "social", Kind: agent.IntegrationHTTP, Enabled: true,
		Purpose: "post the shop's updates", Endpoint: "social.example", Uses: []string{"post_update"}, Writes: true,
		Operations: []agent.Operation{{Name: "post_update", Method: "POST", Path: "/posts",
			Params: []agent.OperationParam{{Name: "text", In: "query", Required: true}}}}}
	tools, err := newMCPClient(root).Tools(context.Background(), in)
	if err != nil || len(tools) != 1 {
		t.Fatalf("%v %+v", err, tools)
	}
	in.Pins = map[string]string{"post_update": tools[0].Definition}
	set := agent.Integrations{Declared: []agent.Integration{in}}
	if err := set.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(integrationsPath(root), set); err != nil {
		t.Fatal(err)
	}
	m := agent.Manifest{Name: "poster", Kind: agent.KindTask, Purpose: "posts the shop's updates",
		Autonomy: agent.AutonomyDraft, Capabilities: []string{"list_pages"},
		Tools:  []agent.Tool{{Name: "post_update", Host: "social.example", Purpose: "post an update"}},
		Budget: agent.Budget{Steps: 6, Tools: 3, Duration: agent.Duration(time.Minute)}}
	if err := declareAgent(root, m, true, false, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	// It has earned the draft its declaration asks for, on the model that
	// drives it here (postingModel's stand-in). Without an evaluation it
	// would run at propose, where a tool that writes asks its person first
	// whoever started the run (TestAnAgentThatEarnedNothingAsksItsPersonBeforeItPosts),
	// and these tests are about what is held because nobody started a run.
	earned := evals.Report{Agent: "poster", At: time.Now().UTC(), K: 3, Model: "stand-in",
		Cases: 3, Reliable: 3, Planted: 3}
	if err := os.MkdirAll(evalResultsDir(root, "poster"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveEvalReport(root, earned); err != nil {
		t.Fatal(err)
	}
	sent := []string{}
	restTransport = func(_ context.Context, method, u string, _ []byte, _ map[string]string) (*fetch.Result, error) {
		sent = append(sent, method+" "+u)
		return &fetch.Result{Status: 200, Body: []byte(`{"id":"p1"}`)}, nil
	}
	t.Cleanup(func() { restTransport = nil })
	return root, &sent
}

// postingModel stands in for a model that posts text through post_update
// first, and is finished after.
func postingModel(t *testing.T, text string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"done","say":"posted"}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			in, _ := json.Marshal(map[string]any{"op": "tool:post_update", "input": map[string]any{"text": text}})
			choice = string(in)
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
}

// startPoster starts poster as a page going live under /blog would, and
// returns its kept run.
func startPoster(t *testing.T, root string) agent.Record {
	t.Helper()
	s := triggerStart{Agent: "poster", Trigger: onBlog, Event: &event.Event{ID: "ev_1", Type: event.PagePublished,
		Pages: []string{"blog/hello"}}, Runner: asAdmin("sam")}
	id, err := startTriggered(context.Background(), root, s)
	if id == "" {
		t.Fatalf("the run did not start: %v", err)
	}
	rec, lerr := loadAgentRun(root, id)
	if lerr != nil {
		t.Fatal(lerr)
	}
	return rec
}

// A run nobody started does not post on its own. The manual says a
// triggered run can do no more than draft and propose, and that anything
// that goes out is a person's decision; the run was capped at the author
// role, but whether a call asked first was read from ask_first alone, so a
// tool that writes to another system and was not listed there was called
// as soon as the model chose it, with nobody asked.
func TestATriggeredRunsOutwardWriteWaitsForAPerson(t *testing.T) {
	root, posted := postingStore(t)
	postingModel(t, "Our new post is up")
	rec := startPoster(t, root)
	if len(*posted) != 0 {
		t.Fatalf("a run nobody started posted without a person: %v\n%+v", *posted, rec.Trace.Steps)
	}
	w := rec.Trace.Waiting
	if w == nil || w.Action.Tool != "post_update" || !strings.Contains(w.Why, "nobody started") {
		t.Fatalf("the run did not wait at the post: %+v", rec.Trace)
	}
	// Never earned away: a kind of call approved often enough by hand still
	// waits when it is a triggered run's send.
	if c := agent.CommitOf(w.Action, w.Why, agent.WaitAsk, true); c != "sends" {
		t.Errorf("a triggered run's send is classed as %q, so it could be earned or batched", c)
	}
	// A person lets it go ahead, and it is what they were shown.
	done, err := continueAgentRun(context.Background(), root, rec.ID,
		&agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*posted) != 1 || !strings.Contains((*posted)[0], "Our+new+post+is+up") || !done.Trace.Complete {
		t.Fatalf("after approval: %v %+v", *posted, done.Trace)
	}
}

// An agent that has earned nothing runs at propose, and at propose a tool
// that writes to another system asks first, whoever started the run: a
// person decides on the post before it goes out (somebody other than the one
// who started the run, as for every step of a run that writes).
// Before, propose held only what an agent wrote to the site, so an agent
// nobody had evaluated posted to a social account the moment its model
// chose to, although its every write here waited to be proposed.
func TestAnAgentThatEarnedNothingAsksItsPersonBeforeItPosts(t *testing.T) {
	root, posted := postingStore(t)
	if err := os.RemoveAll(evalResultsDir(root, "poster")); err != nil {
		t.Fatal(err)
	}
	postingModel(t, "Our new post is up")
	id, out, err := runAgentKept(context.Background(), root, "poster", "post the news", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	w := out.Trace.Waiting
	if len(*posted) != 0 || w == nil || w.Action.Tool != "post_update" {
		t.Fatalf("an agent that earned nothing posted without asking: %v %+v", *posted, out.Trace)
	}
	if strings.Contains(w.Why, "nobody started") {
		t.Errorf("a run a person started was held as one nobody started: %q", w.Why)
	}
	done, err := continueAgentRun(context.Background(), root, id,
		&agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*posted) != 1 || !done.Trace.Complete {
		t.Fatalf("after a person agreed: %v %+v", *posted, done.Trace)
	}
}

// A run a person starts is not changed: its post goes ahead as its
// declaration says, since the person who asked for it is there.
func TestARunAPersonStartsStillPostsAsDeclared(t *testing.T) {
	root, posted := postingStore(t)
	postingModel(t, "Our new post is up")
	_, out, err := runAgentKept(context.Background(), root, "poster", "post the news", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*posted) != 1 || out.Trace.Waiting != nil {
		t.Fatalf("a run a person started was held: %v %+v", *posted, out.Trace.Waiting)
	}
}

// Letting an agent send unattended is two administrators' decision, with a
// reason, and recorded as the widening it is: one proposes it, it waits,
// and only once another approves does a triggered run's post go out with
// nobody asked. Taken back, the next one waits again.
func TestUnattendedSendsAreGrantedByASecondAdministrator(t *testing.T) {
	root, posted := postingStore(t)
	postingModel(t, "Our new post is up")
	grant := []string{"poster", "grant", "post_update", "--why", "the shop's updates go out as pages go live"}
	if err := agentSendsCmdAs(root, grant[:3], asAdmin("dana")); err == nil || !strings.Contains(err.Error(), "--why") {
		t.Fatalf("a grant with no reason was made: %v", err)
	}
	if err := agentSendsCmdAs(root, grant, human("kai")); err == nil {
		t.Fatal("somebody who administers nothing let an agent send unattended")
	}
	model := asAdmin("dana")
	model.Kind, model.Model = audit.KindAI, "mcp-client"
	if err := agentSendsCmdAs(root, grant, model); err == nil {
		t.Fatal("a model let an agent send unattended")
	}
	if err := agentSendsCmdAs(root, []string{"poster", "grant", "list_pages", "--why", "x"}, asAdmin("dana")); err == nil {
		t.Fatal("a grant was made for a tool the agent does not declare")
	}
	if err := agentSendsCmdAs(root, grant, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil || len(pend) != 1 || pend[0].Kind != dual.Sends || pend[0].Why == "" {
		t.Fatalf("the grant did not wait for a second administrator: %v %+v", err, pend)
	}
	if rec := startPoster(t, root); len(*posted) != 0 || rec.Trace.Waiting == nil {
		t.Fatalf("a grant one administrator proposed let the run post: %v", *posted)
	}
	// Not by the one who proposed it.
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	flagToken = personToken(t, root, "dana", auth.RoleAdmin)
	if err := cmdPending(root, []string{"approve", pend[0].ID}); err == nil {
		t.Fatal("the administrator who proposed it approved it")
	}
	flagToken = personToken(t, root, "sam", auth.RoleAdmin)
	if err := cmdPending(root, []string{"approve", pend[0].ID}); err != nil {
		t.Fatal(err)
	}
	evs, _ := audit.Read(auditPath(root))
	widened := false
	for _, e := range evs {
		widened = widened || (e.Action == "agent.changed" && strings.Contains(e.Detail["widened"], "post_update") &&
			e.Detail["proposed_by"] != "" && e.Detail["approved_by"] != "" && e.Detail["proposed_by"] != e.Detail["approved_by"])
	}
	if !widened {
		t.Fatalf("the grant was not recorded as a widening by two people: %+v", evs[len(evs)-3:])
	}
	if rec := startPoster(t, root); len(*posted) != 1 || rec.Trace.Waiting != nil || !rec.Trace.Complete {
		t.Fatalf("a granted tool still waited: %v %+v", *posted, rec.Trace)
	}
	// What it asks first still waits, grant or not.
	set, _ := loadAgents(root)
	m := set.Agents["poster"]
	m.AskFirst = []string{"post_update"}
	if err := declareAgent(root, m, false, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if rec := startPoster(t, root); len(*posted) != 1 || rec.Trace.Waiting == nil {
		t.Fatalf("a grant let a call the declaration asks first go out: %v", *posted)
	}
	m.AskFirst = nil
	if err := declareAgent(root, m, false, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	// Taken back, and it waits again.
	if err := agentSendsCmdAs(root, []string{"poster", "revoke", "post_update"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if rec := startPoster(t, root); len(*posted) != 1 || rec.Trace.Waiting == nil {
		t.Fatalf("a grant taken back still let the run post: %v", *posted)
	}
}

// An approval decides the step it was asked about, not the rest of the
// run: a triggered run taken on after one post was approved still waits at
// the next.
func TestATriggeredRunsNextPostWaitsAfterOneIsApproved(t *testing.T) {
	root, posted := postingStore(t)
	restTransport = func(_ context.Context, method, u string, _ []byte, _ map[string]string) (*fetch.Result, error) {
		*posted = append(*posted, method+" "+u)
		return &fetch.Result{Status: 200, Body: []byte(`{"id":"post-` + strconv.Itoa(len(*posted)) + `"}`)}, nil
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"done","say":"posted"}`
		switch {
		case strings.Contains(string(b), "post-2"):
		case strings.Contains(string(b), "post-1"):
			choice = `{"op":"tool:post_update","input":{"text":"And another"}}`
		case strings.Contains(string(b), "Nothing has been done yet"):
			choice = `{"op":"tool:post_update","input":{"text":"Our new post is up"}}`
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
	rec := startPoster(t, root)
	next, err := continueAgentRun(context.Background(), root, rec.ID,
		&agent.Verdict{N: rec.Trace.Waiting.N, Approve: true}, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*posted) != 1 || next.Trace.Waiting == nil || !strings.Contains(next.Trace.Waiting.Why, "nobody started") {
		t.Fatalf("the run's second post went out on the first one's approval: %v %+v", *posted, next.Trace)
	}
}

// A person who runs a triggered run again has started a run of their own,
// as its record says, and it is held only as a run they start is.
func TestAPersonsReplayOfATriggeredRunIsTheirs(t *testing.T) {
	root, posted := postingStore(t)
	postingModel(t, "Our new post is up")
	rec := startPoster(t, root)
	id, err := replayAgentRun(context.Background(), root, rec.ID, 0, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(*posted) != 1 || again.Trace.Waiting != nil || again.Trigger != "" {
		t.Fatalf("a person's replay was held as a run nobody started: %v %+v", *posted, again.Trace.Waiting)
	}
}

// A visitor's request to a public chatbot starts a run nobody here
// started either: the agent acts on its sponsor's authority with a
// stranger's words in its goal, and its record names the chatbot as what
// started it. Only a stretch taken on after a person answered it was held
// as one, so the post the visitor's request led to went out at once, and
// the same run's next post waited.
func TestAVisitorsRequestDoesNotPostOnItsOwn(t *testing.T) {
	root, posted := postingStore(t)
	postingModel(t, "Our new post is up")
	set, _ := assistant.Load(assistantsPath(root))
	if err := set.Put(assistant.Assistant{Name: "help", Title: "Help", Public: true,
		Actions: []assistant.Action{{Name: "share", Kind: assistant.Agent, Target: "poster",
			Description: "Tell the shop your news", Writes: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	res := runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("a", 32), Chatbot: "help",
		Action: "share"})
	if len(*posted) != 0 {
		t.Fatalf("a visitor's request posted without a person: %v", *posted)
	}
	if res.State != chatact.Waiting {
		t.Fatalf("the visitor was not told a person decides: %+v", res)
	}
}
