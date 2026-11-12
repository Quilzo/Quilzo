// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/chatact"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/event"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/research"
	"github.com/quilzo/quilzo/internal/shell"
	"github.com/quilzo/quilzo/internal/web"
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
	return startOnBlog(t, root, "poster")
}

// startOnBlog starts an agent as a page going live under /blog would, and
// returns its kept run.
func startOnBlog(t *testing.T, root, name string) agent.Record {
	t.Helper()
	s := triggerStart{Agent: name, Trigger: onBlog, Event: &event.Event{ID: "ev_1", Type: event.PagePublished,
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

// scoutStore is the identity store (dana and sam administer) with an agent
// dana answers for that reads one host on the web and is not declared to
// ask first, and a model that reads an address there with what it was
// given in the query, and is finished after. What reached the web is
// counted in read.
func scoutStore(t *testing.T) (root string, read *[]string) {
	t.Helper()
	root, _ = identityStore(t)
	declaredAutonomy(t, root)
	m := agent.Manifest{Name: "scout", Kind: agent.KindTask, Purpose: "Finds out what local bakeries bake",
		Capabilities: []string{"list_pages", "web_fetch"}, Autonomy: agent.AutonomyDraft,
		Web:    &agent.Web{Fetch: []string{"hartsbakery.co.uk"}},
		Budget: agent.Budget{Steps: 6, Tools: 1, Duration: agent.Duration(time.Minute)}}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	got := []string{}
	old := webGet
	webGet = func(_ context.Context, address string, _ func(*url.URL) error) (web.Page, error) {
		mu.Lock()
		got = append(got, address)
		mu.Unlock()
		return web.Page{URL: address, ContentType: "text/plain", Body: []byte("Rye is back on Fridays.")}, nil
	}
	t.Cleanup(func() { webGet = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"done","say":"read"}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			choice = `{"op":"web_fetch","input":{"url":"https://hartsbakery.co.uk/loaves?about=blog%2Fhello"}}`
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
	return root, &got
}

// A run nobody started does not reach another system through its hands on
// its own either. Its tools' writes were held, and its hands were not: an
// address read with web_fetch, whose path and query are the model's words,
// went to the host as soon as the model chose it, in a run a page going
// live had started.
func TestATriggeredRunsHandDoesNotReachOutOnItsOwn(t *testing.T) {
	root, read := scoutStore(t)
	rec := startOnBlog(t, root, "scout")
	if len(*read) != 0 {
		t.Fatalf("a run nobody started read the web without a person: %v\n%s", *read, describeRun(rec.Trace))
	}
	w := rec.Trace.Waiting
	if w == nil || w.Action.Op != "web_fetch" || !strings.HasPrefix(w.Why, agent.UnattendedPrefix) {
		t.Fatalf("the run did not wait at the read: %+v", rec.Trace)
	}
	// Never earned away, as a tool's send from such a run is not.
	if c := agent.CommitOf(w.Action, w.Why, agent.WaitAsk, false); c != "sends" {
		t.Errorf("a triggered run's reach out is classed as %q", c)
	}
	done, err := continueAgentRun(context.Background(), root, rec.ID,
		&agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if len(*read) != 1 || !done.Trace.Complete {
		t.Fatalf("after approval: %v %+v", *read, done.Trace)
	}
	// A run a person starts is not changed.
	*read = (*read)[:0]
	_, out, err := runAgentKept(context.Background(), root, "scout", "what is baked on Fridays?", true, asAdmin("dana"))
	if err != nil || len(*read) != 1 || out.Trace.Waiting != nil {
		t.Fatalf("a run a person started was held: %v %v %+v", err, *read, out.Trace.Waiting)
	}
}

// What a hand reaches may be let go unattended as a tool's write may: by
// two administrators, for what the declaration lets it reach when it is
// granted and no further.
func TestAHandIsGrantedUnattendedAsAToolIs(t *testing.T) {
	root, read := scoutStore(t)
	grant := []string{"scout", "grant", "web_fetch", "--why", "it reads the bakery's page as posts go live"}
	if err := agentSendsCmdAs(root, grant, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if err := agentSendsCmdAs(root, []string{"scout", "grant", "browser_open", "--why", "x"}, asAdmin("dana")); err == nil {
		t.Fatal("a grant was made for a hand the agent does not hold")
	}
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil || len(pend) != 1 || pend[0].Kind != dual.Sends {
		t.Fatalf("the grant did not wait for a second administrator: %v %+v", err, pend)
	}
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	flagToken = personToken(t, root, "sam", auth.RoleAdmin)
	if err := cmdPending(root, []string{"approve", pend[0].ID}); err != nil {
		t.Fatal(err)
	}
	if rec := startOnBlog(t, root, "scout"); len(*read) != 1 || rec.Trace.Waiting != nil || !rec.Trace.Complete {
		t.Fatalf("a granted hand still waited: %v %+v", *read, rec.Trace)
	}
	// Pointed further than it was granted, it waits again.
	set, _ := loadAgents(root)
	m := set.Agents["scout"]
	m.Web = &agent.Web{Fetch: []string{"hartsbakery.co.uk", "elsewhere.example"}}
	if err := declareAgent(root, m, false, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if rec := startOnBlog(t, root, "scout"); len(*read) != 1 || rec.Trace.Waiting == nil {
		t.Fatalf("a grant for one host let the hand reach another unattended: %v", *read)
	}
}

// Every hand that carries the model's words out of a run nobody started
// waits, as the exfiltration breaker reads them: an address opened or read,
// words typed into a page or an app, a search, and a command that reaches
// the network. What stays here does not, and nothing waits in a run a
// person started.
func TestEveryHandThatReachesOutWaitsInARunNobodyStarted(t *testing.T) {
	root, _ := identityStore(t)
	m := agent.Manifest{Name: "hands", Browser: &agent.Browser{Read: []string{"shop.example"}},
		Shell: &agent.Shell{Programs: []string{"curl", "ls"}, Hosts: []string{"api.example.com"}},
		Web:   &agent.Web{Any: true}, Cell: &agent.Cell{}}
	in := func(kv ...string) map[string]any {
		out := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			out[kv[i]] = kv[i+1]
		}
		return out
	}
	held := []agent.Action{
		{Op: "web_fetch", Input: in("url", "https://anywhere.example/?q=the+draft")},
		{Op: "web_search", Input: in("query", "the draft")},
		{Op: "browser_open", Input: in("url", "https://shop.example/?q=the+draft")},
		{Op: "browser_type", Input: in("ref", "e1", "text", "the draft")},
		{Op: "desktop_type", Input: in("text", "the draft")},
		{Op: "shell_run", Input: map[string]any{"program": "curl", "args": []any{"-d", "the draft", "https://api.example.com/"}}},
	}
	stays := []agent.Action{
		{Op: "shell_run", Input: map[string]any{"program": "ls", "args": []any{"-1"}}},
		{Op: "read_page", Input: in("page", "blog/hello")},
		{Op: "browser_read"},
		{Op: "file_write", Input: in("path", "notes.md", "text", "x")},
	}
	unattended, attended := outwardAsks(root, m, true, nil), outwardAsks(root, m, false, nil)
	for _, a := range held {
		why := unattended(a)
		if !strings.HasPrefix(why, agent.UnattendedPrefix) {
			t.Errorf("%s from a run nobody started went ahead: %q", a.Op, why)
		} else if c := agent.CommitOf(a, why, agent.WaitAsk, false); c != "sends" {
			t.Errorf("%s from a run nobody started is classed as %q, so it could be earned", a.Op, c)
		}
		if why := attended(a); why != "" {
			t.Errorf("%s from a run a person started waits: %q", a.Op, why)
		}
	}
	for _, a := range stays {
		if why := unattended(a); why != "" {
			t.Errorf("%s, which reaches nothing outside, waits: %q", a.Op, why)
		}
	}
	// A command with nowhere to reach runs with no network, and is not held.
	m.Shell.Hosts = nil
	if why := outwardAsks(root, m, true, nil)(held[len(held)-1]); why != "" {
		t.Errorf("a command with no host to reach waits: %q", why)
	}
}

// A command that reaches the network, from a run nobody started, through a
// real run in a real box: it waits for a person in the run's own process,
// and declined it never runs. Its declaration does not ask about the
// network, which is what let it go ahead.
func TestATriggeredRunsCommandDoesNotReachTheNetworkOnItsOwn(t *testing.T) {
	n := agentbox.Native{Exe: os.Args[0], Init: []string{"agentbox-init"}, Shim: []string{"agentbox-shim"}}
	if a := n.Check(); !a.OK {
		t.Skip("no box here: " + a.Why)
	}
	if _, err := shell.Find("curl"); err != nil {
		t.Skip("no curl here")
	}
	root, _ := identityStore(t)
	declaredAutonomy(t, root)
	testBackend = n
	t.Cleanup(func() { testBackend = nil })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"done","say":"sent"}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			choice = `{"op":"shell_run","input":{"program":"curl","args":["--max-time","2","-d","the post","https://api.example.com/"]}}`
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
	m := agent.Manifest{Name: "fetcher", Kind: agent.KindTask, Purpose: "Tells the shop's API about new posts",
		Capabilities: []string{"shell_run"}, Autonomy: agent.AutonomyDraft,
		Shell:  &agent.Shell{Programs: []string{"curl"}, Hosts: []string{"api.example.com"}},
		Budget: agent.Budget{Steps: 6, Tools: 1, Duration: agent.Duration(time.Minute)}}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	answered := answerAgentWhenAsked(t, root, "fetcher", false, "sam")
	rec := startOnBlog(t, root, "fetcher")
	if aerr := <-answered; aerr != nil {
		t.Fatalf("nobody was asked: %v\n%s", aerr, describeRun(rec.Trace))
	}
	if outs, _ := loadRunOutputs(root, rec.ID); len(outs) != 0 {
		t.Fatalf("a run nobody started reached the network with nobody asked: %+v", outs)
	}
	asked := false
	for _, st := range rec.Trace.Steps {
		asked = asked || (st.Action.Op == "shell_run" && strings.Contains(st.Why, "sam declined"))
	}
	if !asked {
		t.Fatalf("the command was not put to a person:\n%s", describeRun(rec.Trace))
	}
}

// A run nobody started does not search the open research indexes with the
// model's words on its own either. research_search carries its query to
// OpenAlex as web_search carries one to the search provider, and
// research_cite an identifier the model chose, and both went out at once
// from a run a page going live had started, as reading the store does.
func TestATriggeredRunsResearchDoesNotReachOutOnItsOwn(t *testing.T) {
	root, _ := identityStore(t)
	declaredAutonomy(t, root)
	m := agent.Manifest{Name: "librarian", Kind: agent.KindTask, Purpose: "Finds work on what the shop writes about",
		Capabilities: []string{"list_pages", "research_search"}, Autonomy: agent.AutonomyDraft,
		Budget: agent.Budget{Steps: 6, Tools: 1, Duration: agent.Duration(time.Minute)}}
	if err := declareAgent(root, m, true, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	asked := []string{}
	old := researchIndex
	researchIndex = func(string) research.Index {
		return research.Index{OpenAlex: "https://index.example", Get: func(_ context.Context, u string) ([]byte, int, error) {
			mu.Lock()
			asked = append(asked, u)
			mu.Unlock()
			return []byte(`{"results":[]}`), 200, nil
		}}
	}
	t.Cleanup(func() { researchIndex = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"done","say":"searched"}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			choice = `{"op":"research_search","input":{"query":"the draft of blog/hello"}}`
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
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(asked)
	}

	rec := startOnBlog(t, root, "librarian")
	if count() != 0 {
		t.Fatalf("a run nobody started searched the indexes without a person: %v\n%s", asked, describeRun(rec.Trace))
	}
	w := rec.Trace.Waiting
	if w == nil || w.Action.Op != "research_search" || !strings.HasPrefix(w.Why, agent.UnattendedPrefix) {
		t.Fatalf("the run did not wait at the search:\n%s", describeRun(rec.Trace))
	}
	if c := agent.CommitOf(w.Action, w.Why, agent.WaitAsk, false); c != "sends" {
		t.Errorf("a triggered run's search is classed as %q", c)
	}
	done, err := continueAgentRun(context.Background(), root, rec.ID, &agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
	if err != nil || count() != 1 || !done.Trace.Complete {
		t.Fatalf("after approval: %v %v\n%s", err, asked, describeRun(done.Trace))
	}
	// A citation is looked up at the index too.
	cite := agent.Action{Op: "research_cite", Input: map[string]any{"name": "p", "id": "doi:10.1/the-draft"}}
	if why := outwardAsks(root, m, true, nil)(cite); !strings.HasPrefix(why, agent.UnattendedPrefix) {
		t.Errorf("a triggered run's citation went ahead: %q", why)
	}
	// A run a person starts is not changed.
	if _, out, err := runAgentKept(context.Background(), root, "librarian", "what is written about rye?", true,
		asAdmin("dana")); err != nil || count() != 2 || out.Trace.Waiting != nil {
		t.Fatalf("a run a person started was held: %v %v\n%s", err, asked, describeRun(out.Trace))
	}
	// And it may be let go unattended as any hand may.
	if err := agentSendsCmdAs(root, []string{"librarian", "grant", "research_search", "--why", "it reads as posts go live"},
		asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil || len(pend) != 1 {
		t.Fatalf("%v %+v", err, pend)
	}
	t.Cleanup(func(old string) func() { return func() { flagToken = old } }(flagToken))
	flagToken = personToken(t, root, "sam", auth.RoleAdmin)
	if err := cmdPending(root, []string{"approve", pend[0].ID}); err != nil {
		t.Fatal(err)
	}
	if rec := startOnBlog(t, root, "librarian"); count() != 3 || rec.Trace.Waiting != nil {
		t.Fatalf("a granted search still waited: %v\n%s", asked, describeRun(rec.Trace))
	}
}
