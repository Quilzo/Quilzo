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
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/chatact"
	"github.com/quilzo/quilzo/internal/site"
)

// wideAgent is a manifest that asks for everything, so a narrowing has
// something to take away.
func wideAgent() agent.Manifest {
	return agent.Manifest{
		Name: "editor", Kind: agent.KindTask,
		Purpose:      "write and publish",
		Capabilities: []string{"list_pages", "read_page", "write_page", "publish"},
		Autonomy:     agent.AutonomyPublish,
		Retrieval:    agent.Retrieval{Ref: site.RefDraft},
		Budget: agent.Budget{
			Steps: 50, Tools: 10, Duration: agent.Duration(time.Hour)},
		HumanApproval: true,
	}
}

func asToken(role auth.Role, sc auth.Scope) *Caller {
	return &Caller{Name: "somebody", Role: role, Limits: sc}
}

// The hole. A token deliberately narrowed afterwards stopped mattering the
// moment its holder ran an agent.
func TestAReadOnlyTokenCannotRunAWritingAgent(t *testing.T) {
	got := narrowedBy(wideAgent(),
		asToken(auth.RolePublisher, auth.Scope{ReadOnly: true}))

	if got.Autonomy != agent.AutonomyPropose {
		t.Errorf("a read-only token produced autonomy %q", got.Autonomy)
	}
	for _, c := range got.Capabilities {
		if agent.IsWrite(c) {
			t.Errorf("a read-only token kept the writing capability %q", c)
		}
	}
	if got.Retrieval.Ref != site.RefLive {
		t.Errorf("a read-only token reads %q", got.Retrieval.Ref)
	}
}

// A reader's token cannot produce a draft, however the manifest is written.
func TestARoleCapsWhatAnAgentMayDo(t *testing.T) {
	for _, tc := range []struct {
		role auth.Role
		want agent.Autonomy
	}{
		{auth.RoleReader, agent.AutonomyPropose},
		{auth.RoleAuthor, agent.AutonomyDraft},
		{auth.RolePublisher, agent.AutonomyPublish},
		{auth.RoleAdmin, agent.AutonomyPublish},
	} {
		got := narrowedBy(wideAgent(), asToken(tc.role, auth.Scope{}))
		if got.Autonomy != tc.want {
			t.Errorf("%s gave autonomy %q, wanted %q",
				tc.role, got.Autonomy, tc.want)
		}
	}
	// And the capability list follows: a reader's agent holds no write.
	got := narrowedBy(wideAgent(), asToken(auth.RoleReader, auth.Scope{}))
	for _, c := range got.Capabilities {
		if agent.IsWrite(c) {
			t.Errorf("a reader's token kept %q", c)
		}
	}
}

// A token scoped to content types narrows what the agent may retrieve, in the
// same vocabulary — auth.Scope and agent.Retrieval both name content types.
func TestATypeScopedTokenNarrowsRetrieval(t *testing.T) {
	m := wideAgent()
	m.Retrieval.Types = []string{"article", "product", "policy"}

	got := narrowedBy(m, asToken(auth.RolePublisher,
		auth.Scope{Types: []string{"article", "product"}}))

	if strings.Join(got.Retrieval.Types, ",") != "article,product" {
		t.Errorf("types are %v", got.Retrieval.Types)
	}
}

// A token restricting nothing must not narrow a list to nothing. Empty means
// all on both sides, which is what makes this not a set intersection.
func TestAnUnscopedTokenLeavesTheManifestAlone(t *testing.T) {
	m := wideAgent()
	m.Retrieval.Types = []string{"article"}
	m.Retrieval.Locales = []string{"en"}

	got := narrowedBy(m, asToken(auth.RoleAdmin, auth.Scope{}))

	if len(got.Capabilities) != len(m.Capabilities) {
		t.Errorf("capabilities went from %v to %v", m.Capabilities, got.Capabilities)
	}
	if strings.Join(got.Retrieval.Types, ",") != "article" {
		t.Errorf("types are %v", got.Retrieval.Types)
	}
	if strings.Join(got.Retrieval.Locales, ",") != "en" {
		t.Errorf("locales are %v", got.Retrieval.Locales)
	}
	if got.Autonomy != agent.AutonomyPublish {
		t.Errorf("autonomy is %q", got.Autonomy)
	}
}

// Two restrictions that do not overlap permit nothing, and must say so with an
// empty list rather than a nil one — nil means "all" everywhere else in this
// struct, so returning it here would widen the thing being narrowed.
func TestDisjointScopesPermitNothing(t *testing.T) {
	m := wideAgent()
	m.Retrieval.Types = []string{"article"}

	got := narrowedBy(m, asToken(auth.RolePublisher,
		auth.Scope{Types: []string{"product"}}))

	if got.Retrieval.Types == nil {
		t.Fatal("disjoint type scopes produced nil, which reads as unrestricted")
	}
	if len(got.Retrieval.Types) != 0 {
		t.Errorf("disjoint type scopes produced %v", got.Retrieval.Types)
	}
}

// An unresolved caller refuses rather than permits. This is the case where the
// safe default matters most.
func TestNoCallerMeansNoAuthority(t *testing.T) {
	got := narrowedBy(wideAgent(), nil)
	if got.Autonomy != agent.AutonomyPropose {
		t.Errorf("a nil caller gave autonomy %q", got.Autonomy)
	}
	if got.Retrieval.Ref != site.RefLive {
		t.Errorf("a nil caller reads %q", got.Retrieval.Ref)
	}
}

// Narrowing must never add. Whatever the token says, the result is a subset of
// what the manifest declared.
func TestNarrowingOnlyEverRemoves(t *testing.T) {
	m := wideAgent()
	declared := map[string]bool{}
	for _, c := range m.Capabilities {
		declared[c] = true
	}

	for _, role := range []auth.Role{
		auth.RoleReader, auth.RoleAuthor, auth.RolePublisher, auth.RoleAdmin} {
		for _, sc := range []auth.Scope{
			{}, {ReadOnly: true}, {Types: []string{"article"}},
			{Locales: []string{"en"}}, {Types: []string{"nope"}, ReadOnly: true},
		} {
			got := narrowedBy(m, asToken(role, sc))
			for _, c := range got.Capabilities {
				if !declared[c] {
					t.Errorf("%s/%v gained the capability %q", role, sc, c)
				}
			}
			if !got.Autonomy.AtMost(m.Autonomy) {
				t.Errorf("%s/%v raised autonomy to %q", role, sc, got.Autonomy)
			}
			if got.Budget.Steps > m.Budget.Steps {
				t.Errorf("%s/%v raised the step budget to %d",
					role, sc, got.Budget.Steps)
			}
			if m.HumanApproval && !got.HumanApproval {
				t.Errorf("%s/%v dropped the approval requirement", role, sc)
			}
		}
	}
}

// The budget belongs to the agent. A token carries none, so capping by the
// caller would mean inventing a number.
func TestTheCallerDoesNotChangeTheBudget(t *testing.T) {
	m := wideAgent()
	got := narrowedBy(m, asToken(auth.RoleAdmin, auth.Scope{}))
	if got.Budget != m.Budget {
		t.Errorf("the budget became %+v from %+v", got.Budget, m.Budget)
	}
}

// A role that cannot write must not leave a writing capability in the list.
//
// Stripped rather than left for Session.check to refuse: both would be
// correct, and an agent that holds write_page and is refused every time it
// tries looks broken in a trace, while one that never held it reads as what
// it is.
func TestAWritingCapabilityIsRemovedAndNotJustRefused(t *testing.T) {
	got := narrowedBy(wideAgent(), asToken(auth.RoleReader, auth.Scope{}))
	for _, c := range got.Capabilities {
		if agent.IsWrite(c) {
			t.Errorf("a reader's agent still holds %q", c)
		}
	}
	// And the reads survive, or this narrowed to nothing and proved little.
	if len(got.Capabilities) == 0 {
		t.Fatal("a reader's agent holds nothing at all")
	}
}

// internal/agent spells "live" as its own constant because it deliberately
// does not import the store or the site. This is where the two are both
// visible, so this is where the drift is caught — and behaviourally rather
// than by comparing one constant against another, which would prove nothing.
func TestNarrowingToLiveMeansTheRealLiveRef(t *testing.T) {
	parent := agent.Manifest{Retrieval: agent.Retrieval{Ref: site.RefLive}}
	child := agent.Manifest{Retrieval: agent.Retrieval{Ref: site.RefDraft}}

	if got := parent.Narrow(child).Retrieval.Ref; got != site.RefLive {
		t.Fatalf("narrowing a draft agent by a live one gave %q, and "+
			"site.RefLive is %q — internal/agent's own spelling has drifted",
			got, site.RefLive)
	}
}

// A caller's silence about tools is not a caller forbidding them.
//
// Narrow intersects tool hosts, so a bound declaring none removed every tool
// from every agent — the same mistake the capability list made in boundOf
// before it was corrected, in the same function, one field along.
//
// Found by declaring a tool and watching `quilzo agent run` never try it: the
// probe walked the manifest, the manifest had a tool, and the session had
// none.
func TestACallerDoesNotStripAnAgentsTools(t *testing.T) {
	m := wideAgent()
	m.Tools = []agent.Tool{
		{Name: "lookup", Host: "api.example.com", Purpose: "customers"},
		{Name: "notify", Host: "hooks.example.org", Purpose: "alerts"},
	}

	for _, role := range []auth.Role{
		auth.RoleReader, auth.RoleAuthor, auth.RolePublisher, auth.RoleAdmin} {
		got := narrowedBy(m, asToken(role, auth.Scope{}))
		if len(got.Tools) != len(m.Tools) {
			t.Errorf("%s: the agent declared %d tool(s) and kept %d",
				role, len(m.Tools), len(got.Tools))
		}
	}
	// And a read-only token still keeps them: a tool call is not a write to
	// this store, and whether it may happen is autonomy's question. (A tool
	// that writes to another system is withheld from such a caller's run
	// by withholdWrites, which knows the store's integrations.)
	got := narrowedBy(m, asToken(auth.RolePublisher, auth.Scope{ReadOnly: true}))
	if len(got.Tools) != len(m.Tools) {
		t.Errorf("a read-only token stripped %d of %d tool(s)",
			len(m.Tools)-len(got.Tools), len(m.Tools))
	}
}

// And the session built from a narrowed manifest can still resolve them,
// which is the half that actually failed.
func TestANarrowedAgentCanStillReachItsHosts(t *testing.T) {
	m := wideAgent()
	m.Tools = []agent.Tool{
		{Name: "lookup", Host: "api.example.com", Purpose: "customers"}}

	got := narrowedBy(m, asToken(auth.RoleAuthor, auth.Scope{}))
	s := agent.NewSession(got, nil)
	if host := s.HostFor("lookup"); host != "api.example.com" {
		t.Errorf("the narrowed session resolves lookup to %q", host)
	}
	if err := s.MayCallTool("lookup", ""); err != nil {
		t.Errorf("a declared tool was refused after narrowing: %v", err)
	}
}

// Whether an agent reads what addresses an AI as it is comes from its
// declaration: a caller can neither turn it on nor, by saying nothing,
// turn it off.
func TestKeepingInstructionsIsTheDeclarationsChoice(t *testing.T) {
	for _, keep := range []bool{true, false} {
		m := wideAgent()
		m.Retrieval.KeepInstructions = keep
		if got := narrowedBy(m, asToken(auth.RolePublisher, auth.Scope{})).Retrieval.KeepInstructions; got != keep {
			t.Errorf("declared %v, ran with %v", keep, got)
		}
	}
}

// offeringModel stands in for a model that asks for post_update first,
// offered it or not, and is finished after. Whether a run's first prompt
// offered it is in offered.
func offeringModel(t *testing.T) (offered *bool) {
	t.Helper()
	var mu sync.Mutex
	was := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"done","say":"looked"}`
		if strings.Contains(string(b), "Nothing has been done yet") {
			choice = `{"op":"tool:post_update","input":{"text":"Our new post is up"}}`
			mu.Lock()
			was = was || strings.Contains(string(b), "tool:post_update")
			mu.Unlock()
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
	return &was
}

// readOnlyStore is postingStore with an access policy that grants nothing,
// as a store one person keeps has, where nothing refuses a read-only
// credential the run of an agent and its bound (boundManifest) is all that
// holds it to reading; and a token of dana's issued read-only.
func readOnlyStore(t *testing.T) (root string, posted *[]string, token string) {
	t.Helper()
	root, posted = postingStore(t)
	if err := saveJSON(policyPath(root), &auth.Policy{}); err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err = toks.IssueScoped("dana-ro", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin,
		auth.Scope{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, toks); err != nil {
		t.Fatal(err)
	}
	return root, posted, token
}

// A read-only caller is offered no tool that writes to another system, and
// one asked for anyway is refused, saying the run only reads. A tool call
// is not a write to this store, so the manifest's tools were kept whole for
// such a caller: a token issued read-only ran an agent whose model posted
// to a social account, with nobody asked.
func TestAReadOnlyCallerIsOfferedNoToolThatWrites(t *testing.T) {
	root, posted, token := readOnlyStore(t)
	offered := offeringModel(t)
	readOnly := resolveCaller(root, token)
	if !readOnly.Limits.ReadOnly {
		t.Fatalf("the token is not read-only: %+v", readOnly)
	}
	_, out, err := runAgentKept(context.Background(), root, "poster", "what is new?", true, readOnly)
	if err != nil {
		t.Fatalf("%v\n%s", err, describeRun(out.Trace))
	}
	if len(*posted) != 0 {
		t.Fatalf("a read-only caller's run posted: %v", *posted)
	}
	if *offered {
		t.Error("a read-only caller's run was offered a tool that writes")
	}
	refused := false
	for _, st := range out.Trace.Steps {
		refused = refused || (st.Action.Tool == "post_update" && !st.Allowed && strings.Contains(st.Why, "only reads"))
	}
	if !refused || !out.Trace.Complete {
		t.Fatalf("the write was not refused as one a read-only run may not make:\n%s", describeRun(out.Trace))
	}
	// Asked what such a run could do, the answer is the run's.
	if a, err := could(root, "poster", "tool:post_update", "", true, false, readOnly); err != nil || a.Could ||
		!strings.Contains(a.Why, "only reads") {
		t.Errorf("could: %v %+v", err, a)
	}
	// A caller who may write is offered it, as declared.
	*offered = false
	if _, out, err := runAgentKept(context.Background(), root, "poster", "post the news", true, asAdmin("dana")); err != nil ||
		len(*posted) != 1 || !*offered {
		t.Fatalf("a caller who may write was not offered the tool: %v %v %v\n%s", err, *posted, *offered,
			describeRun(out.Trace))
	}
}

// A chatbot's request that only looks things up is read-only too, and its
// run is offered no tool that writes. It was offered them, and a post the
// model chose waited for a person as a send from a run nobody started,
// though the request was one that changes nothing.
func TestAReadOnlyChatbotRequestIsOfferedNoToolThatWrites(t *testing.T) {
	root, posted, _ := readOnlyStore(t)
	offered := offeringModel(t)
	set, _ := assistant.Load(assistantsPath(root))
	if err := set.Put(assistant.Assistant{Name: "help", Title: "Help", Public: true,
		Actions: []assistant.Action{{Name: "news", Kind: assistant.Agent, Target: "poster",
			Description: "What the shop has posted"}}}); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	res := runChatAction(context.Background(), root, chatact.Request{ID: strings.Repeat("b", 32), Chatbot: "help",
		Action: "news"})
	if len(*posted) != 0 || *offered {
		t.Fatalf("a read-only request's run posted or was offered a write: %v %v", *posted, *offered)
	}
	runs, _ := listAgentRuns(root, "poster", 0)
	if len(runs) != 1 || runs[0].Trace.Waiting != nil || res.State == chatact.Waiting {
		t.Fatalf("a read-only request's post waited for a person rather than being refused: %+v %+v", res, runs)
	}
	// And its run is kept as one, so whoever takes it on reads only too.
	if !runs[0].ReadOnly {
		t.Error("a read-only request's run is not kept as read-only")
	}
	refused := false
	for _, st := range runs[0].Trace.Steps {
		refused = refused || (st.Action.Tool == "post_update" && !st.Allowed && strings.Contains(st.Why, "only reads"))
	}
	if !refused {
		t.Fatalf("the post was not refused as one a read-only run may not make:\n%s", describeRun(runs[0].Trace))
	}
}

// A read-only caller's run stays read-only when a person takes it on. A run
// that waited goes on as whoever answered it, and was bounded by them too:
// a token issued read-only started a run that asked first before reading,
// an administrator let the read go ahead, and the run went on offered the
// post, and made it, with the administrator's reach.
func TestAReadOnlyRunTakenOnStaysReadOnly(t *testing.T) {
	root, posted, token := readOnlyStore(t)
	set, _ := loadAgents(root)
	m := set.Agents["poster"]
	m.AskFirst = []string{"list_pages"}
	if err := declareAgent(root, m, false, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	// Reads the pages first, then posts, offered it or not, then is done.
	var mu sync.Mutex
	after := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"list_pages"}`
		if !strings.Contains(string(b), "Nothing has been done yet") {
			mu.Lock()
			after++
			choice = `{"op":"done","say":"posted"}`
			if after == 1 {
				choice = `{"op":"tool:post_update","input":{"text":"Our new post is up"}}`
			}
			mu.Unlock()
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

	id, out, err := runAgentKept(context.Background(), root, "poster", "what is new?", true, resolveCaller(root, token))
	w := out.Trace.Waiting
	if err != nil || w == nil || w.Action.Op != "list_pages" {
		t.Fatalf("the run did not wait to read: %v\n%s", err, describeRun(out.Trace))
	}
	done, err := continueAgentRun(context.Background(), root, id, &agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
	if err != nil {
		t.Fatalf("%v\n%s", err, describeRun(done.Trace))
	}
	if len(*posted) != 0 {
		t.Fatalf("a read-only caller's run posted once a person took it on: %v\n%s", *posted, describeRun(done.Trace))
	}
	refused := false
	for _, st := range done.Trace.Steps {
		refused = refused || (st.Action.Tool == "post_update" && !st.Allowed && strings.Contains(st.Why, "only reads"))
	}
	if !refused || !done.Trace.Complete {
		t.Fatalf("the post was not refused as one a read-only run may not make:\n%s", describeRun(done.Trace))
	}
	// A run a caller who may write started is taken on as before.
	*posted = (*posted)[:0]
	mu.Lock()
	after = 0
	mu.Unlock()
	id, out, err = runAgentKept(context.Background(), root, "poster", "post the news", true, asAdmin("dana"))
	if w = out.Trace.Waiting; err != nil || w == nil {
		t.Fatalf("%v\n%s", err, describeRun(out.Trace))
	}
	if done, err = continueAgentRun(context.Background(), root, id, &agent.Verdict{N: w.N, Approve: true},
		asAdmin("sam")); err != nil || len(*posted) != 1 {
		t.Fatalf("a run a writer started did not post once taken on: %v %v\n%s", err, *posted, describeRun(done.Trace))
	}
}

// A read-only caller's run reads the desktop and does not work it: no
// typing into an app, no pressing what the app shows, no key that sends.
//
// The browser was made read-only for such a caller and the desktop cell
// had no read-only mode, so a token issued read-only ran an agent that
// typed into an app and pressed its buttons. The cell's own declaration
// is kept as the browser's is: a caller says nothing about pictures.
func TestAReadOnlyCallerDoesNotWorkTheDesktop(t *testing.T) {
	m := wideAgent()
	m.Capabilities = append(m.Capabilities, agent.CellCapabilities[:]...)
	m.Cell = &agent.Cell{Pictures: true}
	got := narrowedBy(m, asToken(auth.RolePublisher, auth.Scope{ReadOnly: true}))
	held := map[string]bool{}
	for _, c := range got.Capabilities {
		held[c] = true
	}
	for _, c := range []string{"desktop_type", "desktop_press", "desktop_key"} {
		if held[c] {
			t.Errorf("a read-only caller's run holds %s", c)
		}
	}
	for _, c := range []string{"desktop_read", "desktop_look"} {
		if !held[c] {
			t.Errorf("a read-only caller's run lost %s, which only reads", c)
		}
	}
	if got.Cell == nil || !got.Cell.Pictures {
		t.Errorf("a read-only caller's run lost the cell's declaration: %+v", got.Cell)
	}
	// A caller who may write keeps the desktop as declared.
	wide := narrowedBy(m, asAdmin("dana"))
	if len(wide.Capabilities) != len(m.Capabilities) || wide.Cell == nil || !wide.Cell.Pictures {
		t.Errorf("a caller who may write was narrowed on the desktop: %v %+v", wide.Capabilities, wide.Cell)
	}
}

// A run confined by whoever started it stays confined when a wider person
// takes it on. A run that waited goes on as whoever answered it and was
// bounded by them alone: dana, an author confined to /about, started a
// run that asked before reading, sam, who holds the whole site, let the read
// go ahead, and the run went on to write the returns page, which dana may
// not touch. Letting one step go ahead decides that step and lends the run
// nothing more, as with a run whoever started could only read for.
func TestAConfinedRunTakenOnStaysConfined(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	m := asker("tidy")
	m.AskFirst = []string{"list_pages"}
	m.Budget.Tools = 4
	if err := declareAgent(root, m, true, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	// Reads the pages first, then writes the returns page and the about
	// page, then is done.
	var mu sync.Mutex
	after := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"list_pages"}`
		if !strings.Contains(string(b), "Nothing has been done yet") {
			mu.Lock()
			after++
			switch after {
			case 1:
				choice = `{"op":"write_page","input":{"page":"returns","fields":` +
					`{"title":"Not hers","body":"Returns are not hers to change.","updated":"2026-11-01"}}}`
			case 2:
				choice = `{"op":"write_page","input":{"page":"about","fields":{"title":"Hers"}}}`
			default:
				choice = `{"op":"done","say":"written"}`
			}
			mu.Unlock()
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

	dana := human("dana")
	dana.Role, dana.Scope = auth.RoleAuthor, "/about"
	id, out, err := runAgentKept(context.Background(), root, "tidy", "tidy the pages", true, dana)
	w := out.Trace.Waiting
	if err != nil || w == nil || w.Action.Op != "list_pages" {
		t.Fatalf("the run did not wait to read: %v\n%s", err, describeRun(out.Trace))
	}
	rec, err := loadAgentRun(root, id)
	if err != nil || rec.Bound == nil || rec.Bound.Scope != "/about" || rec.Bound.Role != string(auth.RoleAuthor) {
		t.Fatalf("the run does not keep its starter's bound: %v %+v", err, rec.Bound)
	}
	done, err := continueAgentRun(context.Background(), root, id, &agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
	if err != nil {
		t.Fatalf("%v\n%s", err, describeRun(done.Trace))
	}
	wrote := map[string]bool{}
	for _, st := range done.Trace.Steps {
		if st.Action.Op == "write_page" {
			page, _ := st.Action.Input["page"].(string)
			wrote[page] = st.Allowed && st.Err == ""
		}
	}
	if wrote["returns"] {
		t.Errorf("a run dana started wrote outside /about once sam took it on:\n%s", describeRun(done.Trace))
	}
	if !wrote["about"] {
		t.Errorf("a run dana started could not write inside /about once sam took it on:\n%s", describeRun(done.Trace))
	}
}

// Whoever takes a run on reaches no further than whoever started it: the
// lower role, the deeper part of the site, the types both hold; two
// reaches with nothing in common are refused, saying who may take it on;
// and a run kept before its starter's reach was is taken on as before.
func TestTakingARunOnIsBoundedByItsStarter(t *testing.T) {
	sam := asAdmin("sam")
	dana := &agent.Bound{Role: string(auth.RoleAuthor), Scope: "/docs", Types: []string{"Article", "faq"}}
	c, err := sam.within(dana)
	if err != nil || c.Role != auth.RoleAuthor || c.Scope != "/docs" || len(c.Limits.Types) != 2 || c.Name != "sam" {
		t.Fatalf("%v %+v", err, c)
	}
	deeper := asAdmin("sam")
	deeper.Scope, deeper.Limits.Types = "/docs/setup", []string{"article"}
	if c, err := deeper.within(dana); err != nil || c.Scope != "/docs/setup" || len(c.Limits.Types) != 1 {
		t.Fatalf("a narrower caller was widened: %v %+v", err, c)
	}
	blog := asAdmin("sam")
	blog.Scope = "/blog"
	if _, err := blog.within(dana); err == nil || !strings.Contains(err.Error(), "who holds /docs") {
		t.Errorf("a caller holding none of the run's part of the site took it on: %v", err)
	}
	blog.Scope, blog.Limits.Types = "", []string{"product"}
	if _, err := blog.within(dana); err == nil {
		t.Error("a caller holding none of the run's types took it on")
	}
	if c, err := sam.within(nil); err != nil || c != sam {
		t.Errorf("a run kept with no bound was narrowed: %v %+v", err, c)
	}
}

// A run made by running another again keeps what bounded it, in its own
// record, so whoever takes the new run on is held to it as well.
//
// Running a run again makes a new record, and that record kept neither
// its starter's reach nor that they could only read. So dana, an author
// confined to /about, ran her waiting run again, sam let the new run's
// read go ahead, and it wrote the returns page; and a run a read-only
// token ran again wrote a page once sam answered it. The run taken on was
// held to its starter; the same run run again and then taken on was held
// to nobody.
func TestARunRunAgainKeepsWhatBoundIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	m := asker("tidy")
	m.AskFirst = []string{"list_pages"}
	m.Budget.Tools = 4
	if err := declareAgent(root, m, true, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	// Reads the pages first, then writes the returns page and the about
	// page, then is done.
	var mu sync.Mutex
	after := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"list_pages"}`
		if !strings.Contains(string(b), "Nothing has been done yet") {
			mu.Lock()
			after++
			switch after {
			case 1:
				choice = `{"op":"write_page","input":{"page":"returns","fields":` +
					`{"title":"Not hers","body":"Returns are not hers to change.","updated":"2026-11-01"}}}`
			case 2:
				choice = `{"op":"write_page","input":{"page":"about","fields":{"title":"Hers"}}}`
			default:
				choice = `{"op":"done","say":"written"}`
			}
			mu.Unlock()
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

	// again starts a run as its starter, runs it again as them from its
	// beginning, and has sam take the new run on: the new run's record,
	// and the pages it then wrote.
	again := func(starter *Caller) (agent.Record, map[string]bool) {
		t.Helper()
		mu.Lock()
		after = 0
		mu.Unlock()
		ctx := context.Background()
		id, out, err := runAgentKept(ctx, root, "tidy", "tidy the pages", true, starter)
		if w := out.Trace.Waiting; err != nil || w == nil || w.Action.Op != "list_pages" {
			t.Fatalf("the run did not wait to read: %v\n%s", err, describeRun(out.Trace))
		}
		newID, err := replayAgentRun(ctx, root, id, 0, starter)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := loadAgentRun(root, newID)
		if err != nil || rec.Trace.Waiting == nil {
			t.Fatalf("the run made again did not wait to read: %v\n%s", err, describeRun(rec.Trace))
		}
		done, _ := continueAgentRun(ctx, root, newID, &agent.Verdict{N: rec.Trace.Waiting.N, Approve: true}, asAdmin("sam"))
		wrote := map[string]bool{}
		for _, st := range done.Trace.Steps {
			if st.Action.Op == "write_page" && st.Allowed && st.Err == "" {
				page, _ := st.Action.Input["page"].(string)
				wrote[page] = true
			}
		}
		return rec, wrote
	}

	dana := human("dana")
	dana.Role, dana.Scope = auth.RoleAuthor, "/about"
	rec, wrote := again(dana)
	if rec.Bound == nil || rec.Bound.Scope != "/about" || rec.Bound.Role != string(auth.RoleAuthor) {
		t.Errorf("a run dana ran again does not keep her reach: %+v", rec.Bound)
	}
	if wrote["returns"] || !wrote["about"] {
		t.Errorf("a run dana ran again, taken on by sam, wrote %v: only /about is hers", wrote)
	}

	reads := asAdmin("rae")
	reads.Limits.ReadOnly = true
	rec, wrote = again(reads)
	if !rec.ReadOnly {
		t.Error("a run a read-only caller ran again does not keep that they could only read")
	}
	if len(wrote) != 0 {
		t.Errorf("a run a read-only caller ran again, taken on by sam, wrote %v", wrote)
	}

	// Somebody wider running a confined run again is held to it too, and
	// the new record says so: sam cannot widen dana's run by running it
	// again and having it taken on.
	mu.Lock()
	after = 0
	mu.Unlock()
	id, _, err := runAgentKept(context.Background(), root, "tidy", "tidy the pages", true, dana)
	if err != nil {
		t.Fatal(err)
	}
	newID, err := replayAgentRun(context.Background(), root, id, 0, asAdmin("sam"))
	if err != nil {
		t.Fatal(err)
	}
	if rec, err := loadAgentRun(root, newID); err != nil || rec.Bound == nil || rec.Bound.Scope != "/about" ||
		rec.Bound.Role != string(auth.RoleAuthor) || rec.By != "sam" {
		t.Errorf("dana's run, run again by sam, is kept as %+v by %s: %v", rec.Bound, rec.By, err)
	}
}

// A caller who may only read by their role, a reader, does not work the
// desktop either, and nor does an agent whose own standing is a reader's.
//
// Read-only was read from the credential's limit alone. A token issued as
// a reader, which no declaration turns into a draft, ran an agent whose
// browser and workspace only read (boundManifest) and whose desktop was
// still typed into and pressed.
func TestACallerWhoOnlyReadsByRoleDoesNotWorkTheDesktop(t *testing.T) {
	m := wideAgent()
	m.Capabilities = append(m.Capabilities, agent.CellCapabilities[:]...)
	m.Cell = &agent.Cell{Pictures: true}
	got := narrowedBy(m, asToken(auth.RoleReader, auth.Scope{}))
	held := map[string]bool{}
	for _, c := range got.Capabilities {
		held[c] = true
	}
	for _, op := range []string{"desktop_type", "desktop_press", "desktop_key"} {
		if held[op] {
			t.Errorf("a reader's run holds %s", op)
		}
	}
	for _, op := range []string{"desktop_read", "desktop_look"} {
		if !held[op] {
			t.Errorf("a reader's run lost %s, which only reads", op)
		}
	}
	// An author may write, and their run keeps the desktop as declared.
	got = narrowedBy(m, asToken(auth.RoleAuthor, auth.Scope{}))
	acts := 0
	for _, c := range got.Capabilities {
		if agent.IsDesktop(c) {
			acts++
		}
	}
	if acts != len(agent.CellCapabilities) {
		t.Errorf("an author's run holds %d of the desktop's %d actions: %v", acts, len(agent.CellCapabilities), got.Capabilities)
	}
}

// A model held to proposing by its evaluations does not work the desktop
// either: it reads the screen and looks at it, as it reads pages in its
// browser and sends nothing through them.
//
// The desktop's acts were taken from a run by what its caller, or the
// agent's own standing, may do, and not by what its evaluations earned. A
// model nobody had evaluated was held to proposing whoever ran it: its
// writes were withheld and its browser only read, and it went on typing
// into the desktop's apps and pressing what they showed. An evaluation
// itself keeps the declaration, which is what it measures, and plays the
// desktop's acts against nothing; so does a walk, which no model decides.
func TestAModelHeldToProposingDoesNotWorkTheDesktop(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	m := asker("tidy")
	m.Capabilities = append(m.Capabilities, agent.CellCapabilities[:]...)
	m.Cell = &agent.Cell{Pictures: true}
	if err := declareAgent(root, m, true, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	set, err := loadAgents(root)
	if err != nil {
		t.Fatal(err)
	}
	acts := func(m agent.Manifest) (works, reads int) {
		for _, c := range m.Capabilities {
			switch {
			case desktopActs(c):
				works++
			case agent.IsDesktop(c):
				reads++
			}
		}
		return works, reads
	}
	// Never evaluated with a model, so a model drives it proposing only.
	got, trail, err := boundManifest(root, set, "tidy", true, false, asAdmin("sam"))
	if err != nil || got.Autonomy != agent.AutonomyPropose {
		t.Fatalf("an unevaluated model drives it at %q: %v", got.Autonomy, err)
	}
	if works, reads := acts(got); works != 0 || reads != 2 {
		t.Errorf("a model held to proposing holds %d of the desktop's acts and %d of its two reads: %v",
			works, reads, got.Capabilities)
	}
	if got.Cell == nil || !got.Cell.Pictures {
		t.Errorf("it lost the cell's declaration: %+v", got.Cell)
	}
	// And the run says what it lost to its evaluations, as it says of a write.
	said := ""
	for _, n := range trail {
		if n.By == "evaluations" {
			said = strings.Join(n.Lost, ",")
		}
	}
	for _, op := range []string{"write_page", "desktop_type", "desktop_press", "desktop_key"} {
		if !strings.Contains(said, op) {
			t.Errorf("what its evaluations took away does not name %s: %q", op, said)
		}
	}
	// A walk of the manifest, an evaluation, and a model whose autonomy is
	// not earned but declared all keep the desktop as declared.
	if got, _, err = boundManifest(root, set, "tidy", false, false, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	if works, _ := acts(got); works != 3 {
		t.Errorf("a walk holds %d of the desktop's three acts: %v", works, got.Capabilities)
	}
	if got, _, err = boundManifest(root, set, "tidy", true, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	if works, _ := acts(got); works != 3 {
		t.Errorf("an evaluation holds %d of the desktop's three acts: %v", works, got.Capabilities)
	}
	declaredAutonomy(t, root)
	if got, _, err = boundManifest(root, set, "tidy", true, false, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	if works, _ := acts(got); works != 3 || got.Autonomy != agent.AutonomyDraft {
		t.Errorf("a model at its declared autonomy, %q, holds %d of the desktop's three acts: %v",
			got.Autonomy, works, got.Capabilities)
	}
}

// A run somebody with no role started goes on reading only when somebody
// who may write takes it on, as it did before it waited.
//
// What its starter reached is kept as the role they held, and an empty
// role was read as no limit, where it is the least there is: somebody
// nobody verified, running an agent in a store with no access rules,
// holds no role, so their run proposes and writes nothing. It asked
// before reading, an administrator let the read go ahead, and the run
// went on as the administrator's and wrote the page. A run kept before
// its starter's reach was has no reach to hold it to, and is taken on as
// before.
func TestARunSomebodyWithNoRoleStartedGoesOnReadingOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	declaredAutonomy(t, root)
	m := asker("tidy")
	m.AskFirst = []string{"list_pages"}
	m.Budget.Tools = 4
	if err := declareAgent(root, m, true, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	// Reads the pages first, then writes the about page, then is done.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"list_pages"}`
		switch body := string(b); {
		case strings.Contains(body, "wrote about"), strings.Contains(body, "not one of this agent's"):
			choice = `{"op":"done","say":"written"}`
		case !strings.Contains(body, "Nothing has been done yet"):
			choice = `{"op":"write_page","input":{"page":"about","fields":{"title":"Not theirs to write"}}}`
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

	wrote := func(tr agent.Trace) bool {
		for _, st := range tr.Steps {
			if st.Action.Op == "write_page" && st.Allowed && st.Err == "" {
				return true
			}
		}
		return false
	}
	// Nobody verified, as the command line resolves a caller with no token.
	kit := &Caller{Name: "kit", Kind: audit.KindHuman, Why: "no token was presented"}
	id, out, err := runAgentKept(context.Background(), root, "tidy", "tidy the pages", true, kit)
	w := out.Trace.Waiting
	if err != nil || w == nil || w.Action.Op != "list_pages" {
		t.Fatalf("the run did not wait to read: %v\n%s", err, describeRun(out.Trace))
	}
	if rec, err := loadAgentRun(root, id); err != nil || rec.Bound == nil || rec.Bound.Role != "" {
		t.Fatalf("the run does not keep that its starter held no role: %v %+v", err, rec.Bound)
	}
	done, _ := continueAgentRun(context.Background(), root, id, &agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
	if wrote(done.Trace) {
		t.Errorf("a run somebody with no role started wrote once sam took it on:\n%s", describeRun(done.Trace))
	}
	if len(done.Trace.Steps) == 0 || done.Trace.Steps[0].Action.Op != "list_pages" || !done.Trace.Steps[0].Allowed {
		t.Errorf("the read sam let go ahead was not made:\n%s", describeRun(done.Trace))
	}
	// The narrowing itself: no role is the least, and a run with no bound
	// kept is not narrowed.
	if c, err := asAdmin("sam").within(&agent.Bound{}); err != nil || c.Role != auth.RoleNone {
		t.Errorf("sam taking on a run its starter held no role for holds %q: %v", c.Role, err)
	}
	if c, err := asAdmin("sam").within(nil); err != nil || c.Role != auth.RoleAdmin {
		t.Errorf("sam taking on a run kept with no bound holds %q: %v", c.Role, err)
	}
}

// A run is bounded at what whoever started it may do now: the role their
// token names no higher than the access policy carries for them
// (auth.Policy.Carries), and the part of the site no wider than their
// grants are on. Their token alone is not that.
//
// The bound was read from the token's own role and path, and so was the
// run itself. dana's token was issued while she administered the store,
// and she is now an author of /about who may run the agent: a run she
// started with it wrote the returns page, and was kept as an
// administrator's over the whole site, so sam, taking it on, wrote the
// returns page too. A token over the whole site for somebody whose grants
// are all on /about did the same, and one over /blog, where she is granted
// nothing now, was kept as an author's of /blog. Each now bounds the run at
// what she may really do, for sam and for her own run alike: her author's
// part of /about, or nothing at all on /blog. Whoever takes a run on is
// held to their own policy the same way, and `agent could` says what the
// run would do.
func TestARunIsBoundedByWhatItsStarterMayDoNow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	root := demoStore(t)
	declaredAutonomy(t, root)
	m := asker("tidy")
	m.AskFirst = []string{"list_pages"}
	m.Budget.Tools = 4
	if err := declareAgent(root, m, true, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	// The same agent asking nothing first, for a run nobody takes on.
	alone := asker("alone")
	alone.AskFirst = nil
	alone.Budget.Tools = 4
	if err := declareAgent(root, alone, true, true, asAdmin("sam")); err != nil {
		t.Fatal(err)
	}
	// Reads the pages first, then writes the returns page and the about
	// page, then is done.
	var mu sync.Mutex
	after := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		choice := `{"op":"list_pages"}`
		if !strings.Contains(string(b), "Nothing has been done yet") {
			mu.Lock()
			after++
			switch after {
			case 1:
				choice = `{"op":"write_page","input":{"page":"returns","fields":` +
					`{"title":"Not hers","body":"Returns are not hers to change.","updated":"2026-11-01"}}}`
			case 2:
				choice = `{"op":"write_page","input":{"page":"about","fields":{"title":"Hers"}}}`
			default:
				choice = `{"op":"done","say":"written"}`
			}
			mu.Unlock()
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

	// dana's tokens, issued while she administered the store: one as an
	// administrator, one as an author over the whole site.
	seedPolicy(t, root, [2]string{"sam", "admin"}, [2]string{"dana", "admin"})
	ts, _ := loadTokens(root)
	asAdminToken, _, err := ts.Issue("dana-cli", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	overTheSite, _, err := ts.Issue("dana-site", "dana", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	onTheBlog, _, err := ts.Issue("dana-blog", "dana", auth.RoleAuthor, "/blog", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	// And lee's, over the whole site, from before lee was confined to /blog.
	leeOverTheSite, _, err := ts.Issue("lee-site", "lee", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	// Then made an author of /about, who may run the agents.
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		p.Revoke("dana", auth.RoleAdmin, "/")
		if err := p.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAuthor, Resource: "/about"}); err != nil {
			return err
		}
		if err := p.Grant(auth.Binding{Principal: "dana", Permission: auth.ActRunAgents, Resource: auth.AreaAgents}); err != nil {
			return err
		}
		// lee publishes /blog and decides what the agents wait for.
		if err := p.Grant(auth.Binding{Principal: "lee", Role: auth.RolePublisher, Resource: "/blog"}); err != nil {
			return err
		}
		return p.Grant(auth.Binding{Principal: "lee", Permission: auth.ActApprove, Resource: auth.AreaAgents})
	}); err != nil {
		t.Fatal(err)
	}

	wrote := func(tr agent.Trace) map[string]bool {
		out := map[string]bool{}
		for _, st := range tr.Steps {
			if st.Action.Op == "write_page" && st.Allowed && st.Err == "" {
				page, _ := st.Action.Input["page"].(string)
				out[page] = true
			}
		}
		return out
	}
	for name, c := range map[string]struct {
		secret string
		bound  agent.Bound
		wrote  bool
	}{
		"an administrator's token from before she was made an author": {asAdminToken,
			agent.Bound{Role: string(auth.RoleAuthor), Scope: "/about"}, true},
		"an author's token over the whole site": {overTheSite,
			agent.Bound{Role: string(auth.RoleAuthor), Scope: "/about"}, true},
		"an author's token over /blog, where she holds nothing now": {onTheBlog,
			agent.Bound{Role: string(auth.RoleNone), Scope: "/blog"}, false},
	} {
		dana := resolveCaller(root, c.secret)
		if !dana.Verified || dana.Name != "dana" {
			t.Fatalf("%s: dana is not who the token says: %s", name, dana.Why)
		}
		mu.Lock()
		after = 0
		mu.Unlock()
		id, out, err := runAgentKept(context.Background(), root, "tidy", "tidy the pages", true, dana)
		w := out.Trace.Waiting
		if err != nil || w == nil || w.Action.Op != "list_pages" {
			t.Fatalf("%s: the run did not wait to read: %v\n%s", name, err, describeRun(out.Trace))
		}
		rec, err := loadAgentRun(root, id)
		if err != nil || rec.Bound == nil || rec.Bound.Role != c.bound.Role || rec.Bound.Scope != c.bound.Scope {
			t.Errorf("%s: a run dana started is bounded at %+v (%v), not at %+v", name, rec.Bound, err, c.bound)
		}
		// A run that may write nothing ends when the model asks it to: it
		// holds no write to be asked for.
		done, err := continueAgentRun(context.Background(), root, id, &agent.Verdict{N: w.N, Approve: true}, asAdmin("sam"))
		if err != nil && c.wrote {
			t.Fatalf("%s: %v\n%s", name, err, describeRun(done.Trace))
		}
		if got := wrote(done.Trace); got["returns"] || got["about"] != c.wrote {
			t.Errorf("%s: a run dana started, taken on by sam, wrote %v\n%s", name, got, describeRun(done.Trace))
		}

		// Her own run, which nobody takes on, is held there too.
		mu.Lock()
		after = 0
		mu.Unlock()
		_, out, err = runAgentKept(context.Background(), root, "alone", "tidy the pages", true, dana)
		if got := wrote(out.Trace); got["returns"] || got["about"] != c.wrote {
			t.Errorf("%s: a run dana started herself wrote %v (%v)\n%s", name, got, err, describeRun(out.Trace))
		}
	}

	// Whoever takes a run on is held to what their own policy lets them do
	// as well, before the run's starter's part of the site is applied: lee,
	// who holds /blog and nothing on /about, does not go on with dana's
	// /about run on the strength of a token over the whole site.
	mu.Lock()
	after = 0
	mu.Unlock()
	dana := resolveCaller(root, overTheSite)
	id, out, err := runAgentKept(context.Background(), root, "tidy", "tidy the pages", true, dana)
	w := out.Trace.Waiting
	if err != nil || w == nil {
		t.Fatalf("the run did not wait to read: %v\n%s", err, describeRun(out.Trace))
	}
	lee := resolveCaller(root, leeOverTheSite)
	done, err := continueAgentRun(context.Background(), root, id, &agent.Verdict{N: w.N, Approve: true}, lee)
	if err == nil || !strings.Contains(err.Error(), "who holds /about") {
		t.Errorf("lee, who holds nothing on /about, took dana's /about run on: %v\n%s", err, describeRun(done.Trace))
	}
	if got := wrote(done.Trace); len(got) != 0 {
		t.Errorf("lee, taking on dana's run, wrote %v", got)
	}

	// And what `quilzo agent could` says a run of hers could do, which
	// builds the run's manifest the same way.
	for page, may := range map[string]bool{"returns": false, "about": true} {
		if a, err := could(root, "alone", "write_page", page, false, false, dana); err != nil || a.Could != may {
			t.Errorf("agent could says a run dana starts could write %s: %v (%s) %v", page, a.Could, a.Why, err)
		}
	}
}

// A run is bounded at the role its starter holds on every page of the part
// of the site it is bounded to, and not at the highest they hold on any:
// a run is one role over one part, and nothing asks the access policy
// again of each page it writes. Somebody the policy grants no role, or
// none still in force, holds none, though others are granted something.
//
// Held to the highest role within the part (auth.Policy.Carries), dana,
// reader of the site and author of /about, ran an agent with an
// administrator's token from before that wrote the returns page as an
// author, and so did she as an author of /about and of /blog, the
// narrowest part holding both being the whole site. Denied author over the
// site, an administrator's run wrote it as an administrator; and demoted
// to the permission to run agents and nothing else, or with her
// administrator's grant ended, she was kept at her token's role, as
// somebody the policy says nothing about is, and her run wrote it as one.
func TestARunIsBoundedAtTheRoleItsStarterHoldsOnEveryPageOfIt(t *testing.T) {
	ended := time.Now().Add(-time.Hour).Unix()
	for name, c := range map[string]struct {
		grants []auth.Binding
		bound  agent.Bound
	}{
		"a reader of the site and an author of /about": {[]auth.Binding{
			{Principal: "dana", Role: auth.RoleReader, Resource: "/"},
			{Principal: "dana", Role: auth.RoleAuthor, Resource: "/about"},
		}, agent.Bound{Role: string(auth.RoleReader), Scope: "/"}},
		"an author of /about and of /blog": {[]auth.Binding{
			{Principal: "dana", Role: auth.RoleAuthor, Resource: "/about"},
			{Principal: "dana", Role: auth.RoleAuthor, Resource: "/blog"},
		}, agent.Bound{Role: string(auth.RoleNone), Scope: "/"}},
		"an administrator denied author over the site": {[]auth.Binding{
			{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"},
			{Principal: "dana", Role: auth.RoleAuthor, Resource: "/", Deny: true},
		}, agent.Bound{Role: string(auth.RoleReader), Scope: "/"}},
		"somebody granted no role, only the permission to run agents": {nil,
			agent.Bound{Role: string(auth.RoleNone), Scope: "/"}},
		"an administrator whose grant has ended": {[]auth.Binding{
			{Principal: "dana", Role: auth.RoleAdmin, Resource: "/", Expires: ended},
		}, agent.Bound{Role: string(auth.RoleNone), Scope: "/"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("QUILZO_TOKEN", "")
			root := demoStore(t)
			declaredAutonomy(t, root)
			alone := asker("alone")
			alone.AskFirst = nil
			alone.Budget.Tools = 4
			if err := declareAgent(root, alone, true, true, asAdmin("sam")); err != nil {
				t.Fatal(err)
			}
			// Reads the pages, then writes the returns page, then is done.
			var mu sync.Mutex
			after := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				choice := `{"op":"list_pages"}`
				if !strings.Contains(string(b), "Nothing has been done yet") {
					mu.Lock()
					if after++; after == 1 {
						choice = `{"op":"write_page","input":{"page":"returns","fields":` +
							`{"title":"Not hers","body":"Returns are not hers to change.","updated":"2026-11-01"}}}`
					} else {
						choice = `{"op":"done","say":"written"}`
					}
					mu.Unlock()
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

			// dana's token, issued while she administered the store.
			seedPolicy(t, root, [2]string{"sam", "admin"}, [2]string{"dana", "admin"})
			ts, _ := loadTokens(root)
			secret, _, err := ts.Issue("dana-cli", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
			if err != nil {
				t.Fatal(err)
			}
			if err := saveJSON(tokensPath(root), ts); err != nil {
				t.Fatal(err)
			}
			if _, err := updatePolicy(root, func(p *auth.Policy) error {
				p.Revoke("dana", auth.RoleAdmin, "/")
				for _, b := range c.grants {
					if err := p.Grant(b); err != nil {
						return err
					}
				}
				return p.Grant(auth.Binding{Principal: "dana", Permission: auth.ActRunAgents, Resource: auth.AreaAgents})
			}); err != nil {
				t.Fatal(err)
			}

			dana := resolveCaller(root, secret)
			if !dana.Verified || dana.Name != "dana" {
				t.Fatalf("dana is not who the token says: %s", dana.Why)
			}
			id, out, err := runAgentKept(context.Background(), root, "alone", "tidy the pages", true, dana)
			for _, st := range out.Trace.Steps {
				if st.Action.Op == "write_page" && st.Allowed && st.Err == "" {
					t.Errorf("a run dana started wrote %v (%v)\n%s", st.Action.Input["page"], err, describeRun(out.Trace))
				}
			}
			rec, err := loadAgentRun(root, id)
			if err != nil || rec.Bound == nil || rec.Bound.Role != c.bound.Role || rec.Bound.Scope != c.bound.Scope {
				t.Errorf("a run dana started is bounded at %+v (%v), not at %+v", rec.Bound, err, c.bound)
			}
			if a, err := could(root, "alone", "write_page", "returns", false, false, dana); err != nil || a.Could {
				t.Errorf("agent could says a run dana starts could write the returns page (%s) %v", a.Why, err)
			}
		})
	}
}
