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
	refused := false
	for _, st := range runs[0].Trace.Steps {
		refused = refused || (st.Action.Tool == "post_update" && !st.Allowed && strings.Contains(st.Why, "only reads"))
	}
	if !refused {
		t.Fatalf("the post was not refused as one a read-only run may not make:\n%s", describeRun(runs[0].Trace))
	}
}
