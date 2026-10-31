// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/gate"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/starter"
	"github.com/quilzo/quilzo/internal/store"
)

// boxStore is a store whose draft is one page with a question box opening
// the chatbot named, written by a person and said to be, with a layout to
// check it against and a public chatbot called help. Every gate but the
// question box's passes, so a refusal is that gate's.
func boxStore(t *testing.T, opens string) (root, tpl string, s *store.Store) {
	t.Helper()
	if w == nil {
		w = out.New(false)
	}
	root = t.TempDir() + "/st"
	tpl = t.TempDir() + "/tpl"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := templateUse(root, []string{"sections", "--dir", tpl, "--no-content"}); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{"index": map[string]any{
		"title": "Home", "standfirst": "Paper, made in small runs.",
		"sections": []any{map[string]any{"ask": map[string]any{
			"title": "Ask a question", "assistant": opens,
			"label": "Your question", "button": "Ask",
		}}},
	}}, "a question box", "test"); err != nil {
		t.Fatal(err)
	}
	if err := cmdProvenance(root, []string{"set", "index", "--source", "humanEdits", "--author", "dana"}); err != nil {
		t.Fatal(err)
	}
	set := &assistant.Set{}
	for _, a := range []assistant.Assistant{
		{Name: "help", Title: "Ask the shop", Public: true},
		{Name: "draft-bot", Title: "Still being built"},
	} {
		if err := set.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	return root, tpl, s
}

// The shared set refuses a box opening a chatbot that does not exist or is
// not public, naming the page and the section, and passes one opening a
// public chatbot. A box in a store whose chatbots cannot be read is a gate
// that could not run; a store with no boxes is not asked about them.
func TestTheQuestionBoxGateRefusesABoxThatOpensNothing(t *testing.T) {
	for opens, want := range map[string]string{
		"helpp":     `index: section 1 (Ask a question): the question box opens the chatbot "helpp", which does not exist`,
		"draft-bot": `index: section 1 (Ask a question): the question box opens the chatbot draft-bot, which is not public`,
		"":          `index: section 1 (Ask a question): the question box names no chatbot`,
	} {
		root, _, s := boxStore(t, opens)
		refused, _, err := contentGates(root, s, "").Run()
		if err != nil {
			t.Fatalf("%q: the gates could not run: %v", opens, err)
		}
		if refused == nil || refused.Check.Name != "question boxes" {
			t.Fatalf("a box opening %q was not refused by the question box gate: %v", opens, refused)
		}
		if got := refused.Findings[0].String(); !strings.HasPrefix(got, want) {
			t.Errorf("%q:\n  got  %s\n  want %s…", opens, got, want)
		}
	}

	root, _, s := boxStore(t, "help")
	if refused, _, err := contentGates(root, s, "").Run(); err != nil || refused != nil {
		t.Fatalf("a box opening a public chatbot was refused: %v %v", refused, err)
	}

	if err := os.WriteFile(assistantsPath(root), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := contentGates(root, s, "").Run(); err == nil || !strings.Contains(err.Error(), "question boxes check could not run") {
		t.Fatalf("unreadable chatbots were taken as no question to answer: %v", err)
	}
	if _, err := site.SaveDraft(s, map[string]any{"index": map[string]any{"title": "Home"}}, "no box", "test"); err != nil {
		t.Fatal(err)
	}
	if err := cmdProvenance(root, []string{"set", "index", "--source", "humanEdits", "--author", "dana"}); err != nil {
		t.Fatal(err)
	}
	if refused, _, err := contentGates(root, s, "").Run(); err != nil || refused != nil {
		t.Fatalf("a site with no question box was refused over a file it does not use: %v %v", refused, err)
	}
}

// Every way to publish refuses the box: the command line, a scheduled
// publish, the agent interface, the browser and a promotion to
// production. And each goes through once the box opens a public chatbot,
// so the refusal is the box's and not something else about the store.
func TestEveryPublishPathRefusesABrokenQuestionBox(t *testing.T) {
	live := func(s *store.Store) string { return s.GetRef(site.RefLive) }

	t.Run("quilzo publish", func(t *testing.T) {
		root, tpl, s := boxStore(t, "helpp")
		err := cmdPublish(root, []string{"--templates", tpl})
		if err == nil || !strings.Contains(err.Error(), "question box") || live(s) != "" {
			t.Fatalf("published a broken box: %v, live %q", err, live(s))
		}
		fixBox(t, root, s)
		if err := cmdPublish(root, []string{"--templates", tpl}); err != nil || live(s) == "" {
			t.Fatalf("a box opening a public chatbot did not publish: %v", err)
		}
	})

	t.Run("a scheduled publish", func(t *testing.T) {
		root, _, s := boxStore(t, "helpp")
		draft := s.GetRef(site.RefDraft)
		sch := &schedule.Schedule{Entries: []schedule.Entry{{Commit: draft,
			At: time.Now().Add(-time.Minute).Unix(), By: "dana", CreatedAt: time.Now().Add(-time.Hour).Unix()}}}
		if err := saveJSON(schedulePath(root), sch); err != nil {
			t.Fatal(err)
		}
		if err := cmdSchedule(root, []string{"run"}); err != nil {
			t.Fatal(err)
		}
		after, err := loadSchedule(root)
		if err != nil {
			t.Fatal(err)
		}
		if r := after.Entries[0].Result; !strings.HasPrefix(r, "refused") || !strings.Contains(r, "question box") || live(s) != "" {
			t.Fatalf("a scheduled publish put up a broken box: %q, live %q", r, live(s))
		}
	})

	t.Run("the agent interface", func(t *testing.T) {
		root, tpl, s := boxStore(t, "helpp")
		srv := buildMCP(root, s, human("dana"), tpl)
		text, merr := callTool(t, srv, "quilzo_publish", "publish", nil)
		got := text
		if merr != nil {
			got = merr.Message
		}
		if !strings.Contains(got, "question box") || live(s) != "" {
			t.Fatalf("published a broken box over MCP: %s, live %q", got, live(s))
		}
		fixBox(t, root, s)
		if text, merr := callTool(t, srv, "quilzo_publish", "publish", nil); merr != nil || live(s) == "" {
			t.Fatalf("a box opening a public chatbot did not publish over MCP: %s %v", text, merr)
		}
	})

	t.Run("the browser", func(t *testing.T) {
		root, tpl, s := boxStore(t, "helpp")
		srv, token := wiredBrowser(t, root, tpl, s)
		publish := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/publish", strings.NewReader(url.Values{}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			return rec
		}
		if rec := publish(); rec.Code != http.StatusUnprocessableEntity ||
			!strings.Contains(rec.Body.String(), "question box") || live(s) != "" {
			t.Fatalf("the browser published a broken box: %d, live %q", rec.Code, live(s))
		}
		fixBox(t, root, s)
		if rec := publish(); live(s) == "" {
			t.Fatalf("a box opening a public chatbot did not publish from the browser: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("a promotion to production", func(t *testing.T) {
		root, tpl, s := boxStore(t, "helpp")
		err := cmdEnv(root, []string{"promote", "draft", "production", "--templates", tpl})
		if err == nil || !strings.Contains(err.Error(), "question box") || live(s) != "" {
			t.Fatalf("a promotion put up a broken box: %v, live %q", err, live(s))
		}
		fixBox(t, root, s)
		if err := cmdEnv(root, []string{"promote", "draft", "production", "--templates", tpl}); err != nil || live(s) == "" {
			t.Fatalf("a box opening a public chatbot was not promoted: %v", err)
		}
	})
}

// Promoting to production from the command line is asked the rest of what
// quilzo publish asks, and waives none of it: whether the caller may publish
// each page it changes, whether each page says who wrote it, whether it
// renders accessibly through the templates, and the approvals given to those
// bytes. Each refusal is its own, and once each is met the commit goes live.
func TestPromotingToProductionAsksWhatQuilzoPublishAsks(t *testing.T) {
	root, tpl, s := boxStore(t, "help")
	live := func() string { return s.GetRef(site.RefLive) }
	refused := func(why, want string, args ...string) {
		t.Helper()
		err := cmdEnv(root, append([]string{"promote", "draft", "production"}, args...))
		if err == nil || !strings.Contains(err.Error(), want) || live() != "" {
			t.Fatalf("%s: promoted, or refused for something else:\n  got  %v\n  want …%s…", why, err, want)
		}
	}
	about := func(body map[string]any) {
		t.Helper()
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		pages["about"] = body
		if _, err := site.SaveDraft(s, pages, "about", "test"); err != nil {
			t.Fatal(err)
		}
	}
	mark := func() {
		t.Helper()
		if err := cmdProvenance(root, []string{"set", "about", "--source", "humanEdits", "--author", "dana"}); err != nil {
			t.Fatal(err)
		}
	}
	page := map[string]any{"title": "About", "standfirst": "Who makes the paper."}

	about(page)
	refused("a page nobody said wrote", "have no provenance and cannot go to production: about", "--templates", tpl)
	mark()

	// Each page it changes, asked about its own path.
	pol := &auth.Policy{}
	grantAll(t, root, pol,
		auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/"},
		auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/about", Deny: true})
	toks := &auth.TokenStore{}
	secret, _, err := toks.Issue("pat", "pat", auth.RolePublisher, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), toks); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func(old string) { flagToken = old }(flagToken)
		flagToken = secret
		refused("a page the caller may not publish", "about, which pat may not publish", "--templates", tpl)
	}()
	for _, path := range []string{policyPath(root), tokensPath(root)} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}

	// Rendered as a publish renders it: templates that are not there are a
	// check that could not run, and a page asking for a layout the site
	// does not have is a blocking failure.
	refused("templates that are not there", "the accessibility check could not run",
		"--templates", t.TempDir()+"/none")
	about(map[string]any{"title": "About", "standfirst": "Who makes the paper.", "layout": "no-such-layout"})
	mark()
	refused("a page that does not render", "blocking accessibility failure", "--templates", tpl)
	about(page)
	mark()

	// The approvals given to these bytes, and none to any other.
	if err := saveJSON(approvalPolicyPath(root), collab.Policy{Required: 1}); err != nil {
		t.Fatal(err)
	}
	refused("a commit nobody approved", "quilzo review status", "--templates", tpl)
	draft := s.GetRef(site.RefDraft)
	if err := saveJSON(proposalsPath(root), &proposalFile{Proposals: []collab.Proposal{{
		Content: draft, Author: "test", AuthorKind: "human", CreatedAt: time.Now().Unix(),
		Approvals: []collab.Approval{{Content: draft, By: "ria", At: time.Now().Unix()}},
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := cmdEnv(root, []string{"promote", "draft", "production", "--templates", tpl}); err != nil || live() != draft {
		t.Fatalf("an approved, marked, accessible commit was not promoted: %v, live %q", err, live())
	}
}

// fixBox points the draft's question box at the public chatbot, and says
// again who wrote the page: the record is bound to the bytes it describes.
func fixBox(t *testing.T, root string, s *store.Store) {
	t.Helper()
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	page := pages["index"].(map[string]any)
	box := page["sections"].([]any)[0].(map[string]any)["ask"].(map[string]any)
	box["assistant"] = "help"
	if _, err := site.SaveDraft(s, pages, "the box opens help", "test"); err != nil {
		t.Fatal(err)
	}
	if err := cmdProvenance(root, []string{"set", "index", "--source", "humanEdits", "--author", "dana"}); err != nil {
		t.Fatal(err)
	}
}

// wiredBrowser is the admin server with the content gates handed to it the
// way `quilzo serve` hands them, for an administrator signed in with a
// passkey.
func wiredBrowser(t *testing.T, root, tpl string, s *store.Store) (*admin.Server, string) {
	t.Helper()
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	token, _, err := ts.IssueSession("test", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, ts, design.Layouts)
	if err != nil {
		t.Fatal(err)
	}
	srv.ContentGates = func(ref string) (*gate.Report, []gate.Finding, error) {
		return contentGates(root, s, ref).Run()
	}
	srv.LoadProvenance = func() (*provenance.Index, error) { return loadProvenance(root) }
	return srv, token
}

// A package whose page carries a question box is held to the same rule as
// a page published by hand: the chatbot it opens is the package's own or
// the site's, and public. Refused before anything is written.
func TestAFeatureIsNotInstalledWithAQuestionBoxThatOpensNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, _, _ := boxStore(t, "help")
	seedPolicy(t, root, [2]string{"dana", "admin"})
	withBox := labPackage
	// Each refusal carries its own reason, so a package refused for
	// something else entirely does not pass for one refused over its box.
	for name, c := range map[string]struct {
		edit func(*feature.Package)
		why  string
	}{
		"a chatbot nobody declares": {withBox("concierge"),
			`page samples, section 1 (Ask about samples): the question box opens the chatbot "concierge", which does not exist`},
		"its own chatbot, not public": {withBox("lab", assistant.Assistant{Name: "lab", Title: "Lab"}),
			"page samples, section 1 (Ask about samples): the question box opens the chatbot lab, which is not public"},
		"the site's chatbot, not public": {withBox("draft-bot"),
			"page samples, section 1 (Ask about samples): the question box opens the chatbot draft-bot, which is not public"},
		"a form action with a stray field": {withBox("help", labBot("notes")),
			"notes, which the form sample_intake does not ask for"},
	} {
		err := installFeatureFile(root, writePackage(t, c.edit), "", "", asAdmin("dana"))
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: not refused for the box or the action:\n  got  %v\n  want …%s…", name, err, c.why)
		}
		if owns(t, root, "lab-samples") != nil {
			t.Fatalf("%s: refused, and installed anyway", name)
		}
	}

	// Its own public chatbot, or the site's, is what a box may open.
	if err := installFeatureFile(root, writePackage(t, withBox("help")), "", "", asAdmin("dana")); err != nil {
		t.Fatalf("a box opening the site's public chatbot was refused: %v", err)
	}
	lab := labBot("sample")
	lab.Public = true
	if err := installFeatureFile(root, writePackage(t, withBox("lab", lab)), "", "", asAdmin("dana")); err != nil {
		t.Fatalf("a box opening the package's own public chatbot was refused: %v", err)
	}
}

// The command line does not take a chatbot away from the question boxes
// that open it: removing it, or declaring it again without --public, is
// refused while a box opens it, saying where the box is, and nothing is
// saved. Declared again with --public it goes through, and a chatbot no box
// opens is the owner's to remove.
func TestTheCommandLineKeepsAChatbotABoxOpens(t *testing.T) {
	root, _, _ := boxStore(t, "help")
	const where = "the draft page index, section 1 (Ask a question), opens help"

	err := cmdAssistant(root, []string{"remove", "help"})
	if err == nil || !strings.Contains(err.Error(), where) {
		t.Fatalf("removing a chatbot a box opens:\n  got  %v\n  want …%s…", err, where)
	}
	err = cmdAssistant(root, []string{"add", "help", "--title", "Ask us anything"})
	if err == nil || !strings.Contains(err.Error(), where) ||
		!strings.Contains(err.Error(), "--public keeps help public") {
		t.Fatalf("declaring it again without --public: %v", err)
	}
	if a, err := loadAssistant(root, "help"); err != nil || !a.Public || a.Title != "Ask the shop" {
		t.Fatalf("a refused change was saved: %+v %v", a, err)
	}

	if err := cmdAssistant(root, []string{"add", "help", "--title", "Ask us anything", "--public"}); err != nil {
		t.Fatalf("declaring it again, public, was refused: %v", err)
	}
	if err := cmdAssistant(root, []string{"remove", "draft-bot"}); err != nil {
		t.Fatalf("removing a chatbot no box opens was refused: %v", err)
	}
}

// Removing a package takes its chatbots with it, and a question box the
// site put on a page of its own opening one would answer "not found" from
// then on: refused, naming that box, and the package stays. The package's
// own pages go with it, so the box on one of them is not counted.
func TestRemovingAFeatureKeepsAChatbotABoxOpens(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, _, s := boxStore(t, "help")
	seedPolicy(t, root, [2]string{"dana", "admin"})
	lab := labBot("sample")
	lab.Public = true
	if err := installFeatureFile(root, writePackage(t, labPackage("lab", lab)), "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	pointAt := func(name string) {
		t.Helper()
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		box := pages["index"].(map[string]any)["sections"].([]any)[0].(map[string]any)["ask"].(map[string]any)
		box["assistant"] = name
		if _, err := site.SaveDraft(s, pages, "the box opens "+name, "test"); err != nil {
			t.Fatal(err)
		}
	}

	pointAt("lab")
	err := removeFeature(root, "lab-samples", asAdmin("dana"))
	const where = "the draft page index, section 1 (Ask a question), opens lab"
	if err == nil || !strings.Contains(err.Error(), where) {
		t.Fatalf("removing the package a box's chatbot came with:\n  got  %v\n  want …%s…", err, where)
	}
	if strings.Contains(err.Error(), "page samples") {
		t.Errorf("the package's own page, which goes with it, was counted: %v", err)
	}
	if owns(t, root, "lab-samples") == nil {
		t.Fatal("refused, and removed anyway")
	}
	if a, err := loadAssistant(root, "lab"); err != nil || !a.Public {
		t.Fatalf("refused, and the chatbot went anyway: %v", err)
	}

	pointAt("help")
	if err := removeFeature(root, "lab-samples", asAdmin("dana")); err != nil {
		t.Fatalf("removing a package no other box depends on was refused: %v", err)
	}
}

// A question box added from the command line opens the site's first public
// chatbot, as one added on the Sections screen does, and the catalogue's
// "help" when the site has no public chatbot.
func TestAQuestionBoxAddedFromTheCommandLineOpensAChatbotTheSiteHas(t *testing.T) {
	root, _, s := boxStore(t, "help")
	opened := func() string {
		t.Helper()
		pages, err := site.PagesAt(s, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		list := pages["index"].(map[string]any)["sections"].([]any)
		name, _ := list[0].(map[string]any)["ask"].(map[string]any)["assistant"].(string)
		return name
	}
	set := &assistant.Set{}
	for _, a := range []assistant.Assistant{
		{Name: "a-draft", Title: "Not yet"},
		{Name: "shop", Title: "Ask the shop", Public: true},
	} {
		if err := set.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	if err := cmdSection(root, []string{"add", "index", "ask", "--at", "0"}); err != nil {
		t.Fatal(err)
	}
	if got := opened(); got != "shop" {
		t.Errorf("a new box opens %q, want the site's public chatbot shop", got)
	}

	if err := assistant.Save(assistantsPath(root), &assistant.Set{}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSection(root, []string{"add", "index", "ask", "--at", "0"}); err != nil {
		t.Fatal(err)
	}
	if got := opened(); got != "help" {
		t.Errorf("with no public chatbot a new box opens %q, want the stub's help", got)
	}
}

// The demonstration shows a question box: its returns page opens a public
// chatbot it declares, so it publishes through the question box gate, and
// pointing the box at a name the site does not have is refused, naming the
// page and the section. Its chatbot cannot be taken away while the box is
// live, and taking the demonstration out takes the chatbot only when no
// page left opens it.
func TestTheDemonstrationsQuestionBoxOpensItsChatbot(t *testing.T) {
	root, tpl, _ := installedDemo(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := loadAssistant(root, "counter"); err != nil || !a.Public {
		t.Fatalf("the demonstration's chatbot is missing or private: %+v %v", a, err)
	}
	if refused, _, err := contentGates(root, s, "").Run(); err != nil || refused != nil {
		t.Fatalf("the demonstration's own draft is refused: %v %v", refused, err)
	}

	err = cmdAssistant(root, []string{"remove", "counter"})
	if err == nil || !strings.Contains(err.Error(), "the live page returns, section 1 (Ask about returns and delivery), opens counter") {
		t.Fatalf("the chatbot the live box opens was taken away: %v", err)
	}

	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	returns := pages["returns"].(map[string]any)
	box := returns["sections"].([]any)[0].(map[string]any)["ask"].(map[string]any)
	box["assistant"] = "counterr"
	if _, err := site.SaveDraft(s, pages, "the box opens a typo", "test"); err != nil {
		t.Fatal(err)
	}
	refused, _, err := contentGates(root, s, "").Run()
	const want = `returns: section 1 (Ask about returns and delivery): the question box opens the chatbot "counterr", which does not exist`
	if err != nil || refused == nil || refused.Check.Name != "question boxes" ||
		!strings.HasPrefix(refused.Findings[0].String(), want) {
		t.Fatalf("a box opening a name the demonstration does not have:\n  got  %v %v\n  want %s…", refused, err, want)
	}
	box["assistant"] = "counter"
	if _, err := site.SaveDraft(s, pages, "the box opens counter again", "test"); err != nil {
		t.Fatal(err)
	}

	// A page of somebody's own opening the chatbot keeps it when the
	// demonstration goes.
	addOwnPage(t, root, tpl, "help-desk", map[string]any{"title": "Help desk",
		"sections": []any{map[string]any{"ask": map[string]any{
			"title": "Ask us", "assistant": "counter"}}}})
	if err := removeDemo(root, true, resolveCaller(root, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAssistant(root, "counter"); err != nil {
		t.Fatalf("the chatbot a page of somebody's own opens was taken: %v", err)
	}
}

// labPackage is the example package with a question box on its page
// opening the chatbot named, declaring these chatbots and the form its
// chatbot's action fills in.
func labPackage(opens string, bots ...assistant.Assistant) func(*feature.Package) {
	return func(p *feature.Package) {
		withoutAddress(p)
		p.Pages[0].Body["sections"] = []any{map[string]any{"ask": map[string]any{
			"title": "Ask about samples", "assistant": opens}}}
		p.Chatbots = bots
		p.Forms = []form.Form{{Name: "sample_intake", Notice: "To log the sample.",
			Fields: []form.Field{{Name: "sample", Label: "Sample", Kind: form.Line}}}}
	}
}

// labBot is a chatbot that fills in the example package's form.
func labBot(fields ...string) assistant.Assistant {
	return assistant.Assistant{Name: "lab", Title: "Ask the lab", Actions: []assistant.Action{{
		Name: "log-sample", Kind: assistant.Form, Target: "sample_intake",
		Description: "log a sample", Fields: fields}}}
}

// quietly runs a command with its output as JSON in a buffer, for a test
// that reads what it said.
func quietly(t *testing.T, run func() error) (string, error) {
	t.Helper()
	saved := w
	var buf bytes.Buffer
	w = &out.Writer{Mode: out.JSON, Out: &buf, Err: &buf}
	defer func() { w = saved }()
	err := run()
	return buf.String(), err
}

// `quilzo assistant action` checks a form action against its form, as the
// Chatbots screen does, and says when nothing will offer it: a chatbot
// answering without a model, or set to and with no model to use.
func TestAnActionIsCheckedAndToldWhetherItIsOffered(t *testing.T) {
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help"}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(formsPath(root), &form.Set{Forms: []form.Form{{Name: "returns", Notice: "To process the return.",
		Fields: []form.Field{
			{Name: "order", Label: "Order", Kind: form.Line},
			{Name: "card", Label: "Card for the refund", Kind: form.Line, Sensitive: true},
		}}}}); err != nil {
		t.Fatal(err)
	}
	action := func(target, fields string) (string, error) {
		return quietly(t, func() error {
			return cmdAssistant(root, []string{"action", "help", "start-return", "--kind", "form",
				"--target", target, "--description", "start a return", "--fields", fields})
		})
	}

	if _, err := action("refunds", "order"); err == nil || !strings.Contains(err.Error(), `"refunds", which this site does not have`) {
		t.Errorf("a form that does not exist: %v", err)
	}
	if _, err := action("returns", "order,email"); err == nil || !strings.Contains(err.Error(), "email, which the form returns does not ask for") ||
		!strings.Contains(err.Error(), assistant.SensitiveNever) {
		t.Errorf("a field the form does not ask for: %v", err)
	}
	if a, _ := loadAssistant(root, "help"); len(a.Actions) != 0 {
		t.Fatal("a refused action was saved")
	}

	said, err := action("returns", "order,card")
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Actions int
		Notes   []string
	}
	if err := json.Unmarshal([]byte(said), &res); err != nil {
		t.Fatalf("%v: %s", err, said)
	}
	notes := strings.Join(res.Notes, "\n")
	if res.Actions != 1 || !strings.Contains(notes, "marks card sensitive") ||
		!strings.Contains(notes, assistant.ActionsNeedModel) || !strings.Contains(notes, "without one") {
		t.Errorf("what adding the action said: %s", said)
	}

	// Set to use a model, through a gateway that has no route: still told,
	// with the reason.
	set, _ := assistant.Load(assistantsPath(root))
	a, _ := set.Get("help")
	a.UseModel = true
	if err := set.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Save(gatewayPath(root), &gateway.Config{}); err != nil {
		t.Fatal(err)
	}
	said, err = quietly(t, func() error {
		return cmdAssistant(root, []string{"action", "help", "returns-page", "--kind", "link",
			"--target", "returns", "--description", "read the returns page"})
	})
	if err != nil || !strings.Contains(said, "declares no route") {
		t.Errorf("a chatbot with no model to use was not told: %v %s", err, said)
	}

	// Only the notice tells a gateway with no route apart. Answering, on
	// the public site and in the inbox, still goes to the gateway, whose
	// "no route" turns the answer into a quoted one there, as it always has.
	a, _ = loadAssistant(root, "help")
	if m, why := assistantModelAt(root, a); m == nil {
		t.Errorf("the answering path lost its model over a gateway with no route: %s", why)
	}
	if m, why := offersModelAt(root, a); m != nil || why != "the model gateway declares no route" {
		t.Errorf("the notice: %v %q", m, why)
	}
}

// An agent declaring a chatbot is told about the actions a person gave it,
// in the same words, and is not refused for them: it cannot change them.
func TestAnAgentIsToldWhatItsChatbotsActionsNeed(t *testing.T) {
	root := publishedShop(t)
	srv := assistantMCP(t, root)
	if _, err := callTool(t, srv, "quilzo_write", "declare_assistant", map[string]any{
		"name": "help", "title": "Help"}); err != nil {
		t.Fatal(err.Message)
	}
	text, _ := callTool(t, srv, "quilzo_write", "declare_assistant", map[string]any{
		"name": "help", "title": "Help"})
	if strings.Contains(text, assistant.ActionsNeedModel) {
		t.Errorf("a chatbot with no actions was told about them: %s", text)
	}

	// A person gives it a form action, and the form goes.
	set, _ := assistant.Load(assistantsPath(root))
	a, _ := set.Get("help")
	a.Actions = []assistant.Action{{Name: "start-return", Kind: assistant.Form, Target: "returns",
		Description: "start a return", Fields: []string{"order"}}}
	if err := set.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	text, merr := callTool(t, srv, "quilzo_write", "declare_assistant", map[string]any{
		"name": "help", "title": "Help, kinder"})
	if merr != nil {
		t.Fatalf("an agent was refused over actions it cannot change: %s", merr.Message)
	}
	for _, want := range []string{assistant.ActionsNeedModel, `"returns", which this site does not have`, "Chatbots screen"} {
		if !strings.Contains(text, want) {
			t.Errorf("the declare result does not say %q: %s", want, text)
		}
	}
	if b, _ := loadAssistant(root, "help"); b.Title != "Help, kinder" {
		t.Error("the change was not saved")
	}
}

// The sections sample has a question box, and `template use` prints the
// steps to publish it. Following them has to publish it: so the steps
// declare the chatbot the box opens when the site does not have one, and
// leave it out once the site has it public.
func TestTheSamplesStepsDeclareTheChatbotItsBoxOpens(t *testing.T) {
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	sample, ok := starter.Get("sections")
	if !ok {
		t.Fatal("the sections starter is missing")
	}
	boxes := func() []assistant.Box {
		set, err := assistant.Load(assistantsPath(root))
		if err != nil {
			t.Fatal(err)
		}
		return set.Boxes(map[string]any{"index": sample.Sample})
	}
	if len(boxes()) == 0 {
		t.Fatal("the sample has no question box that needs a chatbot, so this tests nothing")
	}

	steps := sampleChatbotSteps(root, "index", sample.Sample)
	const want = `quilzo assistant add help --title "Ask this site" --public`
	if len(steps) != 1 || !strings.HasPrefix(steps[0], want) {
		t.Fatalf("the steps before publishing the sample are %q, want one starting %s", steps, want)
	}
	// A step is a line somebody pastes into a shell, so what it says about
	// itself is a comment: the command alone before the #, and the
	// apostrophe in "sample's" after it, where it opens no quote.
	cmd, said, commented := strings.Cut(colourless(steps[0]), "#")
	if strings.TrimSpace(cmd) != want || !commented || !strings.Contains(said, "question box") {
		t.Errorf("the step is not the command and a comment: %q", colourless(steps[0]))
	}
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Ask this site", "--public"}); err != nil {
		t.Fatal(err)
	}
	if left := boxes(); len(left) != 0 {
		t.Fatalf("after the step the sample's box still opens nothing: %s", left[0])
	}
	if steps := sampleChatbotSteps(root, "index", sample.Sample); len(steps) != 0 {
		t.Errorf("a site with the chatbot public is still told to declare it: %q", steps)
	}

	// Declared and not public: said as publishing would say it, not
	// declared again.
	set, _ := assistant.Load(assistantsPath(root))
	a, _ := set.Get("help")
	a.Public = false
	if err := set.Put(a); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	if steps := sampleChatbotSteps(root, "index", sample.Sample); len(steps) != 1 ||
		strings.Contains(steps[0], "assistant add") || !strings.Contains(steps[0], "not public") ||
		!strings.HasPrefix(colourless(steps[0]), "# ") {
		t.Errorf("a private chatbot, said as a comment: %q", steps)
	}
}

// colourless is a line as it reads with the terminal's colours taken out.
func colourless(line string) string {
	return regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(line, "")
}
