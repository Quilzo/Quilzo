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
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/auth"
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
		root, _, s := boxStore(t, "helpp")
		err := cmdEnv(root, []string{"promote", "draft", "production"})
		if err == nil || !strings.Contains(err.Error(), "question box") || live(s) != "" {
			t.Fatalf("a promotion put up a broken box: %v, live %q", err, live(s))
		}
		fixBox(t, root, s)
		if err := cmdEnv(root, []string{"promote", "draft", "production"}); err != nil || live(s) == "" {
			t.Fatalf("a box opening a public chatbot was not promoted: %v", err)
		}
	})
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
	withBox := func(opens string, bots ...assistant.Assistant) func(*feature.Package) {
		return func(p *feature.Package) {
			withoutAddress(p)
			p.Pages[0].Body["sections"] = []any{map[string]any{"ask": map[string]any{
				"title": "Ask about samples", "assistant": opens}}}
			p.Chatbots = bots
			p.Forms = []form.Form{{Name: "sample_intake", Notice: "To log the sample.",
				Fields: []form.Field{{Name: "sample", Label: "Sample", Kind: form.Line}}}}
		}
	}
	for name, edit := range map[string]func(*feature.Package){
		"a chatbot nobody declares":        withBox("concierge"),
		"its own chatbot, not public":      withBox("lab", assistant.Assistant{Name: "lab", Title: "Lab"}),
		"the site's chatbot, not public":   withBox("draft-bot"),
		"a form action with a stray field": withBox("help", labBot("notes")),
	} {
		err := installFeatureFile(root, writePackage(t, edit), "", "", asAdmin("dana"))
		if err == nil {
			t.Errorf("%s: installed", name)
			continue
		}
		if owns(t, root, "lab-samples") != nil {
			t.Fatalf("%s: refused, and installed anyway", name)
		}
	}
	err := installFeatureFile(root, writePackage(t, withBox("concierge")), "", "", asAdmin("dana"))
	if err == nil || !strings.Contains(err.Error(), `page samples, section 1 (Ask about samples): the question box opens the chatbot "concierge"`) {
		t.Errorf("the refusal does not say where the box is: %v", err)
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
		strings.Contains(steps[0], "assistant add") || !strings.Contains(steps[0], "not public") {
		t.Errorf("a private chatbot: %q", steps)
	}
}
