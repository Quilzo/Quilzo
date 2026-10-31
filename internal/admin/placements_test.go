// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	publishgate "github.com/quilzo/quilzo/internal/gate"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
)

// inputTag is the whole <input> a field is drawn as, so a test can ask what
// that one input carries rather than what the page carries somewhere.
func inputTag(t *testing.T, html, id string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<input id="` + regexp.QuoteMeta(id) + `"[^>]*>`).FindString(html)
	if m == "" {
		t.Fatalf("there is no input %s on the screen", id)
	}
	return m
}

// A question box's chatbot field offers the chatbots this site has, public
// ones first, and says of a private one why a box opening it will not
// publish. It is the listing name's argument again: typed blind, a typo is
// found at publishing, after the editing is done.
func TestTheQuestionBoxOffersTheChatbotsThatExist(t *testing.T) {
	srv, token, fa := chatbots(t)
	for _, a := range []assistant.Assistant{
		{Name: "draft-bot", Title: "Still being built"},
		{Name: "help", Title: "Ask the shop", Public: true},
	} {
		if err := fa.set.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	body, err := section.Insert(pages["index"], assistant.SectionKind, 0)
	if err != nil {
		t.Fatal(err)
	}
	if body, err = section.Insert(body, "prose", 1); err != nil {
		t.Fatal(err)
	}
	pages["index"] = body
	if _, err := site.SaveDraft(srv.Store, pages, "a question box", "test"); err != nil {
		t.Fatal(err)
	}

	html := get(t, srv, "/sections/fields?page=index&at=0", token).Body.String()
	if !strings.Contains(html, `<datalist id="chatbot-names">`) {
		t.Fatal("the question box's screen offers no chatbots")
	}
	public := strings.Index(html, `<option value="help">Ask the shop</option>`)
	private := strings.Index(html, `<option value="draft-bot">not public yet`)
	if public < 0 || private < 0 {
		t.Fatalf("the chatbots are not both offered, with what each is:\n%s", html)
	}
	if public > private {
		t.Error("a chatbot that is not public is offered before one that is")
	}
	if tag := inputTag(t, html, "f-assistant"); !strings.Contains(tag, `list="chatbot-names"`) {
		t.Errorf("the chatbot field does not offer the list: %s", tag)
	}
	if tag := inputTag(t, html, "f-title"); strings.Contains(tag, "list=") {
		t.Errorf("the box's title offers chatbot names: %s", tag)
	}

	plain := get(t, srv, "/sections/fields?page=index&at=1", token).Body.String()
	if strings.Contains(plain, "chatbot-names") {
		t.Error("a prose section's screen offers chatbot names")
	}
}

// An editor kept to part of the site is offered the public chatbots and
// not the private ones: the Chatbots screen, where those are listed, is
// asked of the whole site, and the public site answers "not found" for a
// private one so that its name is not learnt from outside.
func TestAPathScopedEditorIsOfferedOnlyPublicChatbots(t *testing.T) {
	srv, tok := scoped(t,
		auth.Binding{Principal: "owner", Role: auth.RoleAdmin, Resource: "/"},
		auth.Binding{Principal: "blogger", Role: auth.RoleAuthor, Resource: "/blog"},
	)
	fa := &fakeAssistants{set: &assistant.Set{}}
	srv.Assistants = fa.wire()
	for _, a := range []assistant.Assistant{
		{Name: "draft-bot", Title: "Still being built"},
		{Name: "help", Title: "Ask the shop", Public: true},
	} {
		if err := fa.set.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if pages["blog/first"], err = section.Insert(pages["blog/first"], assistant.SectionKind, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(srv.Store, pages, "a question box", "test"); err != nil {
		t.Fatal(err)
	}

	html := get(t, srv, "/sections/fields?page=blog/first&at=0", tok["blogger"]).Body.String()
	if !strings.Contains(html, `<option value="help">`) {
		t.Fatalf("the public chatbot is not offered to the blogger:\n%s", html)
	}
	if strings.Contains(html, "draft-bot") {
		t.Error("an editor kept to /blog learnt the name of a chatbot that is not public")
	}
	if html := get(t, srv, "/sections/fields?page=blog/first&at=0", tok["owner"]).Body.String(); !strings.Contains(html, `<option value="draft-bot">`) {
		t.Error("the owner, who may open the Chatbots screen, is not offered the private chatbot")
	}
}

// A question box added from the Sections screen opens the site's first
// public chatbot rather than the catalogue's "help", which this site may
// not have; with no public chatbot it keeps "help".
func TestANewQuestionBoxOpensAChatbotTheSiteHas(t *testing.T) {
	srv, token, fa := chatbots(t)
	add := func() string {
		t.Helper()
		w := decideForm(t, srv, "/sections/edit", token, url.Values{"page": {"index"},
			"do": {"add"}, "kind": {assistant.SectionKind}, "at": {"0"},
			"base": {srv.Store.GetRef(site.RefDraft)}})
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil || loc.Query().Get("e") != "" {
			t.Fatalf("adding a question box was refused: %v %v", loc, err)
		}
		pages, err := site.PagesAt(srv.Store, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		first := pages["index"].(map[string]any)["sections"].([]any)[0].(map[string]any)
		name, _ := first[assistant.SectionKind].(map[string]any)[assistant.BoxField].(string)
		return name
	}
	if got := add(); got != "help" {
		t.Errorf("with no public chatbot a new box opens %q, want the stub's help", got)
	}
	for _, a := range []assistant.Assistant{
		{Name: "a-draft", Title: "Not yet"},
		{Name: "shop", Title: "Ask the shop", Public: true},
	} {
		if err := fa.set.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	if got := add(); got != "shop" {
		t.Errorf("a new box opens %q, want the site's public chatbot shop", got)
	}
}

// The Chatbots screen does not take a chatbot away from the question boxes
// that open it: unticking Public, or removing it, is refused while a box on
// the live site or in the draft opens it, naming where. Once no box does,
// both go through.
func TestTheChatbotsScreenKeepsAChatbotABoxOpens(t *testing.T) {
	srv, token, fa := chatbots(t)
	if err := fa.set.Put(assistant.Assistant{Name: "help", Title: "Ask the shop", Public: true}); err != nil {
		t.Fatal(err)
	}
	withBox := func(sections []any) {
		t.Helper()
		pages, err := site.PagesAt(srv.Store, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		pages["index"].(map[string]any)["sections"] = sections
		if _, err := site.SaveDraft(srv.Store, pages, "the box", "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := site.Publish(srv.Store, ""); err != nil {
			t.Fatal(err)
		}
	}
	withBox([]any{map[string]any{assistant.SectionKind: map[string]any{
		"title": "Ask us", assistant.BoxField: "help"}}})

	private := func() string {
		w := decideForm(t, srv, "/assistants/save", token, url.Values{"name": {"help"},
			"full": {"1"}, "title": {"Ask the shop"}})
		return w.Header().Get("Location")
	}
	remove := func() string {
		return decideForm(t, srv, "/assistants/remove", token, url.Values{"name": {"help"}}).Header().Get("Location")
	}
	for what, do := range map[string]func() string{"unticking Public": private, "removing it": remove} {
		loc := do()
		if !strings.Contains(loc, url.QueryEscape("the live page index, section 1 (Ask us), opens help")) ||
			!strings.Contains(loc, url.QueryEscape("the draft page index, section 1 (Ask us), opens help")) {
			t.Errorf("%s was not refused with where the box is: %s", what, loc)
		}
		if a, ok := fa.set.Get("help"); !ok || !a.Public {
			t.Fatalf("%s went through: %+v", what, a)
		}
	}

	withBox(nil)
	if loc := private(); strings.Contains(loc, "e=") {
		t.Fatalf("making a chatbot no box opens private was refused: %s", loc)
	}
	if loc := remove(); strings.Contains(loc, "e=") {
		t.Fatalf("removing a chatbot no box opens was refused: %s", loc)
	}
	if _, ok := fa.set.Get("help"); ok {
		t.Fatal("the chatbot was not removed")
	}
}

// Applying the sections starter in the browser says which chatbot its
// question box opens and what to do about it, as quilzo template use
// does; once the site has that chatbot public it says nothing.
func TestApplyingAStarterSaysWhatItsQuestionBoxNeeds(t *testing.T) {
	srv, token, fa := chatbots(t)
	srv.Transfer = &Transfer{
		Pages: func() (map[string]any, error) { return srv.draftPages() },
		Save:  func(map[string]any, string, string, string) error { return nil },
	}
	apply := func() string {
		t.Helper()
		w := decideForm(t, srv, "/transfer/starter", token, url.Values{"name": {"sections"}, "page": {"start"}})
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if e := loc.Query().Get("e"); e != "" {
			t.Fatalf("applying the starter was refused: %s", e)
		}
		return loc.Query().Get("m")
	}
	if got := apply(); !strings.Contains(got, "Its question box opens help, which this site does not have: "+
		"declare it on the Chatbots screen and make it public") {
		t.Errorf("a site without the chatbot: %s", got)
	}
	if err := fa.set.Put(assistant.Assistant{Name: "help", Title: "Help"}); err != nil {
		t.Fatal(err)
	}
	if got := apply(); !strings.Contains(got, "Its question box opens help, which is not public") {
		t.Errorf("a site with the chatbot private: %s", got)
	}
	if err := fa.set.Put(assistant.Assistant{Name: "help", Title: "Help", Public: true}); err != nil {
		t.Fatal(err)
	}
	if got := apply(); strings.Contains(got, "question box") {
		t.Errorf("a site with the chatbot public was told about it: %s", got)
	}
}

// A form action is checked against the form it fills in when it is added:
// a form that is not there, or a field it does not ask for, is refused
// with what there is; a sensitive field is let through and said, because
// it is never filled in.
func TestAFormActionIsCheckedWhenItIsAdded(t *testing.T) {
	srv, token, fa := chatbots(t)
	if err := fa.set.Put(assistant.Assistant{Name: "help", Title: "Help"}); err != nil {
		t.Fatal(err)
	}
	add := func(target, fields string) string {
		t.Helper()
		w := decideForm(t, srv, "/assistants/action", token, url.Values{"assistant": {"help"},
			"action": {"start-return"}, "kind": {"form"}, "target": {target},
			"description": {"start a return"}, "fields": {fields}})
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if e := loc.Query().Get("e"); e != "" {
			return "refused: " + e
		}
		return loc.Query().Get("m")
	}
	actions := func() int { a, _ := fa.set.Get("help"); return len(a.Actions) }

	if got := add("refunds", "order"); !strings.Contains(got, `"refunds", which this site does not have`) ||
		!strings.Contains(got, "returns_form") {
		t.Errorf("a form that does not exist: %s", got)
	}
	if got := add("returns_form", "order, email"); !strings.Contains(got, "email, which the form returns_form does not ask for") ||
		!strings.Contains(got, assistant.SensitiveNever) {
		t.Errorf("a field the form does not ask for: %s", got)
	}
	if actions() != 0 {
		t.Fatal("a refused action was saved")
	}
	if got := add("returns_form", "order, card"); strings.HasPrefix(got, "refused") ||
		!strings.Contains(got, "marks card sensitive") || !strings.Contains(got, assistant.SensitiveNever) {
		t.Errorf("an action listing a sensitive field: %s", got)
	}
	if actions() != 1 {
		t.Fatal("a good action was not saved")
	}

	// The forms not being readable refuses a form action, and leaves a link
	// alone: a link is not a form's to answer for.
	srv.Assistants.Forms = nil
	if got := add("returns_form", "order"); !strings.Contains(got, "cannot read the site's forms") {
		t.Errorf("unread forms: %s", got)
	}
	w := decideForm(t, srv, "/assistants/action", token, url.Values{"assistant": {"help"},
		"action": {"returns-page"}, "kind": {"link"}, "target": {"returns"},
		"description": {"read the returns page"}})
	if strings.Contains(w.Header().Get("Location"), "e=") || actions() != 2 {
		t.Errorf("a link was refused for want of forms: %s", w.Header().Get("Location"))
	}
}

// Above the actions panel, a chatbot that answers without a model is said
// to offer none of them, and why; one with a model is not.
func TestTheActionsPanelSaysActionsNeedAModel(t *testing.T) {
	srv, token, fa := chatbots(t)
	if err := fa.set.Put(assistant.Assistant{Name: "help", Title: "Help"}); err != nil {
		t.Fatal(err)
	}
	page := func() string { return get(t, srv, "/assistants/help", token).Body.String() }

	if html := page(); !strings.Contains(html, assistant.ActionsNeedModel) ||
		!strings.Contains(html, "quotes its pages without one") {
		t.Error("an extractive chatbot's actions panel does not say actions need a model")
	}

	a, _ := fa.set.Get("help")
	a.UseModel = true
	if err := fa.set.Put(a); err != nil {
		t.Fatal(err)
	}
	if html := page(); !strings.Contains(html, assistant.ActionsNeedModel) ||
		!strings.Contains(html, "none can be used") {
		t.Error("a chatbot set to use a model that cannot be used is not told")
	}

	fa.model = unfaithful{}
	if html := page(); strings.Contains(html, assistant.ActionsNeedModel) {
		t.Error("a chatbot with a model is told its actions are never offered")
	}
}

// Promoting to production is publishing, so it is asked the content gates
// about the commit that moves, and refused as Review would refuse it. Not
// wired is not passed. Promoting to an environment the public does not see
// is not asked.
func TestPromotingToProductionAsksTheContentGates(t *testing.T) {
	srv, token := setup(t)
	envs := &site.Envs{Environments: []site.Env{
		{Name: "staging", Ref: "env-staging", Order: 50},
		{Name: "production", Ref: site.RefLive, Order: 100, Production: true},
	}}
	withPipeline(srv, envs)
	draft := srv.Store.GetRef(site.RefDraft)
	var asked []string
	srv.ContentGates = func(ref string) (*publishgate.Report, []publishgate.Finding, error) {
		asked = append(asked, ref)
		return &publishgate.Report{
			Check:    publishgate.Check{Name: "question boxes", Refusal: func(int) string { return "1 question box opens nothing" }},
			Findings: []publishgate.Finding{{Page: "index", Detail: "section 1: names no chatbot"}},
		}, nil, nil
	}
	promote := func(from, to string) string { t.Helper(); return promoteAs(t, srv, token, from, to) }

	if loc := promote("draft", "staging"); strings.Contains(loc, "e=") || len(asked) != 0 {
		t.Fatalf("promoting to staging was checked or refused: %s, asked %v", loc, asked)
	}
	loc := promote("staging", "production")
	if !strings.Contains(loc, "e=") || !strings.Contains(loc, url.QueryEscape("names no chatbot")) {
		t.Fatalf("a commit the gates refuse was promoted to production: %s", loc)
	}
	if len(asked) != 1 || asked[0] != draft {
		t.Errorf("the gates were asked about %v, not the commit that would move (%s)", asked, draft)
	}
	if live := srv.Store.GetRef(site.RefLive); live != "" {
		t.Fatalf("production moved to %s although the gates refused", live)
	}

	srv.ContentGates = nil
	if loc := promote("staging", "production"); !strings.Contains(loc, "e=") {
		t.Fatalf("promoting with no gates wired went through: %s", loc)
	}

	srv.ContentGates = func(string) (*publishgate.Report, []publishgate.Finding, error) {
		return nil, nil, errors.New("the claims file is not JSON")
	}
	if loc := promote("staging", "production"); !strings.Contains(loc, url.QueryEscape("not JSON")) {
		t.Fatalf("a gate that could not run let the promotion through: %s", loc)
	}

	srv.ContentGates = noGates
	markedBy(t, srv, "editor")
	if loc := promote("staging", "production"); strings.Contains(loc, "e=") {
		t.Fatalf("a commit every gate passes was refused: %s", loc)
	}
	if live := srv.Store.GetRef(site.RefLive); live != draft {
		t.Fatalf("production is %q, want %s", live, draft)
	}
}

// withPipeline wires the Publishing screen to these environments.
func withPipeline(srv *Server, envs *site.Envs) {
	srv.Publishing = &Publishing{
		Envs:         func() (*site.Envs, error) { return envs, nil },
		SaveEnvs:     func(*site.Envs) error { return nil },
		Schedule:     func() (*schedule.Schedule, error) { return &schedule.Schedule{}, nil },
		SaveSchedule: func(*schedule.Schedule) error { return nil },
	}
}

// promoteAs presses Promote, and is where it was sent back to.
func promoteAs(t *testing.T, srv *Server, token, from, to string) string {
	t.Helper()
	w := decideForm(t, srv, "/publishing/promote", token, url.Values{"from": {from}, "to": {to}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("promote answered %d", w.Code)
	}
	return w.Header().Get("Location")
}

// markedBy records who wrote every page of the draft, so the provenance
// check passes and a refusal is something else's.
func markedBy(t *testing.T, srv *Server, who string) {
	t.Helper()
	ids, err := site.PageIDsAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	idx := provenance.NewIndex()
	for page, id := range ids {
		if err := idx.Set(page, provenance.Record{SourceType: provenance.HumanEdits,
			ContentHash: id, Author: who}); err != nil {
			t.Fatal(err)
		}
	}
	srv.LoadProvenance = func() (*provenance.Index, error) { return idx, nil }
}

// Promoting to production is asked the rest of what publishing asks, and
// waives none of it: whether this session may publish each page the commit
// changes, whether each page says who wrote it, whether it renders
// accessibly, and the approvals given to those bytes, found for the commit
// that moves rather than for the draft.
func TestPromotingToProductionAsksWhatAPublishAsks(t *testing.T) {
	srv, token := setup(t)
	withPipeline(srv, site.DefaultEnvs())
	draft := srv.Store.GetRef(site.RefDraft)
	live := func() string { return srv.Store.GetRef(site.RefLive) }
	refused := func(why, want string) {
		t.Helper()
		loc := promoteAs(t, srv, token, "draft", "production")
		if !strings.Contains(loc, url.QueryEscape(want)) || live() != "" {
			t.Fatalf("%s: promoted, or refused for something else: %s, live %q", why, loc, live())
		}
	}

	refused("pages nobody said wrote", "without provenance: about, index")
	markedBy(t, srv, "editor")

	if err := srv.Policy.Grant(auth.Binding{Principal: "editor", Role: auth.RolePublisher,
		Resource: "/about", Deny: true}); err != nil {
		t.Fatal(err)
	}
	refused("a page the session may not publish", "would change about, which you may not publish")
	if srv.Policy.Revoke("editor", auth.RolePublisher, "/about") != 1 {
		t.Fatal("the deny was not taken away")
	}

	layouts := srv.Layouts
	srv.Layouts = render.OneLayout(`<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head>
<body><main><h1>{{ page.title }}</h1><img src="/media/plate.png"></main></body></html>`)
	refused("a page with an image nobody described", "blocking accessibility failure")
	srv.Layouts = layouts

	// Two approvals needed, and the proposal for the commit found by For:
	// the draft, here, and so the commit the draft once was in a pipeline.
	prop := &collab.Proposal{Content: draft, Author: "editor", AuthorKind: "human"}
	var askedFor []string
	srv.Approvals = &Approvals{
		Policy:  func() (collab.Policy, error) { return collab.Policy{Required: 1}, nil },
		Current: func() (*collab.Proposal, error) { return nil, errors.New("For is wired, so Current is not asked") },
		For: func(commit string) (*collab.Proposal, error) {
			askedFor = append(askedFor, commit)
			return prop, nil
		},
		Save:   func(*collab.Proposal) error { return nil },
		KindOf: func(string) string { return "human" },
	}
	refused("a commit nobody approved", "0 of 1 approvals")
	if len(askedFor) == 0 || askedFor[0] != draft {
		t.Errorf("the approvals were asked of %v, not of the commit that moves (%s)", askedFor, draft)
	}
	prop.Approvals = []collab.Approval{{Content: draft, By: "ria"}}
	if loc := promoteAs(t, srv, token, "draft", "production"); strings.Contains(loc, "e=") || live() != draft {
		t.Fatalf("an approved, marked commit the session may publish was refused: %s", loc)
	}
}
