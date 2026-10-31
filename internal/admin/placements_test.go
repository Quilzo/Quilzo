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
	publishgate "github.com/quilzo/quilzo/internal/gate"
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
	srv.Publishing = &Publishing{
		Envs:         func() (*site.Envs, error) { return envs, nil },
		SaveEnvs:     func(*site.Envs) error { return nil },
		Schedule:     func() (*schedule.Schedule, error) { return &schedule.Schedule{}, nil },
		SaveSchedule: func(*schedule.Schedule) error { return nil },
	}
	draft := srv.Store.GetRef(site.RefDraft)
	var asked []string
	srv.ContentGates = func(ref string) (*publishgate.Report, []publishgate.Finding, error) {
		asked = append(asked, ref)
		return &publishgate.Report{
			Check:    publishgate.Check{Name: "question boxes", Refusal: func(int) string { return "1 question box opens nothing" }},
			Findings: []publishgate.Finding{{Page: "index", Detail: "section 1: names no chatbot"}},
		}, nil, nil
	}
	promote := func(from, to string) string {
		t.Helper()
		w := decideForm(t, srv, "/publishing/promote", token, url.Values{"from": {from}, "to": {to}})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("promote answered %d", w.Code)
		}
		return w.Header().Get("Location")
	}

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
	if loc := promote("staging", "production"); strings.Contains(loc, "e=") {
		t.Fatalf("a commit every gate passes was refused: %s", loc)
	}
	if live := srv.Store.GetRef(site.RefLive); live != draft {
		t.Fatalf("production is %q, want %s", live, draft)
	}
}
