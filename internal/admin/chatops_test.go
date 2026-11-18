// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/gaps"
	"github.com/quilzo/quilzo/internal/gateway"
)

// Changing one limit of a budget on the Models screen keeps the others. The
// form started at zero and a save replaced the caller's whole budget, so an
// owner slowing a public chatbot to thirty calls a minute lifted its money
// and character caps without a word. A field left empty keeps what the
// caller has; 0 is unlimited, as the form says.
func TestABudgetChangedOnTheScreenKeepsWhatItIsNotGiven(t *testing.T) {
	srv, token := setup(t)
	m, cfg := modelsRig()
	cfg.Currency = "GBP"
	srv.Models = m
	save := func(fields url.Values) {
		t.Helper()
		fields.Set("op", "budget")
		fields.Set("name", "chatbot:help")
		if w := decideForm(t, srv, "/models/change", token, fields); strings.Contains(w.Header().Get("Location"), "e=") {
			t.Fatalf("refused: %s", w.Header().Get("Location"))
		}
	}
	budget := func() gateway.Budget {
		t.Helper()
		b, _ := cfg.BudgetFor("chatbot:help")
		return b
	}
	save(url.Values{"chars_per_day": {"100000"}, "money_per_day": {"5.00"}, "money_per_month": {"100"}})
	want := gateway.Budget{Consumer: "chatbot:help", CharsPerDay: 100000, MoneyPerDay: "5.00", MoneyPerMonth: "100"}
	if budget() != want {
		t.Fatalf("the budget saved is %+v", budget())
	}
	// As the form posts it: every field, the ones not typed in empty.
	save(url.Values{"per_minute": {"30"}, "chars_per_day": {""}, "tokens_per_day": {""},
		"money_per_day": {""}, "money_per_month": {""}})
	want.PerMinute = 30
	if budget() != want {
		t.Errorf("one limit changed left %+v", budget())
	}
	save(url.Values{"chars_per_day": {"0"}, "money_per_day": {"0"}})
	want.CharsPerDay, want.MoneyPerDay = 0, ""
	if budget() != want {
		t.Errorf("limits set to unlimited left %+v", budget())
	}
	if body := get(t, srv, "/models", token).Body.String(); strings.Contains(body, `name="per_minute" type="number" min="0" value="0"`) {
		t.Error("the form still starts at zero, which would lift a limit it was not meant to")
	}
}

// The test console asks for the model as the person signed in, so what it
// spends is charged to them and not to the chatbot's visitors' budget. It
// asked as nobody, and every question an owner tried there was charged to
// the chatbot.
func TestTheConsoleAsksAsThePersonTryingIt(t *testing.T) {
	srv, token, fa := chatbots(t)
	fa.set.Put(assistant.Assistant{Name: "help", Title: "Help", UseModel: true})
	fa.model = unfaithful{}
	get(t, srv, "/assistants/help?q="+url.QueryEscape("can I return opened ink"), token)
	if len(fa.triedBy) != 1 || fa.triedBy[0] == "" {
		t.Fatalf("the console asked for the model for %q", fa.triedBy)
	}
}

// A reader may list the chatbots and try one on the Chatbots screen, as on
// the command line and over the agent interface, and what visitors could
// not get answered stays an author's, as it is on those two. The screen
// refused a reader every chatbot while `assistant list` and `assistant ask`
// answered them, so who could try a chatbot depended on where they asked.
func TestAReaderTriesAChatbotOnTheScreenAndReadsNoVisitorsWords(t *testing.T) {
	fa := &fakeAssistants{set: &assistant.Set{Assistants: []assistant.Assistant{{Name: "help", Title: "Help"}}}}
	closed := 0
	wire := func(srv *Server) {
		srv.Assistants = fa.wire()
		srv.Assistants.Gaps = func(string) ([]gaps.Group, bool, error) {
			return []gaps.Group{{Key: "zqbarra", Count: 2, Questions: []string{"Do you ship to Zqbarra island?"}}}, true, nil
		}
		srv.Assistants.Ratings = func(string) (int, int) { return 3, 1 }
		srv.Assistants.CheckGaps = func(context.Context, string, string) (int, int, error) { return 0, 0, nil }
		srv.Assistants.CloseGap = func(string, string, string) error { closed++; return nil }
	}
	reader, token := asRole(t, auth.RoleReader)
	wire(reader)
	if w := get(t, reader, "/assistants", token); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/assistants/help") {
		t.Errorf("a reader was refused the list of chatbots (%d)", w.Code)
	}
	w := get(t, reader, "/assistants/help?q="+url.QueryEscape("can I return opened ink"), token)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "cannot be returned") {
		t.Fatalf("a reader could not try the chatbot (%d)", w.Code)
	}
	body := w.Body.String()
	for _, words := range []string{"Zqbarra", "Whether its answers helped", "/assistants/save", "/assistants/action"} {
		if strings.Contains(body, words) {
			t.Errorf("a reader is shown %q", words)
		}
	}
	decideForm(t, reader, "/assistants/gaps", token, url.Values{"name": {"help"}, "do": {"close"}, "key": {"zqbarra"}})
	if closed != 0 {
		t.Error("a reader closed a group of visitors' questions")
	}

	author, token := asRole(t, auth.RoleAuthor)
	wire(author)
	if body := get(t, author, "/assistants/help", token).Body.String(); !strings.Contains(body, "Zqbarra") {
		t.Error("an author is not shown what the chatbot could not answer")
	}
	decideForm(t, author, "/assistants/gaps", token, url.Values{"name": {"help"}, "do": {"close"}, "key": {"zqbarra"}})
	if closed != 1 {
		t.Error("an author could not close a group")
	}
}

// An author builds a chatbot that is not public on the Chatbots screen, as
// on the command line and over the agent interface: what it is called and
// says and which pages it reads. The rest is shown to them, switched off,
// and stays a publisher's, as does any change to a public chatbot. The
// screen let only a publisher save, while an author's agent changed the
// same settings through declare_assistant.
func TestAnAuthorBuildsAPrivateChatbotOnTheScreen(t *testing.T) {
	fa := &fakeAssistants{set: &assistant.Set{Assistants: []assistant.Assistant{{Name: "help", Title: "Help",
		Exclude: []string{"returns"}, UseModel: true, Collections: []string{"orders"}}}}}
	author, token := asRole(t, auth.RoleAuthor)
	author.Assistants = fa.wire()
	body := get(t, author, "/assistants/help", token).Body.String()
	if !strings.Contains(body, `action="/assistants/save"`) || !strings.Contains(body, `id="title" name="title"`) {
		t.Fatal("an author is not given the settings they may change")
	}
	for _, field := range []string{"collections", "route", "handoff_days", "nudge"} {
		if !regexp.MustCompile(`<input id="` + field + `"[^>]* disabled`).MatchString(body) {
			t.Errorf("%s, a publisher's, is not switched off for an author", field)
		}
	}
	if strings.Contains(body, `action="/assistants/action"`) || strings.Contains(body, `action="/assistants/remove"`) {
		t.Error("an author is offered what a chatbot may do, or its removal")
	}
	// As the browser posts it, and with what a switched-off field would
	// have said added by hand: only what an author builds changes.
	decideForm(t, author, "/assistants/save", token, url.Values{"name": {"help"}, "full": {"1"},
		"title": {"Front desk"}, "greeting": {"Hi"}, "instructions": {""}, "refusal": {""}, "pages": {""},
		"exclude": {"returns, legal"}, "public": {"1"}, "collections": {""}})
	a, _ := fa.set.Get("help")
	if a.Title != "Front desk" || a.Greeting != "Hi" || strings.Join(a.Exclude, ",") != "returns,legal" {
		t.Errorf("what an author builds did not change: %+v", a)
	}
	if a.Public || !a.UseModel || strings.Join(a.Collections, ",") != "orders" {
		t.Errorf("an author changed what is a publisher's: %+v", a)
	}
	decideForm(t, author, "/assistants/save", token, url.Values{"name": {"spare"}, "title": {"Spare"}})
	if b, ok := fa.set.Get("spare"); !ok || b.Public {
		t.Errorf("an author could not make a private chatbot: %+v %v", b, ok)
	}
	decideForm(t, author, "/assistants/remove", token, url.Values{"name": {"spare"}})
	if _, ok := fa.set.Get("spare"); !ok {
		t.Error("an author removed a chatbot")
	}

	// Public, it is a publisher's to change.
	a.Public = true
	fa.set.Put(a)
	if body := get(t, author, "/assistants/help", token).Body.String(); strings.Contains(body, `action="/assistants/save"`) {
		t.Error("an author is offered the settings of a public chatbot")
	}
	decideForm(t, author, "/assistants/save", token, url.Values{"name": {"help"}, "full": {"1"}, "title": {"Renamed"}})
	if a, _ := fa.set.Get("help"); a.Title != "Front desk" {
		t.Errorf("an author changed a public chatbot: %+v", a)
	}
}
