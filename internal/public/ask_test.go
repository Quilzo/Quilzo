// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/throttle"
)

func askSite(t *testing.T, a ...assistant.Assistant) (*Site, *[]bool) {
	t.Helper()
	st := published(t, map[string]any{
		"index":         map[string]any{"title": "Marginalia", "intro": "Paper, made in small runs."},
		"returns":       map[string]any{"title": "Returns", "body": "Opened ink bottles cannot be returned. Unopened items can be returned within 30 days."},
		"drafts/secret": map[string]any{"title": "Pricing plan", "body": "Next year the copper pen goes up to £60."},
	})
	set := &assistant.Set{}
	for _, x := range a {
		if err := set.Put(x); err != nil {
			t.Fatal(err)
		}
	}
	var audited []bool
	st.Assistants = &Assistants{
		Set: func() (*assistant.Set, error) { return set, nil },
		Forms: func() (*form.Set, error) {
			return &form.Set{Forms: []form.Form{{Name: "returns_form", Label: "Start a return",
				Notice: "n", Fields: []form.Field{
					{Name: "order", Label: "Order", Kind: form.Line, Required: true},
					{Name: "card", Label: "Card number", Kind: form.Line, Sensitive: true},
				}}}}, nil
		},
		Audit: func(_, _ string, answered bool) { audited = append(audited, answered) },
	}
	return st, &audited
}

func askPost(st *Site, name, q string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ask/"+name,
		strings.NewReader(url.Values{"q": {q}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "198.51.100.4:1234"
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	return w
}

var shopBot = assistant.Assistant{Name: "help", Title: "Ask the shop", Public: true,
	Exclude: []string{"drafts"}}

func TestAVisitorGetsACitedAnswer(t *testing.T) {
	st, audited := askSite(t, shopBot)
	if w := get(st, "/ask/help", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Your question") {
		t.Fatalf("the ask page: %d", w.Code)
	}
	w := askPost(st, "help", "can I return opened ink?")
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "cannot be returned") {
		t.Fatalf("%d\n%s", w.Code, body)
	}
	if !strings.Contains(body, `href="/returns"`) {
		t.Fatal("the answer does not link to its source")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("an answer to one person's question is cacheable")
	}
	if len(*audited) != 1 || !(*audited)[0] {
		t.Fatalf("audit %v", *audited)
	}
}

func TestAnExcludedPageIsNeverAnAnswer(t *testing.T) {
	st, _ := askSite(t, shopBot)
	body := askPost(st, "help", "what will the copper pen cost next year").Body.String()
	if strings.Contains(body, "£60") {
		t.Fatal("the assistant answered from a page it was told not to read")
	}
	if !strings.Contains(body, "could not find") {
		t.Fatalf("it did not say it did not know:\n%s", body)
	}
}

func TestAPrivateAssistantIsNotThere(t *testing.T) {
	private := shopBot
	private.Name, private.Public = "internal", false
	st, _ := askSite(t, shopBot, private)
	for _, path := range []string{"/ask/internal", "/ask/nope"} {
		if w := get(st, path, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d", path, w.Code)
		}
	}
	if w := askPost(st, "internal", "returns"); w.Code != http.StatusNotFound {
		t.Errorf("a private assistant answered a post: %d", w.Code)
	}
}

func TestWhatAVisitorTypesIsEscaped(t *testing.T) {
	st, _ := askSite(t, shopBot)
	body := askPost(st, "help", `<script>alert(1)</script> returns?`).Body.String()
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("the question reached the page unescaped")
	}
}

func TestQuestionsAreRateLimited(t *testing.T) {
	st, _ := askSite(t, shopBot)
	st.Assistants.Limit = throttle.New(throttle.Default())
	var last int
	for i := 0; i < 20; i++ {
		last = askPost(st, "help", "returns").Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("twenty questions from one address, last answered %d", last)
	}
}

// offering scripts an answer that proposes the returns form.
type offering struct{}

func (offering) Name() string { return "offering" }
func (offering) Complete(context.Context, string, string) (string, error) {
	return `{"answer": "Unopened items can be returned within 30 days [1].",
	  "action": {"name": "start-return", "args": {"order": "Q-1043", "card": "4111111111111111"}}}`, nil
}

// TestAFormIsOfferedForTheVisitorToSend.
//
// The assistant fills in the form and the visitor sends it. The form's own
// honeypot and timing stamp come with it, so it is the same way in as the
// page's own form, and a field the owner marked sensitive is never filled.
func TestAFormIsOfferedForTheVisitorToSend(t *testing.T) {
	bot := shopBot
	bot.UseModel = true
	bot.Actions = []assistant.Action{{Name: "start-return", Kind: assistant.Form,
		Target: "returns_form", Description: "start a return",
		Fields: []string{"order", "card"}}}
	st, _ := askSite(t, bot)
	st.Assistants.Model = func(assistant.Assistant) assistant.Model { return offering{} }
	body := askPost(st, "help", "I want to return unopened items").Body.String()
	for _, want := range []string{`action="/form/returns_form"`, `value="Q-1043"`,
		`name="` + form.Honeypot + `"`, `name="` + form.StampField + `"`,
		"nothing is sent until you do"} {
		if !strings.Contains(body, want) {
			t.Errorf("the offered form lacks %s", want)
		}
	}
	if strings.Contains(body, "4111111111111111") {
		t.Fatal("a sensitive field was pre-filled")
	}
}
