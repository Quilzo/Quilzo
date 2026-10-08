// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/handoff"
	"github.com/quilzo/quilzo/internal/render"
)

// From the visitor's question on the published site, through the inbox, to
// the answer on the visitor's page, with the site and this command each
// doing their half — which is how it runs.
func TestAVisitorAsksForAPersonAndIsAnsweredFromTheInbox(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Ask the shop",
		"--public", "--handoff", "--handoff-days", "14"}); err != nil {
		t.Fatal(err)
	}
	st, err := siteFor(root, &Design{Layouts: render.OneLayout(
		`<!doctype html><html lang="en"><head><title>{{ page.title }}</title>` +
			`</head><body>{{ page.body }}</body></html>`)}, siteOpts{})
	if err != nil {
		t.Fatal(err)
	}
	post := func(path string, v url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.20:5555"
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, req)
		return w
	}
	if body := post("/ask/help", url.Values{"q": {"can I return opened ink"}}).Body.String(); !strings.Contains(body, "Talk to a person") {
		t.Fatal("the published chatbot does not offer a person")
	}
	w := post("/ask/help/handoff", url.Values{"q": {"can I return opened ink"},
		"message": {"My bottle leaked in the post"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("asking for a person answered %d: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")

	all, err := handoffStore(root).List()
	if err != nil || len(all) != 1 || !all[0].Waiting() {
		t.Fatalf("the inbox holds %+v (%v)", all, err)
	}
	ref := "help/" + all[0].ID
	if err := cmdInbox(root, []string{"reply", ref, "Sorry to hear it. A replacement is on its way."}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, loc, nil)
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "A replacement is on its way") {
		t.Fatal("the visitor does not see the answer")
	}

	// The log knows a conversation happened, who answered, and nothing of
	// what anybody said.
	events, _ := audit.Read(auditPath(root))
	var actions []string
	for _, e := range events {
		if strings.HasPrefix(e.Action, "handoff.") {
			actions = append(actions, e.Action)
			for _, v := range e.Detail {
				if strings.Contains(v, "leaked") || strings.Contains(v, "replacement") {
					t.Errorf("the log carries what was said: %v", e.Detail)
				}
			}
			if e.Detail["conversation"] != all[0].ID {
				t.Errorf("%s does not name the conversation", e.Action)
			}
		}
	}
	if strings.Join(actions, " ") != "handoff.open handoff.reply" {
		t.Errorf("the log says %v", actions)
	}

	if err := cmdInbox(root, []string{"close", ref}); err != nil {
		t.Fatal(err)
	}
	if err := cmdInbox(root, []string{"reply", ref, "one more"}); err == nil {
		t.Error("a reply reached an ended conversation")
	}
	for _, bad := range [][]string{{"reply", "help", "x"}, {"show", "help/../x"},
		{"reply", "help/" + all[0].ID}, {"close"}} {
		if err := cmdInbox(root, bad); err == nil {
			t.Errorf("inbox %v was accepted", bad)
		}
	}
}

func TestASuggestionComesFromTheSiteOrNotAtAll(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Ask the shop",
		"--handoff"}); err != nil {
		t.Fatal(err)
	}
	draft, sources, err := suggestReply(root, "help", "can I return opened ink")
	if err != nil {
		t.Fatal(err)
	}
	if draft == "" || len(sources) == 0 {
		t.Errorf("the suggestion is %q from %v", draft, sources)
	}
	// Written to be sent: no [n] markers pointing at a source list the
	// visitor never sees.
	if strings.Contains(draft, "[1]") {
		t.Errorf("the suggestion carries citation markers: %q", draft)
	}
	if _, _, err := suggestReply(root, "help", "what is the airspeed of a swallow"); err == nil {
		t.Error("a question the site does not answer produced a suggestion")
	}
	if _, _, err := suggestReply(root, "gone", "returns"); err == nil {
		t.Error("an assistant that does not exist made a suggestion")
	}
}

func TestConversationsGoWhenTheirAssistantSaysAndNotBefore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Ask the shop",
		"--handoff", "--handoff-days", "7"}); err != nil {
		t.Fatal(err)
	}
	st := handoffStore(root)
	now := time.Now()
	_, old, _ := handoff.NewSecret()
	_, fresh, _ := handoff.NewSecret()
	st.Open("help", old, "", "a week and a day ago", now.Add(-8*24*time.Hour))
	st.Open("help", fresh, "", "yesterday", now.Add(-24*time.Hour))
	job, ok := retentionJob(root)
	if !ok {
		t.Fatal("there is no retention job")
	}
	if _, err := job.Do(now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get("help", old); err != handoff.ErrNotFound {
		t.Error("a conversation past its assistant's period is still kept")
	}
	if _, err := st.Get("help", fresh); err != nil {
		t.Error("a recent conversation was deleted")
	}
}

func TestAModelDoesNotAnswerAVisitor(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := publishedShop(t)
	_, id, _ := handoff.NewSecret()
	handoffStore(root).Open("help", id, "", "hello", time.Now())
	model := &Caller{Name: "agent/support", Kind: audit.KindAI, Verified: true,
		Role: "admin"}
	for _, act := range []string{"reply", "close"} {
		if err := inboxAnswer(root, act, "help/"+id, "I am a model", model); err == nil {
			t.Errorf("a model could %s a conversation with a visitor", act)
		}
	}
	if c, _ := handoffStore(root).Get("help", id); len(c.Messages) != 1 || c.Closed {
		t.Errorf("the conversation changed: %+v", c)
	}
}
