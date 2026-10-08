// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/decide"
)

type decidesReturns struct{}

func (decidesReturns) Name() string { return "t" }
func (decidesReturns) Complete(context.Context, string, string) (string, error) {
	return `{"answers": {"queue": {"value": "returns", "confidence": 0.95}, "angry": {"value": "yes", "confidence": 0.4}}}`, nil
}

func decidersRig() (*Deciders, *decide.Set) {
	set := &decide.Set{}
	return &Deciders{
		Load: func() (*decide.Set, error) {
			cp := *set
			cp.Deciders = append([]decide.Decider(nil), set.Deciders...)
			return &cp, nil
		},
		Save:  func(s *decide.Set, _, _, _ string) error { *set = *s; return nil },
		Model: func(string) (decide.Model, string) { return decidesReturns{}, "" },
	}, set
}

func TestADeciderIsDeclaredAndTriedOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	d, set := decidersRig()
	srv.Deciders = d
	decl := `{"name": "ticket", "title": "Ticket triage", "questions": [
	  {"name": "queue", "ask": "Which team?", "kind": "choice", "options": ["billing", "returns"]},
	  {"name": "angry", "ask": "Angry?", "kind": "yesno"}]}`
	w := decideForm(t, srv, "/decisions/save", token, url.Values{"declaration": {decl}})
	if w.Code != http.StatusSeeOther || len(set.Deciders) != 1 {
		t.Fatalf("%d %+v", w.Code, set)
	}
	body := decideForm(t, srv, "/decisions/ticket", token,
		url.Values{"state": {`{"body": "<script>x</script> refund"}`}}).Body.String()
	for _, want := range []string{"returns", "decided", "a person decides", "under the 0.80 threshold"} {
		if !strings.Contains(body, want) {
			t.Errorf("the console does not show %q", want)
		}
	}
	if strings.Contains(body, "<script>x</script>") {
		t.Fatal("the state reached the page unescaped")
	}
	// Nonsense is refused with the reason.
	w = decideForm(t, srv, "/decisions/save", token, url.Values{"declaration": {`{"name": "x"}`}})
	if !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Fatal("an invalid decider was not refused")
	}
}

func TestOnlyAPublisherDeclaresADecider(t *testing.T) {
	d, set := decidersRig()
	author, token := asRole(t, auth.RoleAuthor)
	author.Deciders = d
	decideForm(t, author, "/decisions/save", token, url.Values{"declaration": {
		`{"name": "t", "title": "T", "questions": [{"name": "q", "ask": "?", "kind": "yesno"}]}`}})
	if len(set.Deciders) != 0 {
		t.Fatal("an author declared a decider")
	}
}
