// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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

// Trying a decider on the screen is asking it, and what it answered is
// handed on to be recorded, with who asked: an answer given on the
// Decisions screen left no trace of what was decided or by whom.
func TestADecisionTriedOnTheScreenIsHandedOnToBeRecorded(t *testing.T) {
	srv, token := setup(t)
	d, _ := decidersRig()
	type ask struct {
		by    string
		res   decide.Result
		state any
	}
	var asked []ask
	d.Asked = func(by string, res decide.Result, state any) { asked = append(asked, ask{by, res, state}) }
	srv.Deciders = d
	decl := `{"name": "ticket", "title": "Ticket triage", "questions": [
	  {"name": "queue", "ask": "Which team?", "kind": "choice", "options": ["billing", "returns"]}]}`
	if w := decideForm(t, srv, "/decisions/save", token, url.Values{"declaration": {decl}}); w.Code != http.StatusSeeOther {
		t.Fatal(w.Code)
	}
	decideForm(t, srv, "/decisions/ticket", token, url.Values{"state": {`{"body": "refund"}`}})
	if len(asked) != 1 || asked[0].by == "" || asked[0].res.Decider != "ticket" {
		t.Fatalf("handed on %+v", asked)
	}
	if a, _ := asked[0].res.Get("queue"); a.Value != "returns" {
		t.Errorf("the answer handed on is %+v", asked[0].res)
	}
	if m, _ := asked[0].state.(map[string]any); m["body"] != "refund" {
		t.Errorf("the state handed on is %v", asked[0].state)
	}
	// A state that is not JSON is not asked about, and nothing is handed on.
	decideForm(t, srv, "/decisions/ticket", token, url.Values{"state": {`not json`}})
	if len(asked) != 1 {
		t.Errorf("%d asks handed on", len(asked))
	}
}
