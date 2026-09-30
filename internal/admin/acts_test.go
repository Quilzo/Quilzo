// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/incident"
)

// wireActs gives the cases screen one installed action that may act on one
// account, carried out by a stand-in that records what it was asked.
func wireActs(srv *Server, kept map[string]*incident.Incident) *[]string {
	sent := &[]string{}
	srv.Cases.Actions = func(id string) ([]ActionOffer, error) {
		return []ActionOffer{{Name: "okta-suspend-user",
			Title:      "Suspend an Okta account",
			Effect:     "The account cannot sign in.",
			Reverts:    "Unsuspending puts it back as it was.",
			Reversible: true, Targets: []string{"okta:00u1a2b3c4d5e6f7"}},
			// Installed, and nothing in this incident it may act on.
			{Name: "okta-clear-sessions", Title: "Clear an Okta account's sessions",
				Effect: "x", Reverts: "y"}}, nil
	}
	srv.Cases.ActRequest = func(id, by, name, target, why string) error {
		if target != "okta:00u1a2b3c4d5e6f7" {
			return fmt.Errorf("%s is not something this incident is about", target)
		}
		_, err := kept[id].RequestAct(incident.Act{Action: name,
			Title: "Suspend an Okta account", Target: target, Reversible: true,
			Says: "POST https://acme.okta.com/api/v1/users/00u1a2b3c4d5e6f7/lifecycle/suspend"},
			by, why, time.Now().UTC())
		return err
	}
	srv.Cases.ActApprove = func(id, by string, act int) (int, error) {
		a, err := kept[id].ApproveAct(act, by, time.Now().UTC())
		if err != nil {
			return 0, err
		}
		*sent = append(*sent, a.Says)
		return 200, kept[id].FinishAct(act, true, 200, time.Now().UTC())
	}
	srv.Cases.ActUndo = func(id, by string, act int, why string) (int, error) {
		if _, err := kept[id].UndoAct(act, by, why, time.Now().UTC()); err != nil {
			return 0, err
		}
		*sent = append(*sent, "undo")
		return 200, kept[id].FinishUndo(act, true, 200, time.Now().UTC())
	}
	return sent
}

func TestAnActionOnTheScreenShowsTheCallAndWaitsForASecondPerson(t *testing.T) {
	srv, token := setup(t)
	kept := wireCases(srv)
	sent := wireActs(srv, kept)
	caseAct(t, srv, token, url.Values{"do": {"declare"}, "title": {"Dana's account"},
		"grade": {"sev2"}})
	var id string
	for k := range kept {
		id = k
	}
	do := func(v url.Values) string {
		v.Set("id", id)
		_, loc := caseAct(t, srv, token, v)
		return loc
	}
	page := func() string {
		body := get(t, srv, "/security/case/"+id, token).Body.String()
		whole(t, body)
		return body
	}
	body := page()
	for _, want := range []string{"Actions on other tools",
		"The account cannot sign in", "Unsuspending puts it back",
		`<option value="okta:00u1a2b3c4d5e6f7">`} {
		if !strings.Contains(body, want) {
			t.Errorf("the offer lacks %q", want)
		}
	}
	// An action with nothing in this incident to act on is not offered.
	if strings.Contains(body, "Clear an Okta account") {
		t.Error("an action was offered with no account it may act on")
	}
	// A target typed in, which the select never offered.
	if loc := do(url.Values{"do": {"act-request"}, "action": {"okta-suspend-user"},
		"target": {"okta:00u9z9z9z9z9z9z9"}, "text": {"x"}}); !strings.Contains(loc, "e=") {
		t.Error("an account the incident is not about was accepted")
	}
	if loc := do(url.Values{"do": {"act-request"}, "action": {"okta-suspend-user"},
		"target": {"okta:00u1a2b3c4d5e6f7"}, "text": {"sessions from two countries"}}); !strings.Contains(loc, "m=") {
		t.Fatalf("request: %s", loc)
	}
	if len(*sent) != 0 {
		t.Fatal("asking sent it")
	}
	body = page()
	for _, want := range []string{"waiting for approval",
		"POST https://acme.okta.com/api/v1/users/00u1a2b3c4d5e6f7/lifecycle/suspend",
		"Approve and send", "sessions from two countries"} {
		if !strings.Contains(body, want) {
			t.Errorf("the request lacks %q", want)
		}
	}
	// Whoever asked does not approve, and nothing goes.
	if loc := do(url.Values{"do": {"act-approve"}, "act": {"1"}}); !strings.Contains(loc, "e=") || len(*sent) != 0 {
		t.Fatalf("the requester approved their own request: %s", loc)
	}
	// Commanding it, they may.
	do(url.Values{"do": {"assign"}, "role": {"commander"}, "who": {kept[id].By}})
	if loc := do(url.Values{"do": {"act-approve"}, "act": {"1"}}); !strings.Contains(loc, "m=") ||
		!strings.Contains(loc, "answered+200") || len(*sent) != 1 {
		t.Fatalf("approve: %s, %d sent", loc, len(*sent))
	}
	body = page()
	if !strings.Contains(body, "in force") || !strings.Contains(body, "Undo it") ||
		!strings.Contains(body, "the tool answered 200") {
		t.Error("a done action is not shown as in force, with its undo")
	}
	if loc := do(url.Values{"do": {"act-undo"}, "act": {"1"}}); !strings.Contains(loc, "e=") {
		t.Error("undone with no reason")
	}
	if loc := do(url.Values{"do": {"act-undo"}, "act": {"1"},
		"text": {"cleared by the owner"}}); !strings.Contains(loc, "m=") || len(*sent) != 2 {
		t.Fatalf("undo: %s", loc)
	}
	if !strings.Contains(page(), "undone") {
		t.Error("an undone action is not shown as undone")
	}
	// A request can be withdrawn, and a withdrawn one offers nothing.
	kept[id].Acts = nil
	do(url.Values{"do": {"act-request"}, "action": {"okta-suspend-user"},
		"target": {"okta:00u1a2b3c4d5e6f7"}, "text": {"again"}})
	if loc := do(url.Values{"do": {"act-withdraw"}, "act": {"1"},
		"text": {"not needed"}}); !strings.Contains(loc, "m=") {
		t.Fatalf("withdraw: %s", loc)
	}
	if body = page(); strings.Contains(body, "Approve and send") {
		t.Error("a withdrawn request can still be approved")
	}
}
