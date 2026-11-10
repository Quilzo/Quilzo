// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/site"
)

// defaultStorePolicy is the approval policy of a store nobody configured:
// no count of approvals, and a person approves what a model wrote, always
// (cmd/quilzo loadApprovalPolicy).
func defaultStorePolicy() (collab.Policy, error) {
	return collab.Policy{RequireHumanForAI: true}, nil
}

// draftWrittenBy commits a draft with this message and returns it.
func draftWrittenBy(t *testing.T, srv *Server, message string) string {
	t.Helper()
	pages := map[string]any{
		"index": map[string]any{"title": "Rewritten", "body": "A model's homepage."},
		"about": map[string]any{"title": "About", "body": "Who we are."},
	}
	if _, err := site.SaveDraft(srv.Store, pages, message, "writer"); err != nil {
		t.Fatal(err)
	}
	return srv.Store.GetRef(site.RefDraft)
}

// A model's draft in a store with no approval count set does not go live
// from Review → Publish until a person approves it.
//
// The command line and the machine interface refused it: a person approves
// what a model wrote, whatever the count, and nothing turns that off. The
// browser asked about approvals only when the count was above zero, which
// on a store nobody configured it never is, so Publish put an agent's
// draft live with nobody having read it — on the surface the rule matters
// most on, since that is where people publish.
func TestTheBrowserRefusesToPublishAModelsDraftNobodyApproved(t *testing.T) {
	for _, recorded := range []bool{true, false} {
		srv, token := setup(t)
		draft := draftWrittenBy(t, srv, collab.AgentPrefix+"rewrote the homepage")
		// The proposal the command line would make for these bytes, or
		// none at all, as a store that never offered the draft has.
		prop := &collab.Proposal{Content: draft, Author: "writer", AuthorKind: "ai",
			CreatedAt: time.Now().Unix(), Message: collab.AgentPrefix + "rewrote the homepage"}
		srv.Approvals = &Approvals{
			Policy: defaultStorePolicy,
			Current: func() (*collab.Proposal, error) {
				if !recorded {
					return nil, nil
				}
				return prop, nil
			},
			Save:   func(p *collab.Proposal) error { prop = p; return nil },
			KindOf: func(string) string { return "human" },
		}

		w := postForm(t, srv, "/publish", token, "reason=go")
		if live := srv.Store.GetRef(site.RefLive); live != "" {
			t.Fatalf("a model's draft went live from the browser with no person's approval "+
				"(proposal recorded: %v)", recorded)
		}
		if body := w.Body.String(); !strings.Contains(body, "person") {
			t.Errorf("the refusal does not say a person's approval is what is needed "+
				"(proposal recorded: %v):\n%s", recorded, body)
		}
		page := get(t, srv, "/review", token).Body.String()
		if !strings.Contains(page, "A model wrote this change") && recorded {
			t.Error("the review screen does not say a model wrote the change it refused")
		}
		if !strings.Contains(page, `action="/review/propose"`) && !recorded {
			t.Error("the review screen does not offer the model's draft for review")
		}

		if !recorded {
			continue
		}

		// A person approving it is the way through.
		if w := postForm(t, srv, "/review/approve", token, "note=read+it"); w.Code >= 400 {
			t.Fatalf("approving answered %d", w.Code)
		}
		if w := postForm(t, srv, "/publish", token, "reason=go"); w.Code != http.StatusOK {
			t.Fatalf("a model's draft a person approved was refused (%d):\n%s", w.Code, w.Body)
		}
		if live := srv.Store.GetRef(site.RefLive); live != draft {
			t.Fatalf("live is %q, not the approved draft %q", live, draft)
		}
	}
}

// A person's own draft in that store still publishes with nobody else
// asked, and the review screen does not ask for an approval it does not
// need: the rule is about what a model wrote, and one person running their
// own site must not find they can no longer publish their own words.
func TestAPersonsDraftStillPublishesWithNoApprovalCountSet(t *testing.T) {
	srv, token := setup(t)
	draft := draftWrittenBy(t, srv, "fixed a typo")
	srv.Approvals = &Approvals{
		Policy: defaultStorePolicy,
		Current: func() (*collab.Proposal, error) {
			return &collab.Proposal{Content: draft, Author: "writer", AuthorKind: "human"}, nil
		},
		Save:   func(*collab.Proposal) error { return nil },
		KindOf: func(string) string { return "human" },
	}
	if page := get(t, srv, "/review", token).Body.String(); strings.Contains(page, "<h2>Approval</h2>") {
		t.Error("the review screen asks for an approval a person's own draft does not need")
	}
	if w := postForm(t, srv, "/publish", token, "reason=go"); w.Code != http.StatusOK {
		t.Fatalf("a person's draft was refused (%d):\n%s", w.Code, w.Body)
	}
	if live := srv.Store.GetRef(site.RefLive); live != draft {
		t.Fatalf("live is %q, not the draft %q", live, draft)
	}
}

// An approval policy the server cannot read refuses the publish and says
// so on the review screen, rather than reading as "nothing is required".
func TestTheReviewScreenSaysTheApprovalPolicyCouldNotBeRead(t *testing.T) {
	srv, token := setup(t)
	srv.Approvals = &Approvals{
		Policy: func() (collab.Policy, error) {
			return collab.Policy{}, errors.New("approval.json: unexpected end of JSON input")
		},
		Current: func() (*collab.Proposal, error) { return nil, nil },
		Save:    func(*collab.Proposal) error { return nil },
	}
	w := postForm(t, srv, "/publish", token, "reason=go")
	if live := srv.Store.GetRef(site.RefLive); live != "" {
		t.Fatal("the browser published with an approval policy it could not read")
	}
	if !strings.Contains(w.Body.String(), "approval policy could not be read") {
		t.Errorf("the refusal does not say why:\n%s", w.Body)
	}
	if page := get(t, srv, "/review", token).Body.String(); !strings.Contains(page, "approval policy could not be read") {
		t.Error("the review screen does not say the approval policy could not be read")
	}
}

// A model's change in the draft does not go live from Review → Publish
// because a person committed something after it, and offering that draft
// for review offers it as a model's.
//
// The browser asked only the draft's newest commit who wrote it. An agent
// rewrote the homepage, a person then fixed a typo on About, and the
// newest commit was the person's: no approval was asked for with no count
// set, a proposal for the draft was made as the person's, and Publish put
// the agent's homepage live with nobody having read it.
func TestTheBrowserRefusesAModelsChangeUnderAPersonsLaterCommit(t *testing.T) {
	for _, recorded := range []bool{true, false} {
		srv, token := setup(t)
		agents := draftWrittenBy(t, srv, collab.AgentPrefix+"rewrote the homepage")
		pages, err := site.PagesAt(srv.Store, site.RefDraft)
		if err != nil {
			t.Fatal(err)
		}
		pages["about"] = map[string]any{"title": "About", "body": "Who we are, spelt right."}
		if _, err := site.SaveDraft(srv.Store, pages, "fixed a typo", "writer"); err != nil {
			t.Fatal(err)
		}
		draft := srv.Store.GetRef(site.RefDraft)
		// A proposal recorded as the person's, as one made by reading the
		// newest commit was, or none at all.
		prop := &collab.Proposal{Content: draft, Author: "writer", AuthorKind: "human",
			CreatedAt: time.Now().Unix(), Message: "fixed a typo"}
		srv.Approvals = &Approvals{
			Policy: defaultStorePolicy,
			Current: func() (*collab.Proposal, error) {
				if !recorded {
					return nil, nil
				}
				return prop, nil
			},
			Save:   func(p *collab.Proposal) error { prop = p; return nil },
			KindOf: func(string) string { return "human" },
		}

		w := postForm(t, srv, "/publish", token, "reason=go")
		if live := srv.Store.GetRef(site.RefLive); live != "" {
			t.Fatalf("a model's change went live from the browser because a person committed "+
				"after it (proposal recorded: %v)", recorded)
		}
		if body := w.Body.String(); !strings.Contains(body, "person") {
			t.Errorf("the refusal does not say a person's approval is what is needed "+
				"(proposal recorded: %v):\n%s", recorded, body)
		}
		page := get(t, srv, "/review", token).Body.String()
		if !strings.Contains(page, "A model wrote this change") && recorded {
			t.Error("the review screen does not say a model wrote some of what it refused")
		}
		if recorded && !strings.Contains(page, agents[:12]) {
			t.Errorf("the review screen does not name the model's change %s", agents[:12])
		}

		if !recorded {
			// Offered for review from this screen, it is offered as a
			// model's, whoever presses the button.
			if w := postForm(t, srv, "/review/propose", token, "message=please+read"); w.Code >= 400 {
				t.Fatalf("proposing answered %d", w.Code)
			}
			if prop.AuthorKind != "ai" {
				t.Fatalf("a draft holding a model's change was proposed as %q", prop.AuthorKind)
			}
			continue
		}

		// A person approving it is the way through.
		if w := postForm(t, srv, "/review/approve", token, "note=read+it"); w.Code >= 400 {
			t.Fatalf("approving answered %d", w.Code)
		}
		if w := postForm(t, srv, "/publish", token, "reason=go"); w.Code != http.StatusOK {
			t.Fatalf("a draft a person approved was refused (%d):\n%s", w.Code, w.Body)
		}
		if live := srv.Store.GetRef(site.RefLive); live != draft {
			t.Fatalf("live is %q, not the approved draft %q", live, draft)
		}

		// A person's change after that, with no model's change since what
		// is live, publishes with nobody else asked.
		pages["about"] = map[string]any{"title": "About", "body": "Who we are, spelt right twice."}
		if _, err := site.SaveDraft(srv.Store, pages, "fixed another typo", "writer"); err != nil {
			t.Fatal(err)
		}
		mine := srv.Store.GetRef(site.RefDraft)
		srv.Approvals.Current = func() (*collab.Proposal, error) {
			return &collab.Proposal{Content: mine, Author: "writer", AuthorKind: "human"}, nil
		}
		if w := postForm(t, srv, "/publish", token, "reason=go"); w.Code != http.StatusOK {
			t.Fatalf("a person's change after an approved one was refused (%d):\n%s", w.Code, w.Body)
		}
		if live := srv.Store.GetRef(site.RefLive); live != mine {
			t.Fatalf("live is %q, not the person's draft %q", live, mine)
		}
	}
}

// Re-offering a draft for review after a model wrote some of it offers it
// as a model's, though the proposal it moves on from was a person's.
//
// Rebase moved the proposal to the new draft and kept its kind, so a
// person's proposal, re-offered once an agent had changed the draft under
// a later typo fix of theirs, still said "human": the webhook told nobody
// a model's work was waiting, and the person whose agent run wrote it was
// not held to the rule for approving that.
func TestReofferingADraftAModelWroteSomeOfOffersItAsAModels(t *testing.T) {
	srv, token := setup(t)
	before := srv.Store.GetRef(site.RefDraft)
	draftWrittenBy(t, srv, collab.AgentPrefix+"rewrote the homepage")
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["about"] = map[string]any{"title": "About", "body": "Who we are, spelt right."}
	if _, err := site.SaveDraft(srv.Store, pages, "fixed a typo", "writer"); err != nil {
		t.Fatal(err)
	}
	prop := &collab.Proposal{Content: before, Author: "writer", AuthorKind: "human",
		CreatedAt: time.Now().Unix(), Message: "the first draft"}
	srv.Approvals = &Approvals{
		Policy:  defaultStorePolicy,
		Current: func() (*collab.Proposal, error) { return prop, nil },
		Save:    func(p *collab.Proposal) error { prop = p; return nil },
		KindOf:  func(string) string { return "human" },
	}
	if w := postForm(t, srv, "/review/propose", token, "message=please+read"); w.Code >= 400 {
		t.Fatalf("proposing answered %d", w.Code)
	}
	if prop.Content != srv.Store.GetRef(site.RefDraft) {
		t.Fatal("the proposal did not move to the draft")
	}
	if prop.AuthorKind != "ai" {
		t.Fatalf("a draft holding a model's change was re-offered as %q", prop.AuthorKind)
	}
}
