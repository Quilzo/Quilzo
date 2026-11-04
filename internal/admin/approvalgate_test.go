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
