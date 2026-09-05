package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/site"
)

// proposeAs runs a proposal against a draft with this commit message.
func proposeAs(t *testing.T, message, proposerKind string) *collab.Proposal {
	t.Helper()
	srv, token := setup(t)

	pages := map[string]any{
		"index": map[string]any{"title": "Rewritten", "body": "..."},
	}
	if _, err := site.SaveDraft(srv.Store, pages, message, "assistant"); err != nil {
		t.Fatal(err)
	}

	var saved *collab.Proposal
	srv.Approvals = &Approvals{
		Policy:  func() (collab.Policy, error) { return collab.NewPolicy(), nil },
		Current: func() (*collab.Proposal, error) { return saved, nil },
		Save:    func(p *collab.Proposal) error { saved = p; return nil },
		KindOf:  func(string) string { return proposerKind },
	}

	req := httptest.NewRequest(http.MethodPost, "/review/propose",
		strings.NewReader("message=please+publish"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if saved == nil {
		t.Fatalf("no proposal was recorded (status %d)", rec.Code)
	}
	return saved
}

// A model's work stays a model's work when a person offers it for review.
//
// This is the control RequireHumanForAI exists to be. The admin decided
// authorship from whoever pressed Propose, so a person opening the review
// screen on a draft an agent had just written proposed it as "human" — the
// rule never fired, and two service accounts could approve a model's work into
// production with nobody having read it.
//
// The command line already read the commit and got this right. The disagreeing
// surface was the one dual authorisation was built for: approval.go says a
// control only reachable from a terminal is one the people it constrains route
// around by using the interface.
func TestAModelsWorkIsProposedAsAIEvenWhenAPersonOffersIt(t *testing.T) {
	for _, message := range []string{
		collab.AgentPrefix + "rewrote the homepage",
		"assist: tightened the standfirst",
		"mcp: updated three pages",
	} {
		prop := proposeAs(t, message, "human")
		if prop.AuthorKind != "ai" {
			t.Errorf("a draft committed as %q was proposed as %q.\n"+
				"  RequireHumanForAI never fires, so two service accounts "+
				"can approve it.", message, prop.AuthorKind)
		}
	}
}

// And a person's own work is not relabelled. A rule that called everything AI
// would be obeyed for a week and then switched off.
func TestAPersonsOwnWorkIsStillHuman(t *testing.T) {
	prop := proposeAs(t, "fixed a typo in the standfirst", "human")
	if prop.AuthorKind != "human" {
		t.Errorf("a person's own commit was proposed as %q", prop.AuthorKind)
	}
}

// A service account proposing its own change is a service change, not a
// person's. The content said nothing, so the proposer decides.
func TestAServiceAccountsOwnWorkKeepsItsKind(t *testing.T) {
	prop := proposeAs(t, "nightly import", "service")
	if prop.AuthorKind != "service" {
		t.Errorf("a service account's commit was proposed as %q",
			prop.AuthorKind)
	}
}

// The rule itself, at the boundary, so the reasoning is testable without a
// server around it.
func TestAuthorshipIsAPropertyOfTheContent(t *testing.T) {
	cases := []struct {
		message, proposer, want string
	}{
		{collab.AgentPrefix + "x", "human", "ai"},
		{"assist: x", "human", "ai"},
		{"mcp: x", "service", "ai"},
		{"a real edit", "human", "human"},
		{"a real edit", "service", "service"},
		{"a real edit", "", "human"},
		// The prefix has to be a prefix. A commit that mentions an agent in
		// passing is not one an agent wrote.
		{"revert the agent: change", "human", "human"},
		{"discussed mcp: with the team", "human", "human"},
	}
	for _, c := range cases {
		if got := collab.AuthorKindFor(c.message, c.proposer); got != c.want {
			t.Errorf("AuthorKindFor(%q, %q) = %q, want %q",
				c.message, c.proposer, got, c.want)
		}
	}
}

// The reviewer has to be told which change a model wrote.
//
// The rule requiring a human approval on AI-authored work is worth nothing if
// the human it requires cannot tell which change that is. A reviewer sees a
// diff, and a diff does not say who wrote it — so an approval given in good
// faith satisfies the rule without keeping it.
func TestTheReviewScreenSaysWhenAModelWroteTheChange(t *testing.T) {
	srv, token := setup(t)

	pages := map[string]any{
		"index": map[string]any{"title": "Rewritten", "body": "..."},
	}
	if _, err := site.SaveDraft(srv.Store, pages,
		collab.AgentPrefix+"rewrote the homepage", "assistant"); err != nil {
		t.Fatal(err)
	}
	draft := srv.Store.GetRef(site.RefDraft)

	prop := &collab.Proposal{
		Content: draft, Author: "editor", AuthorKind: "ai",
		CreatedAt: 1787000000, Message: "please publish",
	}
	srv.Approvals = &Approvals{
		Policy:  func() (collab.Policy, error) { return collab.NewPolicy(), nil },
		Current: func() (*collab.Proposal, error) { return prop, nil },
		Save:    func(*collab.Proposal) error { return nil },
		KindOf:  func(string) string { return "human" },
	}

	w := get(t, srv, "/review", token)
	if w.Code != http.StatusOK {
		t.Fatalf("the review screen answered %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "A model wrote this change") {
		t.Error("the review screen does not say a model wrote the change")
	}
	if !strings.Contains(body, "rewrote the homepage") {
		t.Error("the review screen does not say what the model did; the " +
			"reviewer is asked to approve a diff with no account of it")
	}
}

// And it does not say so about a person's work, or the notice becomes
// wallpaper that everybody stops reading.
func TestTheReviewScreenIsQuietAboutAPersonsChange(t *testing.T) {
	srv, token := setup(t)
	draft := srv.Store.GetRef(site.RefDraft)

	prop := &collab.Proposal{
		Content: draft, Author: "editor", AuthorKind: "human",
		CreatedAt: 1787000000,
	}
	srv.Approvals = &Approvals{
		Policy:  func() (collab.Policy, error) { return collab.NewPolicy(), nil },
		Current: func() (*collab.Proposal, error) { return prop, nil },
		Save:    func(*collab.Proposal) error { return nil },
		KindOf:  func(string) string { return "human" },
	}

	w := get(t, srv, "/review", token)
	if strings.Contains(w.Body.String(), "A model wrote this change") {
		t.Error("a person's own change is announced as a model's")
	}
}

// Proposing tells whoever has to agree that they are being waited on.
//
// Dual authorisation only works if the people it waits on find out. Without a
// notification the review screen is a page somebody has to think to open, a
// proposal sits until its author asks in person — and the reliable way to stop
// being asked in person is to turn the requirement off.
func TestProposingNotifiesTheApprovers(t *testing.T) {
	srv, token := setup(t)

	pages := map[string]any{
		"index": map[string]any{"title": "Rewritten", "body": "..."},
	}
	if _, err := site.SaveDraft(srv.Store, pages,
		collab.AgentPrefix+"rewrote the homepage", "assistant"); err != nil {
		t.Fatal(err)
	}

	var told *collab.Proposal
	var saved *collab.Proposal
	srv.Approvals = &Approvals{
		Policy:  func() (collab.Policy, error) { return collab.NewPolicy(), nil },
		Current: func() (*collab.Proposal, error) { return saved, nil },
		Save:    func(p *collab.Proposal) error { saved = p; return nil },
		KindOf:  func(string) string { return "human" },
		Notify:  func(p *collab.Proposal) { told = p },
	}

	req := httptest.NewRequest(http.MethodPost, "/review/propose",
		strings.NewReader("message=please+publish"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if told == nil {
		t.Fatalf("nobody was told a change is waiting for them (status %d, saved=%v)", rec.Code, saved != nil)
	}
	// The field that decides whether a person has to read it.
	if told.AuthorKind != "ai" {
		t.Errorf("the notification says %q wrote it, so a reader cannot tell "+
			"a human approval is required", told.AuthorKind)
	}
}

// A save that fails must still not swallow the notification decision: the
// approvers are told about a proposal that exists, and about nothing else.
func TestAFailedSaveDoesNotInventAProposal(t *testing.T) {
	srv, token := setup(t)

	var told *collab.Proposal
	srv.Approvals = &Approvals{
		Policy:  func() (collab.Policy, error) { return collab.NewPolicy(), nil },
		Current: func() (*collab.Proposal, error) { return nil, nil },
		Save: func(*collab.Proposal) error {
			return errSaveFailed
		},
		KindOf: func(string) string { return "human" },
		Notify: func(p *collab.Proposal) { told = p },
	}

	req := httptest.NewRequest(http.MethodPost, "/review/propose",
		strings.NewReader("message=x"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code < 400 && told == nil {
		t.Fatal("the proposal neither failed nor notified")
	}
}

var errSaveFailed = fmt.Errorf("the store is read-only")
