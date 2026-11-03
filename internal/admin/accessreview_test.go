// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/accessreview"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// memoryReview is the host's side of the review, kept in memory, applying
// nothing: what is tested here is the screen and who it lets press what.
// cmd/quilzo drives the same routes against the real functions.
func memoryReview(srv *Server) (*AccessReview, *[]string) {
	var current *accessreview.Review
	var pressed []string
	as := func(by Actor) accessreview.Decider {
		return accessreview.Decider{Name: by.Name, Kind: audit.KindHuman, Verified: true}
	}
	return &AccessReview{
		Current: func() (*accessreview.Review, error) { return current, nil },
		Last:    func() (time.Time, bool, error) { return time.Time{}, false, nil },
		Every:   func() time.Duration { return accessreview.DefaultEvery },
		Start: func(by Actor) (*accessreview.Review, error) {
			items := accessreview.Snapshot(accessreview.Inputs{Policy: srv.Policy, Tokens: srv.Tokens, Now: time.Now()})
			r, err := accessreview.New("r1", items, as(by), time.Now())
			current = r
			pressed = append(pressed, "start "+by.Name)
			return r, err
		},
		Decide: func(by Actor, id string, v accessreview.Verdict, why string) (accessreview.Item, error) {
			it, err := current.Check(id, v, as(by), why)
			if err != nil {
				return it, err
			}
			current.Record(id, v, as(by), why, time.Now())
			pressed = append(pressed, "decide "+id+" "+string(v)+" "+by.Name)
			return it, nil
		},
		Close: func(by Actor) (accessreview.Summary, error) {
			pressed = append(pressed, "close "+by.Name)
			return current.Close(as(by), current.Items, false, time.Now())
		},
	}, &pressed
}

// Regression 4, on the screen. A publisher and an auditor of the
// compliance area are refused every button; an administrator of the whole
// store is not; and a credential a program sent is refused whatever it
// may do, because a service token reviews nothing.
func TestOnlyAnAdministratorSignedInDecidesOnThePeopleScreen(t *testing.T) {
	srv, editor := setup(t)
	hooks, pressed := memoryReview(srv)
	srv.AccessReview = hooks
	for _, b := range []auth.Binding{
		{Principal: "pub", Role: auth.RolePublisher, Resource: "/"},
		{Principal: "aud", Role: auth.RoleReader, Resource: auth.AreaCompliance},
		{Principal: "aud", Role: auth.RoleReader, Resource: auth.AreaLog},
		{Principal: "kit", Role: auth.RoleAuthor, Resource: "/blog"},
	} {
		if err := srv.Policy.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	session := func(who string, role auth.Role) string {
		secret, _, err := srv.Tokens.IssueSession(who, who, role, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	pub, aud := session("pub", auth.RolePublisher), session("aud", auth.RoleReader)

	for _, who := range []string{pub, aud} {
		if w := postForm(t, srv, "/people/review/start", who, ""); w.Code != http.StatusForbidden {
			t.Errorf("start: %d", w.Code)
		}
	}
	if w := postForm(t, srv, "/people/review/start", editor, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("an administrator could not start a review: %d", w.Code)
	}
	var kit string
	for _, it := range hooks.mustCurrent(t).Items {
		if it.Principal == "kit" {
			kit = it.ID
		}
	}
	decide := url.Values{"item": {kit}, "verdict": {"keep"}}.Encode()
	for _, who := range []string{pub, aud} {
		if w := postForm(t, srv, "/people/review/decide", who, decide); w.Code != http.StatusForbidden {
			t.Errorf("decide: %d", w.Code)
		}
		if w := postForm(t, srv, "/people/review/close", who, ""); w.Code != http.StatusForbidden {
			t.Errorf("close: %d", w.Code)
		}
	}
	program, _, err := srv.Tokens.Issue("deploy", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv.MFAFrom = time.Now().Add(14 * 24 * time.Hour)
	if w := postForm(t, srv, "/people/review/decide", program, decide); w.Code != http.StatusForbidden {
		t.Errorf("a program's credential decided: %d", w.Code)
	}
	w := postForm(t, srv, "/people/review/decide", editor, decide)
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "item "+kit+": keep") {
		t.Errorf("an administrator's decision: %d %s", w.Code, loc)
	}
	if got := strings.Join(*pressed, "; "); got != "start editor; decide "+kit+" keep editor" {
		t.Errorf("the host was asked: %s", got)
	}
}

func (h *AccessReview) mustCurrent(t *testing.T) *accessreview.Review {
	t.Helper()
	r, err := h.Current()
	if err != nil || r == nil {
		t.Fatalf("no review: %v", err)
	}
	return r
}

// The section shows each item with its buttons, the person's own without
// them, a privileged item asking for a reason, and a refusal the host
// gives as the message it comes back with; and it passes the checks the
// interface enforces on content.
func TestTheReviewSectionShowsWhatToDecide(t *testing.T) {
	srv, editor := setup(t)
	hooks, _ := memoryReview(srv)
	srv.AccessReview = hooks
	if err := srv.Policy.Grant(auth.Binding{Principal: "sam", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	before := get(t, srv, "/people", editor).Body.String()
	if !strings.Contains(before, "No review has closed yet") || !strings.Contains(before, `action="/people/review/start"`) {
		t.Fatal("with no review open, the section does not offer one")
	}
	postForm(t, srv, "/people/review/start", editor, "")
	page := get(t, srv, "/people", editor)
	body := page.Body.String()
	for _, want := range []string{"editor is admin on /", "sam is admin on /", "privileged",
		"This is your own access", `action="/people/review/close"`, "Needed to keep it"} {
		if !strings.Contains(body, want) {
			t.Errorf("the open review does not show %q", want)
		}
	}
	r := a11y.Check("/people", body)
	for _, f := range r.Findings {
		if f.Severity == a11y.Blocking {
			t.Errorf("%s (%s): %s", f.Rule, f.Criterion, f.Detail)
		}
	}
	var sam string
	for _, it := range hooks.mustCurrent(t).Items {
		if it.Principal == "sam" {
			sam = it.ID
		}
	}
	w := postForm(t, srv, "/people/review/decide", editor, url.Values{"item": {sam}, "verdict": {"keep"}}.Encode())
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "needs a reason") {
		t.Errorf("privileged access kept with no reason: %s", loc)
	}
	w = postForm(t, srv, "/people/review/close", editor, "")
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "undecided") {
		t.Errorf("closed with items undecided: %s", loc)
	}
}

// A server built without reviews leaves the section out and refuses the
// buttons, rather than offering one that fails.
func TestWithoutReviewsTheSectionIsAbsent(t *testing.T) {
	srv, editor := setup(t)
	if strings.Contains(get(t, srv, "/people", editor).Body.String(), "Review who has access") {
		t.Error("a section with nothing behind it")
	}
	w := postForm(t, srv, "/people/review/start", editor, "")
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "without access reviews") {
		t.Errorf("start with no host: %d %s", w.Code, loc)
	}
}

// A session exchanged from a long-lived token and sent in a header is a
// program's, as the token is: the admin's own rule (authenticate) is that
// a credential in a header short of two factors belongs to a program. In
// the grace before two factors are compulsory that rule is not yet
// enforced, and the screen let such a session start and decide a review as
// a person.
func TestASessionExchangedFromATokenCannotReview(t *testing.T) {
	srv, editor := setup(t)
	hooks, pressed := memoryReview(srv)
	srv.AccessReview = hooks
	srv.MFAFrom = time.Now().Add(14 * 24 * time.Hour)
	program, _, err := srv.Tokens.Issue("deploy", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	exchanged, _, err := srv.Tokens.Exchange(program, auth.RoleNone, "", 15*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/people/review/start", "/people/review/close"} {
		if w := postForm(t, srv, path, exchanged, ""); w.Code != http.StatusForbidden {
			t.Errorf("%s with an exchanged session: %d", path, w.Code)
		}
	}
	if w := postForm(t, srv, "/people/review/start", editor, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("an administrator signed in with a passkey could not start: %d", w.Code)
	}
	decide := url.Values{"item": {"1"}, "verdict": {"revoke"}}.Encode()
	if w := postForm(t, srv, "/people/review/decide", exchanged, decide); w.Code != http.StatusForbidden {
		t.Errorf("decide with an exchanged session: %d", w.Code)
	}
	if got := strings.Join(*pressed, "; "); got != "start editor" {
		t.Errorf("the host was asked: %s", got)
	}
}
