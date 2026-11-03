// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
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
			return current.Close(as(by), current.Items, false, nil, time.Now())
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

// The same program, through the front door: its token pasted into the
// sign-in form makes a session in a cookie, which in the grace before two
// factors are compulsory is let in as a browser's, and the header check
// above never sees it. A review is decided by somebody proved with two
// factors, which a program's token is not, however it arrives.
func TestAProgramsTokenSignedInThroughTheFormCannotReview(t *testing.T) {
	srv, editor := setup(t)
	hooks, pressed := memoryReview(srv)
	srv.AccessReview = hooks
	srv.MFAFrom = time.Now().Add(14 * 24 * time.Hour)
	program, _, err := srv.Tokens.Issue("deploy", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader(url.Values{"token": {program}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == "quilzo_token" {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatalf("signing in with the token made no session: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := postFormAs(t, srv, "/people", cookie, nil); w.Code == http.StatusUnauthorized {
		t.Fatal("the session made from the token is not let in during the grace, so this tests nothing")
	}
	for _, path := range []string{"/people/review/start", "/people/review/close"} {
		if w := postFormAs(t, srv, path, cookie, url.Values{}); w.Code != http.StatusForbidden {
			t.Errorf("%s with a session signed in from a program's token: %d", path, w.Code)
		}
	}
	if w := postForm(t, srv, "/people/review/start", editor, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("an administrator signed in with a passkey could not start: %d", w.Code)
	}
	decide := url.Values{"item": {"1"}, "verdict": {"revoke"}}
	if w := postFormAs(t, srv, "/people/review/decide", cookie, decide); w.Code != http.StatusForbidden {
		t.Errorf("decide with a session signed in from a program's token: %d", w.Code)
	}
	if got := strings.Join(*pressed, "; "); got != "start editor" {
		t.Errorf("the host was asked: %s", got)
	}
}

// A button returns to where it was pressed, saying what it came to there:
// on the card for a decision, at the top of the section for starting and
// closing, a success as a status and a refusal as an alert. It went to the
// top of People, above the grant form, with a refusal in the same grey as
// a success, and the administrator scrolled back down to find which card
// the message was about.
func TestAReviewButtonComesBackToWhereItWasPressed(t *testing.T) {
	srv, editor := setup(t)
	hooks, _ := memoryReview(srv)
	srv.AccessReview = hooks
	for _, b := range []auth.Binding{
		{Principal: "sam", Role: auth.RoleAdmin, Resource: "/"},
		{Principal: "kit", Role: auth.RoleAuthor, Resource: "/blog"},
	} {
		if err := srv.Policy.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	follow := func(w *httptest.ResponseRecorder) (string, string) {
		t.Helper()
		loc := w.Header().Get("Location")
		path, anchor, _ := strings.Cut(loc, "#")
		return get(t, srv, path, editor).Body.String(), anchor
	}
	body, anchor := follow(postForm(t, srv, "/people/review/start", editor, ""))
	if anchor != "review" || !strings.Contains(body, `<p class="notice ok" role="status">review r1 started`) {
		t.Fatalf("starting did not come back to the section with a status (#%s)", anchor)
	}
	var sam, kit string
	for _, it := range hooks.mustCurrent(t).Items {
		switch it.Principal {
		case "sam":
			sam = it.ID
		case "kit":
			kit = it.ID
		}
	}
	body, anchor = follow(postForm(t, srv, "/people/review/decide", editor,
		url.Values{"item": {sam}, "verdict": {"keep"}}.Encode()))
	card := cardOf(t, body, sam)
	if anchor != "item-"+sam || !strings.Contains(card, `class="notice bad" role="alert">item `+sam+` is privileged`) {
		t.Errorf("a refusal did not come back to its card as an alert (#%s): %s", anchor, card)
	}
	if strings.Contains(cardOf(t, body, kit), "notice") {
		t.Error("the refusal was shown on another card too")
	}
	body, _ = follow(postForm(t, srv, "/people/review/decide", editor,
		url.Values{"item": {sam}, "verdict": {"keep"}, "why": {"runs the agency's second shift"}}.Encode()))
	card = cardOf(t, body, sam)
	for _, want := range []string{`class="notice ok" role="status">item ` + sam + `: keep, sam is admin on /`,
		"Kept by editor on", "runs the agency&#39;s second shift"} {
		if !strings.Contains(card, want) {
			t.Errorf("the decided card does not show %q: %s", want, card)
		}
	}
	body, _ = follow(postForm(t, srv, "/people/review/decide", editor,
		url.Values{"item": {kit}, "verdict": {"revoke"}}.Encode()))
	if card := cardOf(t, body, kit); !strings.Contains(card, "from kit&#39;s next request, it gives them nothing") ||
		!strings.Contains(card, "Revoked by editor on") {
		t.Errorf("a revoke does not say what it took: %s", card)
	}
	if !strings.Contains(body, "Closing waits until every item is decided; item ") ||
		!strings.Contains(body, " is your own, for another administrator to decide.") {
		t.Error("the close button does not say that the rest is the administrator's own")
	}
	body, anchor = follow(postForm(t, srv, "/people/review/close", editor, ""))
	if anchor != "review" || !strings.Contains(body, `class="notice bad" role="alert">1 item(s) are undecided`) {
		t.Errorf("a refused close did not come back to the section as an alert (#%s)", anchor)
	}
	// A card that is not there, as for an item number nobody listed, has
	// its refusal said at the top of the section rather than nowhere.
	body, _ = follow(postForm(t, srv, "/people/review/decide", editor,
		url.Values{"item": {"99"}, "verdict": {"keep"}}.Encode()))
	if !strings.Contains(body, `class="notice bad" role="alert">review r1 has no item`) {
		t.Error("a refusal about an item that is not there was not shown")
	}
}

// cardOf is one item's card on People.
func cardOf(t *testing.T, body, id string) string {
	t.Helper()
	start := strings.Index(body, `id="item-`+id+`"`)
	if start < 0 {
		t.Fatalf("no card for item %s", id)
	}
	end := strings.Index(body[start:], "</li>")
	return body[start : start+end]
}

// What closing waits for is said beside the button, and when the person
// pressing it is the only administrator, their own items do not hold it:
// the review closes without them.
func TestTheCloseButtonSaysWhatItWaitsFor(t *testing.T) {
	if got := closeHint(0, nil, false); got != "" {
		t.Errorf("nothing undecided: %q", got)
	}
	if got := closeHint(2, nil, false); got != "Closing waits until every item is decided." {
		t.Errorf("none of their own: %q", got)
	}
	if got := closeHint(2, []string{"1", "3"}, false); !strings.Contains(got, "items 1 and 3 are your own, for another administrator") {
		t.Errorf("two of their own: %q", got)
	}
	got := closeHint(3, []string{"1", "3"}, true)
	if !strings.Contains(got, "closes without items 1 and 3, your own") || !strings.Contains(got, "every other item") {
		t.Errorf("alone: %q", got)
	}
	if got := closeHint(1, []string{"1"}, true); strings.Contains(got, "waits") {
		t.Errorf("alone with only their own left: %q", got)
	}

	srv, editor := setup(t)
	hooks, _ := memoryReview(srv)
	srv.AccessReview = hooks
	postForm(t, srv, "/people/review/start", editor, "")
	body := get(t, srv, "/people", editor).Body.String()
	if !strings.Contains(body, "with no other administrator to decide it, the review closes without it") ||
		strings.Contains(body, "another administrator decides it") {
		t.Error("the only administrator's own card says another administrator decides it")
	}
}

// A session that may not decide is not offered buttons that answer with a
// bare refusal: it is told how to decide instead. A person signed in with
// one factor in the grace before two are compulsory was shown Start,
// Keep, Revoke and Close, and each answered with a page of plain text.
func TestASessionThatMayNotDecideIsToldHowInsteadOfOfferedButtons(t *testing.T) {
	srv, editor := setup(t)
	hooks, _ := memoryReview(srv)
	srv.AccessReview = hooks
	srv.MFAFrom = time.Now().Add(14 * 24 * time.Hour)
	if err := srv.Policy.Grant(auth.Binding{Principal: "sam", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	oneFactor, _, err := srv.Tokens.IssueSession("signin", "sam", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodToken)
	if err != nil {
		t.Fatal(err)
	}
	page := func() string {
		req := httptest.NewRequest(http.MethodGet, "/people", nil)
		req.AddCookie(&http.Cookie{Name: "quilzo_token", Value: oneFactor})
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("People with one factor in the grace: %d", w.Code)
		}
		return w.Body.String()
	}
	before := page()
	if strings.Contains(before, `action="/people/review/start"`) || !strings.Contains(before, "Starting one needs a sign-in with two factors") {
		t.Error("a one-factor session was offered Start, or not told how to start")
	}
	postForm(t, srv, "/people/review/start", editor, "")
	open := page()
	for _, gone := range []string{`action="/people/review/decide"`, `action="/people/review/close"`} {
		if strings.Contains(open, gone) {
			t.Errorf("a one-factor session was offered %s", gone)
		}
	}
	if !strings.Contains(open, "Deciding needs a sign-in with two factors") {
		t.Error("a one-factor session is not told how to decide")
	}
	if strings.Contains(get(t, srv, "/people", editor).Body.String(), "Deciding needs a sign-in") {
		t.Error("a passkey session is told it cannot decide")
	}
}

// After a review closes, the section says when the next is due, as the
// command line does, and that one is due once the period has passed.
func TestTheSectionSaysWhenTheNextReviewIsDue(t *testing.T) {
	srv, editor := setup(t)
	hooks, _ := memoryReview(srv)
	closed := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	hooks.Last = func() (time.Time, bool, error) { return closed, true, nil }
	srv.AccessReview = hooks
	if body := get(t, srv, "/people", editor).Body.String(); !strings.Contains(body,
		"The last review closed on 4 Aug 2026") {
		t.Fatal("the last close is not shown")
	}
	v := srv.reviewSection(httptest.NewRequest(http.MethodGet, "/people", nil), principal{Name: "editor"},
		closed.Add(30*24*time.Hour))
	if v.Next != "2 Nov 2026" || v.Due {
		t.Errorf("a month after a close: next %q, due %v", v.Next, v.Due)
	}
	if v := srv.reviewSection(httptest.NewRequest(http.MethodGet, "/people", nil), principal{Name: "editor"},
		closed.Add(91*24*time.Hour)); !v.Due {
		t.Error("ninety-one days after a close, one is not due")
	}
}
