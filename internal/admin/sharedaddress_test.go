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

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/throttle"
)

// Guessing from one address delays the guesses, not everybody else who
// reaches the admin from there.
//
// It held everybody. Behind Docker's port publishing, a NAT or an office
// proxy every client is one address, and after six bad tokens at /mcp from
// it the reference stack refused a valid token there ("too many failed
// attempts from this address"), answered a signed-out visit with 429, and
// refused a passkey sign-in, for up to fifteen minutes. The content API and
// the admin's screens already authenticated a throttled request and let a
// valid credential through, because only the address is known before the
// credential is checked; /mcp, the passkey ceremony, the sign-in form, token
// exchange and enrolment links refused before looking.
func TestGuessingFromOneAddressLocksNobodyElseOut(t *testing.T) {
	srv := enrolling(t)
	srv.Interface = &AgentInterface{
		Enabled: func() bool { return true },
		Config:  func() (oauthas.Config, bool) { return oauthas.Config{}, false },
		Build: func(req *http.Request, c *mcp.Caller) (*mcp.Server, error) {
			s := mcp.NewServer("quilzo", "test")
			s.Authorise = func(mcp.Operation) error { return nil }
			s.Register(mcp.Operation{Name: "whoami", NeedsRole: "reader", Summary: "who"},
				func(map[string]any) (any, error) { return "you are " + c.Principal, nil })
			return s, nil
		},
	}
	r := &ifaceRig{srv: srv}

	// Made before anything goes wrong: dana's passkey, a link for a second
	// one, a token for the sign-in box and one for a program.
	first, _, err := srv.Enrol.Issue("dana", "editor", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dana := newFake(t, "dana-key")
	if w := dana.enrol(t, srv, first); w.Code != http.StatusOK {
		t.Fatalf("enrolling: %d %s", w.Code, w.Body)
	}
	second, _, err := srv.Enrol.Issue("dana", "editor", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pasted, _, err := srv.Tokens.Issue("pasted", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	program, _, err := srv.Tokens.Issue("program", "editor", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	// Then somebody at the same address guesses, until the address is
	// throttled. Every request in this test comes from httptest's one
	// address, as every client on the reference stack came from one.
	// On a stopped clock, so the delay is still running at the end however
	// long the test takes.
	stopped := time.Now()
	srv.Throttle = throttle.New(throttle.Default()).WithClock(func() time.Time { return stopped })
	for i := 0; i < 10; i++ {
		r.mcpCall(t, "qz_wrongwrongwrongwrongwrong")
	}
	if w := r.mcpCall(t, "qz_wrongwrongwrongwrongwrong"); w.Code == http.StatusOK ||
		!strings.Contains(w.Body.String(), "too many failed attempts") {
		t.Fatalf("the guessing was not throttled: %d %s", w.Code, w.Body)
	}

	// Everybody else there still gets in.
	if w := r.mcpCall(t, program); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "you are editor") {
		t.Errorf("a valid token was refused at /mcp: %d %s", w.Code, w.Body)
	}
	swap := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {program}, "subject_token_type": {typeAccessToken}}
	if w := exchange(t, srv, swap, ""); w.Code != http.StatusOK {
		t.Errorf("a valid token could not be exchanged: %d %s", w.Code, w.Body)
	}
	if w := get(t, srv, "/", ""); w.Code == http.StatusTooManyRequests {
		t.Errorf("somebody arriving signed out was told 429, though they presented nothing")
	}
	req := httptest.NewRequest(http.MethodPost, "/signin", strings.NewReader("token="+url.QueryEscape(pasted)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if loc := unsigned(w.Header().Get("Location")); w.Code != http.StatusSeeOther || strings.Contains(loc, "e=") || cookieFrom(w) == "" {
		t.Errorf("a valid token pasted into the sign-in box was refused: %d to %q", w.Code, loc)
	}
	if w := dana.signInFrom(t, srv, "192.0.2.1:1234"); w.Code != http.StatusOK {
		t.Errorf("a passkey sign-in was refused: %d %s", w.Code, w.Body)
	}
	if w := get(t, srv, "/enrol/"+second, ""); w.Code != http.StatusOK {
		t.Errorf("a live enrolment link was refused: %d", w.Code)
	}

	// And a guess is still refused for trying too often, at each of them.
	if w := exchange(t, srv, url.Values{"grant_type": {grantTokenExchange}, "subject_token": {"qz_wrongwrongwrongwrongwrong"},
		"subject_token_type": {typeAccessToken}}, ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("a wrong token was exchanged for an answer other than 429: %d %s", w.Code, w.Body)
	}
	if w := newFake(t, "dana-key").signInFrom(t, srv, "192.0.2.1:1234"); w.Code != http.StatusTooManyRequests {
		t.Errorf("a wrong key was answered %d, not 429", w.Code)
	}
	if w := get(t, srv, "/enrol/nosuchlinknosuchlinknosuchlink", ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("a made-up enrolment link was answered %d, not 429", w.Code)
	}
}

// The sign-in page tells somebody they tried too often when it was their
// attempt that was refused for it, and not because of guesses made from their
// address by somebody else.
//
// The form asked the limiter about the address and answered 429, "Too many
// attempts from this address ... Try again in", to whoever opened it. A right
// token or passkey is let in from a throttled address now, so that told
// everybody behind a shared address to wait for a lockout they were not in;
// on the reference stack, everybody who went to the sign-in page.
func TestTheSignInPageSaysTooManyOnlyAfterARefusalForIt(t *testing.T) {
	srv, token := setup(t)
	srv.Throttle = throttle.New(throttle.Default())
	refusedTo := ""
	for i := 0; i < 30; i++ {
		refusedTo = signInPost(srv, "qz_wrong").Header().Get("Location")
	}
	if unsigned(refusedTo) != "/signin?e=throttled" {
		t.Fatalf("the guessing was not refused for trying too often, but sent to %q", refusedTo)
	}
	open := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "203.0.113.9:5555"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := open("/signin"); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "Too many attempts") {
		t.Errorf("somebody opening the sign-in page from the address was answered %d:\n%s", w.Code, w.Body)
	}
	if w := signInPost(srv, token); w.Code != http.StatusSeeOther || cookieFrom(w) == "" {
		t.Fatalf("the right token from the address was not signed in: %d", w.Code)
	}
	if w := open(refusedTo); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" ||
		!strings.Contains(w.Body.String(), "Too many attempts") {
		t.Errorf("an attempt refused for trying too often was answered %d", w.Code)
	}
}
