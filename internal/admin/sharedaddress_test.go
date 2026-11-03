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
