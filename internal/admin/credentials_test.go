// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/throttle"
)

// The sign-in box is behind the same limiter as everything else.
//
// It was not, and the gap was the whole point of the door. requireAuth
// throttles a token presented as a cookie; the identical guess sent through
// the form was free. Measured against the running server before this: forty
// wrong tokens through the form returned forty 401s and never a 429, while two
// through the cookie path were enough to start refusing.
//
// The missing count is worse than the missing limit. Failures here never
// reached Throttle.Fail, so they never contributed to the per-source counter
// that protects every other surface, and never crossed the threshold that
// fires OnAuthFailure — a sustained attempt against the one door built for
// people raised no alert anywhere.
func TestTheSignInFormIsThrottled(t *testing.T) {
	srv, _ := setup(t)
	srv.Throttle = throttle.New(throttle.Default())
	alerts := 0
	srv.OnAuthFailure = func(string, int) { alerts++ }

	codes := map[int]int{}
	for i := 0; i < 25; i++ {
		req := httptest.NewRequest(http.MethodPost, "/signin",
			strings.NewReader("token=qz_definitelynotarealtoken"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.RemoteAddr = "198.51.100.7:4444"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		codes[w.Code]++
	}

	if codes[http.StatusTooManyRequests] == 0 {
		t.Errorf("twenty-five wrong tokens through the sign-in form and not "+
			"one was refused for trying too often: %v. The same guesses sent "+
			"as a cookie are throttled after two", codes)
	}
	if alerts == 0 {
		t.Error("no failure threshold was ever reported, so a sustained " +
			"attempt against the sign-in box raises nothing anywhere")
	}
}

// Signing out revokes the session, rather than forgetting it.
//
// This cleared the cookie and left the credential alive. The OIDC and passkey
// paths mint a server-side session token lasting eight hours, so somebody who
// signed in through an identity provider, pressed Sign out and walked away had
// a working credential for the rest of the working day — in a proxy log, on a
// shared machine, in whatever copied the Authorization header.
func TestSigningOutRevokesTheSession(t *testing.T) {
	srv, parent := setup(t)

	// A session, the way OIDC and passkeys mint one.
	session, tok, err := srv.Tokens.Exchange(parent, auth.RoleNone, "",
		time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/", session); w.Code != http.StatusOK {
		t.Fatalf("the session does not work to begin with: %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/signout", nil)
	req.Header.Set("Authorization", "Bearer "+session)
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	if w := get(t, srv, "/", session); w.Code == http.StatusOK {
		t.Error("the session still works after signing out. Clearing the " +
			"cookie only forgets the credential; whoever else holds a copy " +
			"of it does not")
	}
	for _, x := range srv.Tokens.Tokens {
		if x.ID == tok.ID && !x.Revoked {
			t.Error("the session token is not marked revoked, so it survives " +
				"a restart too")
		}
	}
}

// And a long-lived token is not revoked by signing out.
//
// It is somebody's own credential, used deliberately. Revoking it because they
// closed a tab would destroy the thing they signed in with.
func TestSigningOutDoesNotRevokeALongLivedToken(t *testing.T) {
	srv, token := setup(t)

	req := httptest.NewRequest(http.MethodGet, "/signout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	if w := get(t, srv, "/", token); w.Code != http.StatusOK {
		t.Errorf("signing out revoked the long-lived token this person signs "+
			"in with: %d", w.Code)
	}
}
