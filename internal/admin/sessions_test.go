// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// cookieFrom returns the session cookie a response set.
func cookieFrom(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == "quilzo_token" {
			return c.Value
		}
	}
	return ""
}

// TestTheCookieNeverHoldsThePastedToken.
//
// It did: the long-lived token went straight into the cookie, so the
// credential most likely to be copied was the one that lasts a month, and
// signing out could not revoke it without destroying the token somebody signs
// in with. The cookie holds an eight-hour session exchanged from it.
func TestTheCookieNeverHoldsThePastedToken(t *testing.T) {
	srv, token := setup(t)
	w := signInPost(srv, token)
	session := cookieFrom(w)
	if session == "" {
		t.Fatal("signing in set no cookie")
	}
	if session == token {
		t.Fatal("the cookie holds the long-lived token itself")
	}
	tok, err := srv.Tokens.Authenticate(session, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !tok.IsSession() {
		t.Fatal("the cookie's credential is not a session")
	}
	if life := time.Until(time.Unix(tok.ExpiresAt, 0)); life > DefaultSessionTTL+time.Minute {
		t.Fatalf("the session lasts %s", life)
	}

	// Signing out ends the session and leaves the token alone.
	req := httptest.NewRequest(http.MethodPost, "/signout", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "quilzo_token", Value: session})
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)

	if _, err := srv.Tokens.Authenticate(session, time.Now()); err == nil {
		t.Fatal("the session still works after signing out")
	}
	if _, err := srv.Tokens.Authenticate(token, time.Now()); err != nil {
		t.Fatalf("signing out destroyed the token somebody signs in with: %v", err)
	}
}

// TestEverySignInPathMintsASession, read from the source.
//
// OIDC and passkeys minted their credentials with Tokens.Issue, which makes
// somebody's own long-lived token: IsSession said false and sign-out left
// them alive for eight hours. The two files are checked for the call rather
// than driven end to end, because the bug is which constructor was chosen,
// and a ceremony test would pass with either.
func TestEverySignInPathMintsASession(t *testing.T) {
	for _, f := range []string{"oidcauth.go", "passkeys.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		if strings.Contains(src, "Tokens.Issue(") ||
			strings.Contains(src, "Tokens.IssueScoped(") {
			t.Errorf("%s mints a sign-in credential with Issue, which sign-out "+
				"will not revoke; use IssueSession", f)
		}
		if !strings.Contains(src, "Tokens.IssueSession(") {
			t.Errorf("%s no longer mints a session at all", f)
		}
	}
}

// TestSigningOutEndsAnIdentityProviderSession, the path that was broken.
func TestSigningOutEndsAnIdentityProviderSession(t *testing.T) {
	srv, _ := setup(t)
	secret, _, err := srv.Tokens.IssueSession("oidc:editor", "editor",
		srv.roleFor("editor"), "/", DefaultSessionTTL, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/", secret); w.Code != http.StatusOK {
		t.Fatalf("the session does not work to begin with: %d", w.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/signout", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "quilzo_token", Value: secret})
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	if w := get(t, srv, "/", secret); w.Code == http.StatusOK {
		t.Fatal("an identity-provider session outlived signing out")
	}
}
