// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
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
	srv, token := tokenSignIn(t)
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
	// And one for this door, kept to its idle clock, which a server that
	// keeps no such clock refuses (auth.Token's SignedIn). Unmarked, it was
	// a session like any a program exchanges, and the public site's content
	// API took it for its whole eight hours.
	if !tok.SignedIn() {
		t.Fatal("the cookie's session is not marked as one somebody signed in with")
	}
	if pasted, _, err := srv.Tokens.Exchange(token, auth.RoleNone, "", time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	} else if p, err := srv.Tokens.Authenticate(pasted, time.Now()); err != nil || p.SignedIn() {
		t.Fatalf("a session a program exchanged is marked as signed in: %v %+v", err, p)
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

// A session pasted into the sign-in box is one somebody signed in with as
// well, and is marked and stored as that.
//
// A pasted session is used as it is, since a session cannot be exchanged
// again, and this door keeps its idle clock for it as for any other. It
// was left unmarked, so the session in the browser's cookie, signed out
// here once it was left unused, went on being taken by the public site's
// content API and by the studio for the rest of its twelve hours: the
// defect the mark exists for, reached by pasting a session, not a token.
func TestASessionPastedAtSignInIsMarkedAsSignedInWith(t *testing.T) {
	srv, token := tokenSignIn(t)
	stored := 0
	srv.SaveTokens = func(*auth.TokenStore) error { stored++; return nil }
	pasted, _, err := srv.Tokens.Exchange(token, auth.RoleNone, "", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w := signInPost(srv, pasted)
	if got := cookieFrom(w); got != pasted {
		t.Fatalf("a pasted session did not sign in as it is: %d, cookie set %v", w.Code, got != "")
	}
	tok, err := srv.Tokens.Authenticate(pasted, time.Now())
	if err != nil || !tok.SignedIn() {
		t.Fatalf("a session signed in with by pasting it is not marked: %v", err)
	}
	if stored == 0 {
		t.Error("the mark was not stored, so no other server reads it")
	}
	// One that cannot be stored signs nobody in: unmarked on disk, it
	// would be taken elsewhere after this door had signed it out.
	other, _, err := srv.Tokens.Exchange(token, auth.RoleNone, "", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv.SaveTokens = func(*auth.TokenStore) error { return os.ErrPermission }
	if w := signInPost(srv, other); cookieFrom(w) != "" {
		t.Errorf("a session whose mark could not be stored signed in: %d", w.Code)
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

// The OIDC callback reads the access rules as they are stored now before it
// asks whether somebody is suspended or in the policy, read from the source.
//
// It asked the copy the last screen had read. The other ways in are posts,
// and readOnlyTokens authenticates every post first, which reads the store
// again; the callback is a GET the identity provider redirects to, which
// nothing read the store for. So somebody denied the whole site on the
// command line, or by provisioning through another process, was given a
// session by single sign-on until somebody opened a screen, which is what
// suspended exists to stop before a session is made. Checked for the call
// rather than driven end to end, because driving it needs an identity
// provider and the defect is a call missing before the first decision.
func TestTheOIDCCallbackReadsTheStoreBeforeDeciding(t *testing.T) {
	b, err := os.ReadFile("oidcauth.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	// The decision is made where the callback finishes, once the provider
	// has said who somebody is.
	start := strings.Index(src, "\nfunc (s *Server) finishOIDC(")
	if start < 0 {
		t.Fatal("oidcauth.go has no finishOIDC")
	}
	body := src[start:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	refresh, decide := strings.Index(body, "s.refresh()"), strings.Index(body, "s.suspended(")
	if decide < 0 {
		t.Fatal("the OIDC callback no longer asks whether somebody is suspended")
	}
	if refresh < 0 || refresh > decide {
		t.Fatal("the OIDC callback decides who is suspended from the copy the last screen read")
	}
}

// TestSigningOutEndsAnIdentityProviderSession, the path that was broken.
func TestSigningOutEndsAnIdentityProviderSession(t *testing.T) {
	srv, _ := setup(t)
	secret, _, err := srv.Tokens.IssueSession("oidc:editor", "editor",
		srv.roleFor("editor"), "/", DefaultSessionTTL, "admin", auth.MethodSSO)
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
