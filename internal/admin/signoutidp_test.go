// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oidc"
)

// Signing out after an OIDC sign-in ended the session here and left the
// one at the identity provider, so the next sign-in through it skipped the
// password, and nothing said so. Where the provider has an end-session
// address (OpenID Connect RP-Initiated Logout), signing out here offers
// signing out there too; signing out here stays what it was.
func TestSigningOutOffersToSignOutOfTheIdentityProvider(t *testing.T) {
	srv, passkey := setup(t)
	var d oidc.Discovery
	if err := json.Unmarshal([]byte(`{"issuer": "https://idp.example",
		"authorization_endpoint": "https://idp.example/authorize",
		"end_session_endpoint": "https://idp.example/logout"}`), &d); err != nil {
		t.Fatal(err)
	}
	srv.OIDC = &OIDC{ClientID: "cms", Label: "Keycloak", RedirectURI: "https://cms.example/auth/callback",
		Provider: &oidc.Provider{Discovery: d}}
	session := func() string {
		t.Helper()
		secret, _, err := srv.Tokens.IssueSession("oidc:editor", "editor", srv.roleFor("editor"), "/",
			DefaultSessionTTL, auth.RoleAdmin, auth.MethodSSO)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	signOut := func(method, session string, form url.Values, menu bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/signout", strings.NewReader(form.Encode()))
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
		}
		if menu {
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Dest", "document")
		}
		req.AddCookie(&http.Cookie{Name: "quilzo_token", Value: session})
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	ended := func(session string) bool {
		_, err := srv.Tokens.Authenticate(session, time.Now())
		return err != nil
	}
	const out = "https://idp.example/logout?client_id=cms"

	// The menu's link signs out here at once, then says the provider's
	// session goes on and offers to end it.
	s := session()
	w := signOut(http.MethodGet, s, nil, true)
	if !ended(s) {
		t.Fatal("the menu's sign-out did not end the session here")
	}
	loc := w.Header().Get("Location")
	if loc == "/signin" || !strings.HasPrefix(loc, "/signin") {
		t.Fatalf("signed out to %q, with nothing said about Keycloak's session", loc)
	}
	page := get(t, srv, loc, "").Body.String()
	if !strings.Contains(page, out) || !strings.Contains(page, "Keycloak") {
		t.Errorf("the sign-in page does not offer to sign out of Keycloak:\n%s", firstLines(page, 60))
	}

	// The question asked of a request the person may not have made offers
	// both, and its second button goes on to the provider.
	s = session()
	if body := signOut(http.MethodGet, s, nil, false).Body.String(); !strings.Contains(body, `name="idp"`) {
		t.Errorf("Sign out? does not offer signing out of Keycloak:\n%s", firstLines(body, 40))
	}
	w = signOut(http.MethodPost, s, url.Values{"idp": {"1"}}, false)
	if !ended(s) || w.Code != http.StatusSeeOther || w.Header().Get("Location") != out {
		t.Errorf("signing out here and at Keycloak: ended %v, %d to %q", ended(s), w.Code, w.Header().Get("Location"))
	}

	// A session nobody signed in to through the provider has nothing there
	// to end.
	if w := signOut(http.MethodPost, passkey, nil, false); w.Header().Get("Location") != "/signin" {
		t.Errorf("a passkey session signed out to %q", w.Header().Get("Location"))
	}
	// Nor does an address anybody can write make the page offer it.
	if page := get(t, srv, "/signin?out=https://evil.example", "").Body.String(); strings.Contains(page, "evil.example") {
		t.Error("the sign-in page printed an address from its query")
	}
}
