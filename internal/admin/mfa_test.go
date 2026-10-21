// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/saml"
)

// confirm is signIn from a session that has to prove its person: the same
// ceremony, presenting the session it is to replace.
func (f *fakeAuthenticator) confirm(t *testing.T, srv *Server, session string) *httptest.ResponseRecorder {
	t.Helper()
	start := decodeBody(t, postJSON(t, srv, "/signin/passkey/challenge", "", nil))
	challenge, _ := start["challenge"].(string)
	cd := f.clientData(t, "webauthn.get", challenge)
	ad := f.authData()
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, srv, "/signin/passkey/verify", session, map[string]any{
		"id": enc(f.id), "challenge": challenge,
		"clientDataJSON": enc(cd), "authenticatorData": enc(ad), "signature": enc(sig),
	})
}

// Once two factors are compulsory, a token pasted into the sign-in form is a
// first factor: the session it makes reaches nothing but "Confirm it's
// you", and the passkey that confirms it gives a session that came through
// both, which reaches everything.
func TestATokenAloneIsAFirstFactorOnly(t *testing.T) {
	srv, full := fullyWired(t)
	f := newFake(t, "credential-mfa")
	f.register(t, srv, full)
	token, _, err := srv.Tokens.Issue("cli", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv.MFAFrom = time.Now().Add(-time.Minute)

	session := cookieFrom(signInPost(srv, token))
	if session == "" {
		t.Fatal("signing in with a token set no session")
	}
	c := &http.Cookie{Name: "quilzo_token", Value: session}
	if w := browse(srv, http.MethodGet, "/", c, nil); w.Code != http.StatusSeeOther ||
		w.Header().Get("Location") != "/signin/verify" {
		t.Fatalf("a token's session reached the admin: %d %s", w.Code, w.Header().Get("Location"))
	}
	if page := browse(srv, http.MethodGet, "/signin/verify", c, nil).Body.String(); !strings.Contains(page, "which is one factor") {
		t.Errorf("the confirm page does not say why:\n%s", page)
	}

	f.count++
	w := f.confirm(t, srv, session)
	if w.Code != http.StatusOK {
		t.Fatalf("confirming with the passkey: %d %s", w.Code, w.Body)
	}
	both := cookieFrom(w)
	if both == "" || both == session {
		t.Fatal("confirming did not replace the session")
	}
	if w := browse(srv, http.MethodGet, "/", &http.Cookie{Name: "quilzo_token", Value: both}, nil); w.Code != http.StatusOK {
		t.Fatalf("the confirmed session does not reach the admin: %d", w.Code)
	}
	tok, err := srv.Tokens.Authenticate(both, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Level() != 2 || !tok.HasMethod(auth.MethodToken) || !tok.HasMethod(auth.MethodPasskey) {
		t.Errorf("the confirmed session says %v, level %d", tok.Methods, tok.Level())
	}
	if _, err := srv.Tokens.Authenticate(session, time.Now()); err == nil {
		t.Error("the one-factor session it replaced still works")
	}
}

// A token in a header is a program's: refused at the admin once two
// factors are compulsory, let through with a notice before.
func TestATokenInAHeaderIsRefusedOnceTwoFactorsAreCompulsory(t *testing.T) {
	srv, token := tokenSignIn(t)
	w := get(t, srv, "/", token)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "signing in here takes two") {
		t.Fatalf("in the grace a token was refused, or not told: %d", w.Code)
	}
	srv.MFAFrom = time.Now().Add(-time.Minute)
	if w := get(t, srv, "/", token); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "two factors") {
		t.Fatalf("after the grace a token reached the admin: %d %s", w.Code, w.Body)
	}
	// A session that does not say how it began is one factor too.
	legacy, _, err := srv.Tokens.IssueSession("old", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if w := browse(srv, http.MethodGet, "/", &http.Cookie{Name: "quilzo_token", Value: legacy}, nil); w.Code == http.StatusOK {
		t.Error("a session with no record of how it began reached the admin")
	}
}

// Single sign-on required holds on every request, not only at the sign-in
// form: a session that did not come through the identity provider is
// refused, one that did is let in, and a break-glass account is not held
// to it.
func TestSingleSignOnRequiredHoldsOnEveryRequest(t *testing.T) {
	srv, _ := setup(t)
	for _, who := range []string{"dana@quilzo.io", "glass@quilzo.io"} {
		if err := srv.Policy.Grant(auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: "/"}); err != nil {
			t.Fatal(err)
		}
	}
	srv.SAML = &SAMLAdmin{Providers: func() ([]saml.Config, error) {
		return []saml.Config{{Name: "okta", Required: true, Domains: []string{"quilzo.io"},
			BreakGlass: []string{"glass@quilzo.io"}}}, nil
	}}
	session := func(who string, methods ...string) string {
		s, _, err := srv.Tokens.IssueSession("s", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, methods...)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if w := get(t, srv, "/", session("dana@quilzo.io", auth.MethodPasskey)); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Body.String(), "requires signing in through") {
		t.Errorf("a passkey session went round single sign-on: %d", w.Code)
	}
	if w := get(t, srv, "/", session("dana@quilzo.io", auth.MethodSSO)); w.Code != http.StatusOK {
		t.Errorf("a single sign-on session was refused: %d", w.Code)
	}
	if w := get(t, srv, "/", session("glass@quilzo.io", auth.MethodPasskey)); w.Code != http.StatusOK {
		t.Errorf("the break-glass account was held to single sign-on: %d", w.Code)
	}
}

// A passkey is added from a session already at two factors once they are
// compulsory, so a copied token cannot bind the copier's own key; before,
// a token's session may add the first one.
func TestAPasskeyIsAddedFromTwoFactorsOnceCompulsory(t *testing.T) {
	srv, _ := setup(t)
	one := principal{Name: "editor", Role: srv.roleFor("editor"), Scope: "/", Level: 1}
	srv.MFAFrom = time.Now().Add(time.Hour)
	if err := srv.mayEnrol(one); err != nil {
		t.Errorf("in the grace a token's session could not add its first passkey: %v", err)
	}
	srv.MFAFrom = time.Now().Add(-time.Hour)
	if err := srv.mayEnrol(one); err == nil {
		t.Error("after the grace a token's session added a passkey")
	}
	two := one
	two.Level = 2
	if err := srv.mayEnrol(two); err != nil {
		t.Errorf("a two-factor session could not add a passkey: %v", err)
	}
}
