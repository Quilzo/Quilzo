// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/oidc"
)

// oidcServer is an admin signing people in through an OIDC provider by
// their email claim, and what it records of refused sign-ins.
func oidcServer(t *testing.T) (*Server, *[]map[string]string) {
	t.Helper()
	srv, _ := setup(t)
	srv.OIDC = &OIDC{ClientID: "cms", Claim: "email", RedirectURI: "https://cms.example/auth/callback",
		Provider: &oidc.Provider{Discovery: oidc.Discovery{Issuer: "https://idp.example",
			AuthorizationEndpoint: "https://idp.example/authorize"}}}
	var refused []map[string]string
	srv.Audit = func(action, _ string, d map[string]string) {
		if action == "signin.oidc.refused" {
			refused = append(refused, d)
		}
	}
	return srv, &refused
}

// startOIDC begins a sign-in, as a browser does, and returns its state
// and the cookie it is bound to.
func startOIDC(t *testing.T, srv *Server) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/signin/oidc", nil))
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != http.StatusSeeOther {
		t.Fatalf("starting a sign-in: %d %v", w.Code, err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "quilzo_oidc" {
			return loc.Query().Get("state"), c
		}
	}
	t.Fatal("no binding cookie")
	return "", nil
}

func oidcCallback(srv *Server, query string, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?"+query, nil)
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

// A refused OIDC sign-in is recorded, as a refused SAML one is
// (signin.saml.refused).
//
// It was not. The provider saying no, another browser's answer, a token
// for another tenant, an unverified address, somebody suspended or not in
// the access policy: each was shown to the browser and written nowhere,
// so the log of who tried to sign in and was turned away had every SAML
// attempt and no OIDC one. An answer to no sign-in started here is
// refused without a record, as an unsolicited SAML response is, because
// anybody can open the callback address.
func TestARefusedOIDCSignInIsRecorded(t *testing.T) {
	srv, refused := oidcServer(t)

	// The provider's own refusal is shown as the provider put it, and
	// recorded by its code: the description is free text that can name
	// the person, and all of it is a query anybody who began a sign-in can
	// type.
	state, c := startOIDC(t, srv)
	w := oidcCallback(srv, url.Values{"state": {state}, "error": {"access_denied"},
		"error_description": {"ann@acme.com declined"}}.Encode(), c)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "access_denied") ||
		!strings.Contains(w.Body.String(), "ann@acme.com declined") {
		t.Fatalf("the provider's refusal: %d", w.Code)
	}
	state, _ = startOIDC(t, srv)
	if w := oidcCallback(srv, url.Values{"state": {state}, "code": {"c"}}.Encode(), nil); w.Code != http.StatusForbidden {
		t.Fatalf("another browser's answer: %d", w.Code)
	}
	state, c = startOIDC(t, srv)
	oidcCallback(srv, url.Values{"state": {state}, "error": {strings.Repeat("e", 60000)}}.Encode(), c)
	if len(*refused) != 3 || (*refused)[0]["why"] != "the provider refused: access_denied" ||
		!strings.Contains((*refused)[1]["why"], "another browser") || (*refused)[0]["issuer"] != "https://idp.example" ||
		len((*refused)[2]["why"]) > 200 {
		t.Fatalf("three refusals were recorded as %.300v", *refused)
	}
	// A sign-in the provider refused is over: its answer, sent again, is
	// an answer to nothing, and one sign-in begun is at most one record.
	if oidcCallback(srv, url.Values{"state": {state}, "error": {"access_denied"}}.Encode(), c); len(*refused) != 3 {
		t.Errorf("a refusal sent twice was recorded twice: %d records", len(*refused))
	}

	// Answers to nothing started here are refused and not recorded.
	*refused = nil
	for _, q := range []string{"error=access_denied", "state=made-up&code=c", "code=c"} {
		if w := oidcCallback(srv, q, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	if len(*refused) != 0 {
		t.Errorf("answers to no sign-in were recorded: %v", *refused)
	}

	// Once the provider has said who somebody is, the refusal names them,
	// as an identity the log pseudonymises.
	r := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	w = httptest.NewRecorder()
	srv.finishOIDC(w, r, "stranger@example.com", ssoProof{MFA: true}, "")
	if sessionOf(w) != nil || w.Code != http.StatusForbidden {
		t.Fatalf("somebody not in the access policy: %d", w.Code)
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "editor", Role: auth.RoleReader, Resource: "/", Deny: true}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	srv.finishOIDC(w, r, "editor", ssoProof{MFA: true}, "")
	if sessionOf(w) != nil || w.Code != http.StatusForbidden {
		t.Fatalf("somebody suspended: %d", w.Code)
	}
	if len(*refused) != 2 || (*refused)[0]["principal"] != "stranger@example.com" ||
		!strings.Contains((*refused)[0]["why"], "not in the access policy") ||
		(*refused)[1]["principal"] != "editor" || !strings.Contains((*refused)[1]["why"], "suspended") {
		t.Errorf("the refusals of people were recorded as %v", *refused)
	}

	// A token refused for what it says (an unverified address, another
	// tenant) names who it says it is, by the claim people are named with.
	said := &oidc.Claims{Subject: "s-1", Email: "new@example.com",
		Raw: map[string]any{"preferred_username": " New@Example.com "}}
	for claim, want := range map[string]string{"email": "new@example.com", "sub": "s-1",
		"preferred_username": "new@example.com"} {
		o := &OIDC{Claim: claim, RequireVerifiedEmail: true, Tenant: "another"}
		if _, err := o.principalFor(said); err == nil {
			t.Fatalf("claim %s: a token for another tenant was taken", claim)
		}
		if got := o.claimed(said); got != want {
			t.Errorf("claim %s: a refused token is said to be %q's", claim, got)
		}
	}
}

// A SAML sign-in refused once the provider has said who somebody is is
// recorded too: somebody suspended, or not in the access policy, was
// refused at the end every single sign-on shares (finishSSO), which wrote
// nothing, while the refusals before it were recorded.
func TestARefusedSAMLSignInOfSomebodyIsRecorded(t *testing.T) {
	srv, _ := samlServer(t, nil)
	var refused []map[string]string
	srv.Audit = func(action, _ string, d map[string]string) {
		if action == "signin.saml.refused" {
			refused = append(refused, d)
		}
	}
	id, relay, c := start(t, srv)
	if w := postACS(t, srv, relay, response(t, resp{who: "nobody@northwind.example", inResponseTo: id}), c); sessionOf(w) != nil {
		t.Fatal("somebody not in the access policy was signed in")
	}
	if len(refused) != 1 || refused[0]["provider"] != "corp" || refused[0]["principal"] != "nobody@northwind.example" ||
		!strings.Contains(refused[0]["why"], "not in the access policy") {
		t.Errorf("the refusal was recorded as %v", refused)
	}
}

// A sign-in by address finds its person in the access policy whatever the
// case of the address, as SAML always has.
//
// OIDC took the email claim as the provider sent it and the policy
// compares names exactly, so somebody provisioned as ann@acme.com whose
// provider's email claim said Ann@Acme.com signed in successfully and was
// refused as not in the access policy. SAML lowercases what it is sent,
// so somebody provisioned under a capital was refused there. Two names in
// the policy that differ only in case are two principals to it, and
// neither is chosen; a subject (claim sub) is an opaque identifier,
// compared exactly.
func TestAnAddressSignsInWhateverItsCase(t *testing.T) {
	srv, _ := oidcServer(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "ann@acme.com", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	signIn := func(who string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.finishOIDC(w, httptest.NewRequest(http.MethodGet, "/auth/callback", nil), who, ssoProof{MFA: true}, "")
		return w
	}
	if tok := sessionToken(t, srv, signIn("Ann@Acme.com")); tok.Principal != "ann@acme.com" {
		t.Errorf("Ann@Acme.com signed in as %q", tok.Principal)
	}

	if err := srv.Policy.Grant(auth.Binding{Principal: "ANN@acme.com", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if w := signIn("Ann@Acme.com"); sessionOf(w) != nil {
		t.Error("an address two principals differ only by case from signed in as one of them")
	}
	if tok := sessionToken(t, srv, signIn("ANN@acme.com")); tok.Principal != "ANN@acme.com" {
		t.Errorf("the name exactly as the policy has it signed in as %q", tok.Principal)
	}

	srv.OIDC.Claim = "sub"
	if err := srv.Policy.Grant(auth.Binding{Principal: "Subject-7", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if w := signIn("subject-7"); sessionOf(w) != nil {
		t.Error("a subject in another case signed in")
	}

	saml, _ := samlServer(t, nil)
	if err := saml.Policy.Grant(auth.Binding{Principal: "Bo.Lee@northwind.example", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	id, relay, c := start(t, saml)
	w := postACS(t, saml, relay, response(t, resp{who: "Bo.Lee@northwind.example", inResponseTo: id}), c)
	if tok := sessionToken(t, saml, w); tok.Principal != "Bo.Lee@northwind.example" {
		t.Errorf("a SAML sign-in signed in as %q", tok.Principal)
	}
}
