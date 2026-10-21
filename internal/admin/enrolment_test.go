// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/enrol"
)

// enrol runs the ceremony an enrolment page runs, with the link's secret.
func (f *fakeAuthenticator) enrol(t *testing.T, srv *Server, secret string) *httptest.ResponseRecorder {
	t.Helper()
	w := postJSON(t, srv, "/enrol/challenge", "", map[string]any{"secret": secret})
	if w.Code != http.StatusOK {
		return w
	}
	challenge, _ := decodeBody(t, w)["challenge"].(string)
	der, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, srv, "/enrol/register", "", map[string]any{
		"secret": secret, "id": enc(f.id), "challenge": challenge, "label": "my laptop",
		"clientDataJSON":    enc(f.clientData(t, "webauthn.create", challenge)),
		"authenticatorData": enc(f.authData()),
		"publicKey":         enc(der),
		"algorithm":         -7,
	})
}

func enrolling(t *testing.T) *Server {
	t.Helper()
	srv, _ := fullyWired(t)
	srv.Enrol = &enrol.Store{Path: filepath.Join(t.TempDir(), "enrolments.json")}
	if err := srv.Policy.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	return srv
}

// A link adds one passkey for the person it names, once; with it they sign
// in, at two factors, without ever holding a token.
func TestALinkAddsOnePasskeyForThePersonItNames(t *testing.T) {
	srv := enrolling(t)
	srv.MFAFrom = time.Now().Add(-time.Minute)
	secret, _, err := srv.Enrol.Issue("dana", "editor", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	page := get(t, srv, "/enrol/"+secret, "")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "<strong>dana</strong>") ||
		page.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("the page: %d %q", page.Code, page.Header().Get("Referrer-Policy"))
	}
	f := newFake(t, "dana-key")
	if w := f.enrol(t, srv, secret); w.Code != http.StatusOK {
		t.Fatalf("enrolling: %d %s", w.Code, w.Body)
	}
	if len(srv.Passkeys.Credentials) != 1 || srv.Passkeys.Credentials[0].Principal != "dana" {
		t.Fatalf("stored %+v", srv.Passkeys.Credentials)
	}
	other := newFake(t, "second-key")
	if w := other.enrol(t, srv, secret); w.Code != http.StatusNotFound {
		t.Errorf("a used link added a second passkey: %d", w.Code)
	}
	f.count++
	w := f.signIn(t, srv)
	if w.Code != http.StatusOK {
		t.Fatalf("signing in with the enrolled passkey: %d %s", w.Code, w.Body)
	}
	session := cookieFrom(w)
	if g := get(t, srv, "/", session); g.Code != http.StatusOK {
		t.Errorf("the passkey's session does not reach the admin: %d", g.Code)
	}
}

// A link that names nothing shows nothing and is counted, and none works
// while the admin is locked down.
func TestALinkThatNamesNothingOpensNothing(t *testing.T) {
	srv := enrolling(t)
	w := get(t, srv, "/enrol/qzenrol_made-up", "")
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "dana") {
		t.Errorf("a made-up link: %d", w.Code)
	}
	if w := postJSON(t, srv, "/enrol/challenge", "", map[string]any{"secret": "qzenrol_made-up"}); w.Code != http.StatusNotFound {
		t.Errorf("a made-up link was given a challenge: %d", w.Code)
	}
	secret, _, err := srv.Enrol.Issue("dana", "editor", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv.EnrolBlocked = func(time.Time) string { return "the admin is locked down" }
	if w := postJSON(t, srv, "/enrol/challenge", "", map[string]any{"secret": secret}); w.Code != http.StatusServiceUnavailable {
		t.Errorf("a link worked during a lockdown: %d", w.Code)
	}
}

// A ceremony begun through one person's link cannot finish through
// another's: the key would be bound to whoever the second link names.
func TestAChallengeFromOneLinkDoesNotFinishAnother(t *testing.T) {
	srv := enrolling(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "erin", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	danaLink, _, _ := srv.Enrol.Issue("dana", "editor", time.Hour, time.Now())
	erinLink, _, _ := srv.Enrol.Issue("erin", "editor", time.Hour, time.Now())
	challenge, _ := decodeBody(t, postJSON(t, srv, "/enrol/challenge", "", map[string]any{"secret": danaLink}))["challenge"].(string)
	f := newFake(t, "crossed-key")
	der, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	w := postJSON(t, srv, "/enrol/register", "", map[string]any{
		"secret": erinLink, "id": enc(f.id), "challenge": challenge,
		"clientDataJSON":    enc(f.clientData(t, "webauthn.create", challenge)),
		"authenticatorData": enc(f.authData()),
		"publicKey":         enc(der),
		"algorithm":         -7,
	})
	if w.Code != http.StatusBadRequest || len(srv.Passkeys.Credentials) != 0 {
		t.Errorf("a ceremony crossed links: %d, %d stored", w.Code, len(srv.Passkeys.Credentials))
	}
}

// An administrator gives somebody a link from the People screen; it is
// shown once on its own page and works for that person.
func TestTheLinkIsGivenFromThePeopleScreen(t *testing.T) {
	srv2, admin := fullyWired(t)
	srv2.Enrol = &enrol.Store{Path: filepath.Join(t.TempDir(), "enrolments.json")}
	if err := srv2.Policy.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(get(t, srv2, "/people", admin).Body.String(), "/people/enrol") {
		t.Error("the People screen offers no enrolment link")
	}
	w := post(t, srv2, "/people/enrol?principal=dana", admin)
	body := w.Body.String()
	i := strings.Index(body, enrolStart+enrol.Prefix)
	if w.Code != http.StatusOK || i < 0 {
		t.Fatalf("no link was shown: %d", w.Code)
	}
	secret := body[i+len(enrolStart) : i+len(enrolStart)+len(enrol.Prefix)+52]
	if l, err := srv2.Enrol.Peek(secret, time.Now()); err != nil || l.Principal != "dana" || l.By != "editor" {
		t.Errorf("the link shown: %+v %v", l, err)
	}
	if w := post(t, srv2, "/people/enrol?principal=nobody", admin); w.Code == http.StatusOK &&
		strings.Contains(w.Body.String(), enrol.Prefix) {
		t.Error("a link was made for somebody with no access")
	}
	// A waiting link can be ended from the same screen.
	if !strings.Contains(get(t, srv2, "/people", admin).Body.String(), "/people/enrol/revoke") {
		t.Error("the People screen offers no way to end a waiting link")
	}
	post(t, srv2, "/people/enrol/revoke?principal=dana", admin)
	if _, err := srv2.Enrol.Peek(secret, time.Now()); err == nil {
		t.Error("the link still works after it was ended")
	}
}
