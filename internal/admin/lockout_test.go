// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/enrol"
	"github.com/quilzo/quilzo/internal/lockout"
)

// signInFrom is signIn from an address of the caller's choosing.
func (f *fakeAuthenticator) signInFrom(t *testing.T, srv *Server, addr string) *httptest.ResponseRecorder {
	t.Helper()
	send := func(path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "https://"+testHost+path, bytes.NewReader(raw))
		req.Host, req.TLS, req.RemoteAddr = testHost, &tls.ConnectionState{}, addr
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	challenge, _ := decodeBody(t, send("/signin/passkey/challenge", map[string]any{}))["challenge"].(string)
	f.count++
	cd := f.clientData(t, "webauthn.get", challenge)
	ad := f.authData()
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return send("/signin/passkey/verify", map[string]any{
		"id": enc(f.id), "challenge": challenge,
		"clientDataJSON": enc(cd), "authenticatorData": enc(ad), "signature": enc(sig),
	})
}

// postFormAs posts a form in a browser holding session.
func postFormAs(t *testing.T, srv *Server, path, session string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "quilzo_token", Value: session})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// Somebody guessing at an account from elsewhere is locked out of it from
// there; its owner, from their own place, signs straight in and is told.
// Another administrator lets it work from everywhere again; nobody unlocks
// themselves.
func TestFailuresFromElsewhereLockOutThePlaceNotThePerson(t *testing.T) {
	srv, admin := fullyWired(t)
	srv.Enrol = &enrol.Store{Path: filepath.Join(t.TempDir(), "enrolments.json")}
	if err := srv.Policy.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	srv.Throttle = nil // counted here by the lockout alone
	srv.Lockout = &lockout.Store{Path: filepath.Join(t.TempDir(), "lockout.json")}
	var mu sync.Mutex
	var actions []string
	srv.Audit = func(action, _ string, _ map[string]string) {
		mu.Lock()
		actions = append(actions, action)
		mu.Unlock()
	}
	secret, _, err := srv.Enrol.Issue("dana", "editor", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dana := newFake(t, "dana-key")
	if w := dana.enrol(t, srv, secret); w.Code != http.StatusOK {
		t.Fatalf("enrolling: %d %s", w.Code, w.Body)
	}
	const home, away = "192.0.2.10:5000", "203.0.113.7:5000"
	if w := dana.signInFrom(t, srv, home); w.Code != http.StatusOK {
		t.Fatalf("dana at home: %d %s", w.Code, w.Body)
	}

	guesser := newFake(t, "dana-key") // the same credential id, not the key
	for i := 0; i < lockout.Threshold; i++ {
		if w := guesser.signInFrom(t, srv, away); w.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d: %d %s", i+1, w.Code, w.Body)
		}
	}
	if !strings.Contains(strings.Join(actions, " "), "account.locked") {
		t.Errorf("no account.locked in %v", actions)
	}
	w := dana.signInFrom(t, srv, away)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("the right key from the locked-out place: %d %s", w.Code, w.Body)
	}
	w = dana.signInFrom(t, srv, home)
	if w.Code != http.StatusOK {
		t.Fatalf("dana was locked out of her own account at home: %d %s", w.Code, w.Body)
	}
	next, _ := decodeBody(t, w)["next"].(string)
	if !strings.Contains(next, "failed+sign-ins+on+your+account") {
		t.Errorf("dana was not told: %q", next)
	}

	// Locked again, and listed for whoever looks after sign-ins.
	for i := 0; i < lockout.Threshold; i++ {
		guesser.signInFrom(t, srv, away)
	}
	if !strings.Contains(get(t, srv, "/security/signins", admin).Body.String(), "/security/signins/unlock") {
		t.Fatal("Sign-ins does not offer to unlock dana")
	}
	session := cookieFrom(dana.signInFrom(t, srv, home))
	if w := postFormAs(t, srv, "/security/signins/unlock", session, url.Values{"person": {"dana"}}); w.Code != http.StatusSeeOther ||
		!strings.Contains(w.Header().Get("Location"), "e=") {
		t.Errorf("dana unlocked herself: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = postForm(t, srv, "/security/signins/unlock", admin, "person=dana")
	if !strings.Contains(w.Header().Get("Location"), "m=") {
		t.Fatalf("unlocking: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := dana.signInFrom(t, srv, away); w.Code != http.StatusOK {
		t.Errorf("unlocked and still refused from elsewhere: %d %s", w.Code, w.Body)
	}
}

// The ceiling: so many failures in a row, from anywhere, and passkey sign-in
// to the account is off until a single sign-on or another administrator
// turns it back on.
func TestTheCeilingTurnsPasskeysOffUntilThePersonProvesThemselves(t *testing.T) {
	srv := enrolling(t)
	srv.Lockout = &lockout.Store{Path: filepath.Join(t.TempDir(), "lockout.json")}
	now := time.Now()
	for i := 0; i < lockout.Ceiling; i++ {
		if _, _, err := srv.Lockout.Fail("dana", "192.0.2.10", now); err != nil {
			t.Fatal(err)
		}
	}
	secret, _, err := srv.Enrol.Issue("dana", "editor", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	dana := newFake(t, "dana-key")
	dana.enrol(t, srv, secret)
	if w := dana.signInFrom(t, srv, "192.0.2.10:5000"); w.Code != http.StatusTooManyRequests ||
		!strings.Contains(w.Body.String(), "until you sign in another way") {
		t.Fatalf("a disabled account signed in: %d %s", w.Code, w.Body)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.10:5000"
	// A sign-on the provider did not say used two factors proves nothing.
	srv.ssoNext(r, "dana", ssoProof{})
	if d, _ := srv.Lockout.Check("dana", "192.0.2.10", time.Now()); !d.Disabled {
		t.Fatal("a one-factor sign-on turned the passkeys back on")
	}
	if next := srv.ssoNext(r, "dana", ssoProof{MFA: true}); !strings.Contains(next, "m=") {
		t.Errorf("signing on did not tell dana about the failures: %q", next)
	}
	if w := dana.signInFrom(t, srv, "192.0.2.10:5000"); w.Code != http.StatusOK {
		t.Errorf("after a single sign-on, the passkey is still off: %d %s", w.Code, w.Body)
	}
}

// verifyAs is a passkey sign-in made in place, from the page of the person
// named, as the page does after an idle sign-out.
func (f *fakeAuthenticator) verifyAs(t *testing.T, srv *Server, expect string) *httptest.ResponseRecorder {
	t.Helper()
	challenge, _ := decodeBody(t, postJSON(t, srv, "/signin/passkey/challenge", "", nil))["challenge"].(string)
	f.count++
	cd := f.clientData(t, "webauthn.get", challenge)
	ad := f.authData()
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, srv, "/signin/passkey/verify", "", map[string]any{
		"id": enc(f.id), "challenge": challenge, "expect": expect,
		"clientDataJSON": enc(cd), "authenticatorData": enc(ad), "signature": enc(sig),
	})
}

// Signing in again in place carries on with the page only for the person
// it was theirs: somebody else's passkey is refused and makes no session.
// The person is told, in place, of any failures before.
func TestSigningInAgainInPlaceIsForThePagesPerson(t *testing.T) {
	srv := enrolling(t)
	srv.Lockout = &lockout.Store{Path: filepath.Join(t.TempDir(), "lockout.json")}
	if err := srv.Policy.Grant(auth.Binding{Principal: "erin", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	keys := map[string]*fakeAuthenticator{}
	for _, who := range []string{"dana", "erin"} {
		secret, _, err := srv.Enrol.Issue(who, "editor", time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		keys[who] = newFake(t, who+"-key")
		if w := keys[who].enrol(t, srv, secret); w.Code != http.StatusOK {
			t.Fatalf("enrolling %s: %d %s", who, w.Code, w.Body)
		}
	}
	w := keys["erin"].verifyAs(t, srv, "dana")
	if w.Code != http.StatusConflict || cookieFrom(w) != "" {
		t.Fatalf("erin carried on with dana's page: %d %s", w.Code, w.Body)
	}
	srv.Lockout.Fail("dana", "203.0.113.7", time.Now())
	w = keys["dana"].verifyAs(t, srv, "dana")
	if w.Code != http.StatusOK || cookieFrom(w) == "" {
		t.Fatalf("dana in place: %d %s", w.Code, w.Body)
	}
	if notice, _ := decodeBody(t, w)["notice"].(string); !strings.HasPrefix(notice, "1 failed sign-in on your account") {
		t.Errorf("the notice in place: %q", notice)
	}
}
