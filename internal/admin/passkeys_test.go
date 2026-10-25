// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/webauthn"
)

// A passkey, exercised through the real routes.
//
// The package's own verifier is tested against a simulated authenticator in
// internal/webauthn. What this adds is everything around it: the challenge
// store, the credential lookup, the session the sign-in mints, and the checks
// that only exist here — that a challenge issued to one session cannot
// register a key on another, and that somebody can only remove their own.

const testHost = "cms.example"

type fakeAuthenticator struct {
	key   *ecdsa.PrivateKey
	id    []byte
	rpID  string
	count uint32
	// flags replaces present-and-verified when it is not zero.
	flags byte
}

func newFake(t *testing.T, id string) *fakeAuthenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAuthenticator{key: k, id: []byte(id), rpID: testHost, count: 1}
}

func (f *fakeAuthenticator) authData() []byte {
	sum := sha256.Sum256([]byte(f.rpID))
	out := append([]byte{}, sum[:]...)
	flags := byte(0x01 | 0x04)
	if f.flags != 0 {
		flags = f.flags
	}
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, f.count)
}

func (f *fakeAuthenticator) clientData(t *testing.T, kind, challenge string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type": kind, "challenge": challenge,
		"origin": "https://" + testHost, "crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// post sends JSON over TLS, because a browser will not do WebAuthn otherwise
// and neither will this server.
func postJSON(t *testing.T, srv *Server, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://"+testHost+path,
		bytes.NewReader(raw))
	req.Host = testHost
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON (%d): %s", w.Code, w.Body.String())
	}
	return out
}

// register runs a full registration ceremony and returns the credential id.
func (f *fakeAuthenticator) register(t *testing.T, srv *Server, token string) {
	t.Helper()
	start := decodeBody(t, postJSON(t, srv, "/passkeys/challenge", token, nil))
	challenge, _ := start["challenge"].(string)
	if challenge == "" {
		t.Fatalf("no challenge was issued: %v", start)
	}
	der, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	w := postJSON(t, srv, "/passkeys/register", token, map[string]any{
		"id": enc(f.id), "challenge": challenge, "label": "a test key",
		"clientDataJSON":    enc(f.clientData(t, "webauthn.create", challenge)),
		"authenticatorData": enc(f.authData()),
		"publicKey":         enc(der),
		"algorithm":         -7,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("registration answered %d: %s", w.Code, w.Body.String())
	}
}

// signIn runs a sign-in ceremony and returns the response.
func (f *fakeAuthenticator) signIn(t *testing.T, srv *Server) *httptest.ResponseRecorder {
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
	return postJSON(t, srv, "/signin/passkey/verify", "", map[string]any{
		"id": enc(f.id), "challenge": challenge,
		"clientDataJSON":    enc(cd),
		"authenticatorData": enc(ad),
		"signature":         enc(sig),
	})
}

// The whole loop: register a key while signed in with a token, then sign in
// with the key alone and come back holding a session.
func TestAPasskeyRegistersAndThenSignsSomebodyIn(t *testing.T) {
	srv, token := fullyWired(t)
	f := newFake(t, "credential-one")

	f.register(t, srv, token)
	if len(srv.Passkeys.Credentials) != 1 {
		t.Fatalf("%d credentials stored", len(srv.Passkeys.Credentials))
	}

	f.count++
	w := f.signIn(t, srv)
	if w.Code != http.StatusOK {
		t.Fatalf("signing in with a registered passkey answered %d: %s",
			w.Code, w.Body.String())
	}

	// A session, and a real one: the cookie has to authenticate.
	var session string
	for _, c := range w.Result().Cookies() {
		if c.Name == "quilzo_token" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("signing in with a passkey set no session cookie")
	}
	if _, err := srv.Tokens.Authenticate(session, time.Now()); err != nil {
		t.Fatalf("the minted session does not authenticate: %v", err)
	}

	// And the counter was written back, or the clone check has nothing to
	// compare against next time.
	if got := srv.Passkeys.Credentials[0].SignCount; got != f.count {
		t.Errorf("the stored counter is %d and the authenticator is at %d",
			got, f.count)
	}
}

// A challenge answers once. Otherwise a captured ceremony is a spare key.
func TestAChallengeCannotBeUsedTwice(t *testing.T) {
	srv, token := fullyWired(t)
	f := newFake(t, "credential-one")
	f.register(t, srv, token)

	start := decodeBody(t, postJSON(t, srv, "/signin/passkey/challenge", "", nil))
	challenge, _ := start["challenge"].(string)

	f.count++
	build := func() map[string]any {
		cd := f.clientData(t, "webauthn.get", challenge)
		ad := f.authData()
		sum := sha256.Sum256(cd)
		digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
		sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"id": enc(f.id), "challenge": challenge,
			"clientDataJSON":    enc(cd),
			"authenticatorData": enc(ad),
			"signature":         enc(sig),
		}
	}
	body := build()
	if w := postJSON(t, srv, "/signin/passkey/verify", "", body); w.Code != http.StatusOK {
		t.Fatalf("the first use answered %d: %s", w.Code, w.Body.String())
	}
	if w := postJSON(t, srv, "/signin/passkey/verify", "", body); w.Code == http.StatusOK {
		t.Fatal("the same ceremony signed somebody in twice, so a captured " +
			"one is a spare key")
	}
}

// An unknown credential and a bad signature answer the same thing. Telling a
// stranger which credentials exist tells them which accounts do.
func TestAnUnknownCredentialSaysNothingUseful(t *testing.T) {
	srv, token := fullyWired(t)
	known := newFake(t, "credential-one")
	known.register(t, srv, token)

	stranger := newFake(t, "never-registered")
	w := stranger.signIn(t, srv)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an unknown credential answered %d", w.Code)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "unknown") ||
		strings.Contains(strings.ToLower(w.Body.String()), "not registered") {
		t.Errorf("the refusal says the credential is unknown: %s", w.Body.String())
	}
}

// Only the page that permits a script may permit one.
func TestOnlyThePasskeyScreensPermitAScript(t *testing.T) {
	srv, token := fullyWired(t)

	for _, path := range []string{"/passkeys", "/signin/passkey"} {
		w := get(t, srv, path, token)
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'nonce-") {
			t.Errorf("%s does not scope its script to a nonce: %s", path, csp)
		}
		for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "*"} {
			if strings.Contains(csp, forbidden) {
				t.Errorf("%s permits %q: %s", path, forbidden, csp)
			}
		}
	}

	// Elsewhere, only the interface's own script, by a nonce of its own.
	for _, path := range []string{"/", "/people", "/access", "/media"} {
		w := get(t, srv, path, token)
		csp := w.Header().Get("Content-Security-Policy")
		if strings.Contains(csp, "script-src") &&
			!strings.Contains(csp, "script-src 'nonce-") {
			t.Errorf("%s permits a script other than by nonce: %s", path, csp)
		}
		for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "*"} {
			if strings.Contains(csp, forbidden) {
				t.Errorf("%s permits %q: %s", path, forbidden, csp)
			}
		}
	}
}

// Two nonces from two responses must differ, or an injection into one page
// carries a value that works on the next.
func TestThePasskeyNonceIsFreshPerResponse(t *testing.T) {
	srv, token := fullyWired(t)
	first := get(t, srv, "/passkeys", token).Header().Get("Content-Security-Policy")
	second := get(t, srv, "/passkeys", token).Header().Get("Content-Security-Policy")
	if first == second {
		t.Error("two responses carried the same nonce")
	}
}

// Passkeys need a secure context, and a browser says so silently. This server
// says it out loud instead of serving a button that does nothing.
func TestPlainHTTPOnANonLoopbackHostExplainsItself(t *testing.T) {
	srv, token := fullyWired(t)

	req := httptest.NewRequest(http.MethodPost, "http://192.168.1.5/passkeys/challenge", nil)
	req.Host = "192.168.1.5"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("plain HTTP on a LAN address answered %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "HTTPS") {
		t.Errorf("the refusal does not name the reason: %s", w.Body.String())
	}
}

// Loopback is the exception browsers make, and this has to make it too or
// passkeys cannot be tried locally at all.
func TestLoopbackOverPlainHTTPIsAllowed(t *testing.T) {
	srv, token := fullyWired(t)

	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/passkeys/challenge", nil)
	req.Host = "localhost:8080"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("localhost answered %d: %s", w.Code, w.Body.String())
	}
}

// Every script this program serves, not just the first one.
//
// The sink and external-reference checks were written for the playground, when
// it was the only page with a script. There are three now, and a guard that
// covers one of three is a guard that will be true and useless. This walks the
// templates instead, so the fourth is covered before anybody writes it.
func TestEveryServedScriptAvoidsDangerousSinks(t *testing.T) {
	sources := map[string]string{}

	files, err := assets.ReadDir("assets")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".html") {
			continue
		}
		body, rerr := assets.ReadFile("assets/" + f.Name())
		if rerr != nil {
			t.Fatal(rerr)
		}
		sources[f.Name()] = string(body)
	}
	// The playground builds its script in Go rather than in a template, so the
	// walk above cannot see it. Rendered and added here rather than left to
	// its own test: the point of this is that there is one list.
	rendered, _ := fetchPlayground(t)
	sources["playground (rendered)"] = rendered

	checked := 0
	for name, page := range sources {

		at := strings.Index(page, "<script")
		if at < 0 {
			continue
		}
		checked++
		script := page[at:]

		for _, sink := range []string{"innerHTML", "outerHTML", "eval(",
			"document.write", "new Function", "setTimeout(\""} {
			if strings.Contains(script, sink) {
				t.Errorf("%s uses %s", name, sink)
			}
		}
		// Nothing external, which is what lets script-src stay nonce-only and
		// connect-src stay 'self'. A library here would need a host in the
		// policy, reopening exactly what the nonce closed.
		for _, ext := range []string{"http://", "https://", "//cdn", "integrity="} {
			if strings.Contains(script, ext) {
				t.Errorf("%s references something external: %q", name, ext)
			}
		}
		// A script tag without a nonce is a script the policy will refuse to
		// run — a page that silently does nothing.
		for _, tag := range scriptTags(page) {
			if !strings.Contains(tag, "nonce=") {
				t.Errorf("%s has a script tag with no nonce: %s", name, tag)
			}
		}
	}
	if checked < 3 {
		t.Errorf("only %d templates with scripts were checked; this program "+
			"serves three and the walk is wrong", checked)
	}
}

func scriptTags(page string) []string {
	var out []string
	rest := page
	for {
		at := strings.Index(rest, "<script")
		if at < 0 {
			return out
		}
		rest = rest[at:]
		end := strings.Index(rest, ">")
		if end < 0 {
			return out
		}
		out = append(out, rest[:end+1])
		rest = rest[end+1:]
	}
}

// An address is not a domain, and a browser will not take one.
//
// This is the case the secure-context rule lets through: http://127.0.0.1 is
// a secure context, so everything looked fine, the screen offered the button,
// and Chrome answered "This is an invalid domain" from inside
// navigator.credentials — where the server never sees it and the page appears
// to do nothing.
//
// Found by driving a real browser at these routes (scripts/passkey/
// browsercheck.mjs). Reading the specification did not produce it: it says a
// relying party id is a valid domain string, and does not say what a browser
// does when handed an address instead.
func TestAnAddressIsRefusedAsARelyingParty(t *testing.T) {
	srv, token := fullyWired(t)

	for _, host := range []string{"127.0.0.1:8801", "[::1]:8801"} {
		req := httptest.NewRequest(http.MethodPost,
			"http://"+host+"/passkeys/challenge", nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d; the button would be offered and would "+
				"then fail inside the browser", host, w.Code)
			continue
		}
		// The message has to name the way out, or somebody reads "needs a
		// domain name" and has no idea what to do on their own machine.
		if !strings.Contains(w.Body.String(), "localhost") {
			t.Errorf("%s is refused without suggesting localhost: %s",
				host, w.Body.String())
		}
	}
}

// The policy on these pages must keep everything the shell needs, not only
// what the script needs.
//
// It replaced the admin's policy wholesale and dropped manifest-src, so the
// web manifest was blocked on exactly these two screens: the admin stayed
// installable everywhere else and quietly stopped being installable here.
func TestThePasskeyPolicyKeepsWhatTheShellNeeds(t *testing.T) {
	srv, token := fullyWired(t)

	for _, path := range []string{"/passkeys", "/signin/passkey"} {
		csp := get(t, srv, path, token).Header().Get("Content-Security-Policy")
		for _, need := range []string{"manifest-src 'self'", "style-src 'self'"} {
			if !strings.Contains(csp, need) {
				t.Errorf("%s omits %q, so part of the shell is blocked on "+
					"this screen and nowhere else: %s", path, need, csp)
			}
		}
	}
}

// A change to a passkey lands on the key it is for.
//
// Requests run at once, and the list was changed by index: a sign-in found
// its key, checked the signature and wrote the counter back at the index it
// had found, and a removal in between shifted the list, so the counter that
// detects a cloned key moved onto somebody else's. A removal cut at an index
// found before another removal moved it, taking the wrong person's key.
func TestAPasskeyChangeLandsOnTheKeyItIsFor(t *testing.T) {
	cred := func(id, who string, n uint32) StoredCredential {
		return StoredCredential{Credential: webauthn.Credential{ID: []byte(id), Principal: who, SignCount: n}}
	}
	p := &Passkeys{Credentials: []StoredCredential{cred("a", "ada", 1), cred("b", "bo", 5), cred("c", "cy", 9)}}
	// Bo's sign-in finds the key; Ada removes hers before it writes back.
	b, ok := p.lookup([]byte("b"))
	if !ok {
		t.Fatal("no key b")
	}
	if _, err := p.remove([]byte("a"), "ada"); err != nil {
		t.Fatal(err)
	}
	used := b.Credential
	used.SignCount = 6
	if err := p.noteUse(b.ID, used, time.Now()); err != nil {
		t.Fatal(err)
	}
	got := map[string]uint32{}
	for _, c := range p.list() {
		got[string(c.ID)] = c.SignCount
	}
	if got["b"] != 6 || got["c"] != 9 {
		t.Fatalf("the counter landed on the wrong key: %v", got)
	}
	// Somebody else's key is not theirs to remove, and a removed key signs
	// nobody in.
	if _, err := p.remove([]byte("c"), "bo"); !errors.Is(err, errPasskeyGone) {
		t.Fatalf("bo removed cy's key: %v", err)
	}
	if err := p.noteUse([]byte("a"), used, time.Now()); !errors.Is(err, errPasskeyGone) {
		t.Fatalf("a removed key was written back: %v", err)
	}
	if err := p.add(cred("b", "bo", 0)); !errors.Is(err, errPasskeyExists) {
		t.Fatalf("a key was kept twice: %v", err)
	}

	// And at once, which the race detector checks: what ends up kept is
	// what was added and not removed.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := []byte(fmt.Sprintf("k%d", i))
			_ = p.add(cred(string(id), "ivo", 0))
			_ = p.noteUse(id, webauthn.Credential{ID: id, SignCount: 1}, time.Now())
			if i%2 == 0 {
				_, _ = p.remove(id, "ivo")
			}
			_ = p.list()
		}(i)
	}
	wg.Wait()
	if n := len(p.list()); n != 2+25 {
		t.Fatalf("%d keys kept; 2 and 25 of 50 were left", n)
	}
}
