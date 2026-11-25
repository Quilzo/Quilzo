// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/render"
)

// signoffHost is the name the admin is reached by in these tests: a
// domain, as a passkey's relying party has to be.
const signoffHost = "quilzo.example"

// signoff is somebody signed in to the admin of the store at root with a
// passkey, as the server wires it.
type signoff struct {
	t     *testing.T
	srv   *admin.Server
	token string
	key   *passkey
}

func signoffFor(t *testing.T, root, name string) *signoff {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	srv.Passkeys = &admin.Passkeys{}
	srv.Audit = func(action, resource string, detail map[string]string) {
		record(root, adminRecord(action, resource, detail))
	}
	srv.AuditRecord = func(rec audit.Record) error { return recordE(root, rec) }
	srv.AuditReady = func() error { return auditReady(root) }
	tok, _, err := toks.IssueSession("passkey:"+name, name, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	b := &signoff{t: t, srv: srv, token: tok, key: newPasskey(t)}
	der, err := x509.MarshalPKIXPublicKey(b.key.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := b.json("/passkeys/challenge", nil)["challenge"].(string)
	b.json("/passkeys/register", map[string]any{"id": b64(b.key.id), "challenge": challenge, "label": "a test key",
		"clientDataJSON":    b64(b.clientData("webauthn.create", challenge)),
		"authenticatorData": b64(b.key.authData(signoffHost)), "publicKey": b64(der), "algorithm": -7})
	return b
}

func (b *signoff) clientData(kind, challenge string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": "https://" + signoffHost,
		"crossOrigin": false})
	return raw
}

// do sends a request as the person signed in, over TLS, as the page's own
// script sends it.
func (b *signoff) do(method, path, contentType string, body []byte) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequest(method, "https://"+signoffHost+path, bytes.NewReader(body))
	req.Host, req.TLS = signoffHost, &tls.ConnectionState{}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Origin", "https://"+signoffHost)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	b.srv.Handler().ServeHTTP(w, req)
	return w
}

func (b *signoff) json(path string, body any) map[string]any {
	b.t.Helper()
	raw, _ := json.Marshal(body)
	w := b.do(http.MethodPost, path, "application/json", raw)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK {
		b.t.Fatalf("%s answered %d: %s", path, w.Code, w.Body.String())
	}
	return out
}

// approve is the person approving a waiting decision on Sign-off with their
// passkey, over the challenge the page asked for.
func (b *signoff) approve(id string) *httptest.ResponseRecorder {
	b.t.Helper()
	challenge, _ := b.json("/register/approvals/item/"+id+"/challenge", nil)["challenge"].(string)
	b.key.count++
	cd, ad := b.clientData("webauthn.get", challenge), b.key.authData(signoffHost)
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, b.key.key, digest[:])
	if err != nil {
		b.t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"id": b64(b.key.id), "challenge": challenge, "clientDataJSON": b64(cd),
		"authenticatorData": b64(ad), "signature": b64(sig)})
	return b.do(http.MethodPost, "/register/approvals/item/"+id+"/approve", "application/json", raw)
}

// surfaceOf is the hash `quilzo approval show` gives a waiting decision.
func surfaceOf(t *testing.T, root, token, id string) string {
	t.Helper()
	o, e, code := cliRun(t, root, token, "--json", "approval", "show", id)
	var v struct{ Surface string }
	if code != 0 || json.Unmarshal([]byte(o), &v) != nil || v.Surface == "" {
		t.Fatalf("approval show %s: %d %s %s", id, code, firstLines(o, 4), e)
	}
	return v.Surface
}

// One person is one pseudonym on every surface, so whoever raised a
// decision is known as its raiser wherever they try to approve it. A scope
// lee raises on the command line is refused lee on Sign-off, and a key lee
// asks to pin in the admin is refused lee at the console; somebody else
// approves each.
//
// The command line named lee by the programme's own keeper, Sign-off by the
// approvals' file and the admin's other screens by the subject map: three
// pseudonyms for one person, and a person who raised a decision approved
// it as somebody the register could not tell from anybody else.
func TestOnePersonIsOnePseudonymOnTheCommandLineAndInTheAdmin(t *testing.T) {
	root, owner := accessStore(t)
	lee := programmeApprover(t, root, owner)

	o, e, code := cliRun(t, root, lee, "--json", "soa", "scope", "group", "--title", "The group", "--domains", "identity")
	if code != 0 {
		t.Fatalf("soa scope: %d %s", code, e)
	}
	scope := waitingID(t, o)
	signedIn := signoffFor(t, root, "lee")
	w := signedIn.approve(scope)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "raised or drafted") {
		t.Fatalf("lee approving on Sign-off the scope lee raised on the command line answered %d: %s", w.Code, w.Body.String())
	}
	if _, err := register.Open(signedIn.srv.Store).Get(register.ID(scope)); err == nil {
		t.Fatal("the scope is in the register, approved by the person who raised it")
	}
	if _, e, code := cliRun(t, root, owner, "approval", "approve", scope, "--surface", surfaceOf(t, root, owner, scope)); code != 0 {
		t.Fatalf("the owner approving lee's scope at the console exited %d: %s", code, firstLines(e, 3))
	}

	// The reverse: lee asks in the admin for a key to be pinned.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	form := url.Values{"name": {"vendor"}, "title": {"A vendor's build service"}, "key": {string(pemKey)}}
	if w := signedIn.do(http.MethodPost, "/evidence/keys", "application/x-www-form-urlencoded", []byte(form.Encode())); w.Code != http.StatusOK {
		t.Fatalf("asking to pin a key in the admin answered %d: %s", w.Code, firstLines(w.Body.String(), 20))
	}
	o, _, _ = cliRun(t, root, owner, "--json", "register", "proposals")
	var waiting struct {
		Proposals []struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		} `json:"proposals"`
	}
	_ = json.Unmarshal([]byte(o), &waiting)
	pin := ""
	for _, p := range waiting.Proposals {
		if p.Kind == string(register.KindPinnedKey) {
			pin = p.ID
		}
	}
	if pin == "" {
		t.Fatalf("the key lee asked to pin does not wait for an approval: %s", firstLines(o, 8))
	}
	hash := surfaceOf(t, root, lee, pin)
	if _, e, code := cliRun(t, root, lee, "approval", "approve", pin, "--surface", hash); code != 3 || !strings.Contains(e, "raised or drafted") {
		t.Fatalf("lee approving at the console the key lee asked for in the admin exited %d: %s", code, firstLines(e, 3))
	}
	if _, e, code := cliRun(t, root, owner, "approval", "approve", pin, "--surface", hash); code != 0 {
		t.Fatalf("the owner approving the pin exited %d: %s", code, firstLines(e, 3))
	}
	if o, _, _ := cliRun(t, root, owner, "evidence", "keys"); !strings.Contains(o, "vendor") {
		t.Errorf("the key approved by somebody else is not pinned: %s", firstLines(o, 6))
	}
}
