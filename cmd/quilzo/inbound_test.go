// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/inbound"
	"github.com/quilzo/quilzo/internal/oidc"
	"github.com/quilzo/quilzo/internal/spool"
	"github.com/quilzo/quilzo/internal/ssf"
	"github.com/quilzo/quilzo/internal/telemetry"
)

func shownSecret(t *testing.T, shown []string, prefix string) string {
	t.Helper()
	for _, s := range shown {
		if v, ok := strings.CutPrefix(s, prefix); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("no %q in %v", prefix, shown)
	return ""
}

func session(t *testing.T, root, who string) {
	t.Helper()
	ts, _ := loadTokens(root)
	if _, _, err := ts.IssueSession("s", who, auth.RoleAuthor, "/", 3600e9, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	_ = saveJSON(tokensPath(root), ts)
}

func sessionState(t *testing.T, root, who string) (live, held int) {
	t.Helper()
	ts, _ := loadTokens(root)
	for _, tok := range ts.Snapshot() {
		if tok.Principal != who || tok.Revoked {
			continue
		}
		live++
		if tok.StepUp != "" {
			held++
		}
	}
	return
}

func storedFrom(t *testing.T, root, src string) int {
	t.Helper()
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Release()
	n := 0
	_ = sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		if e.Source == src {
			n++
		}
		return nil
	})
	return n
}

func oktaLogEvent(uuid, typ, actor, target string) map[string]any {
	ev := map[string]any{"uuid": uuid, "published": time.Now().UTC().Format(time.RFC3339), "eventType": typ,
		"displayMessage": typ, "outcome": map[string]any{"result": "SUCCESS"},
		"actor":  map[string]any{"id": "00u-" + actor, "type": "User", "alternateId": actor},
		"client": map[string]any{"ipAddress": "81.2.69.9"}}
	if target != "" {
		ev["target"] = []any{map[string]any{"id": "00u-" + target, "type": "User", "alternateId": target}}
	}
	return ev
}

func oktaPost(t *testing.T, inb *inboundServer, secret, eventID string, events ...map[string]any) int {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"eventType": "com.okta.event_hook", "eventId": eventID,
		"data": map[string]any{"events": events}})
	r := httptest.NewRequest(http.MethodPost, "/feeds/okta", strings.NewReader(string(b)))
	r.Header.Set("Authorization", secret)
	w := httptest.NewRecorder()
	inb.ServeHTTP(w, r)
	return w.Code
}

// Okta's hook is verified once, then every delivery that carries the secret
// is stored, read by the rules at once, and what it means for a person is
// acted on — here a suspension in Okta ends the sessions here.
func TestAnOktaEventHookIsStoredDetectedAndActedOn(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	_, shown, err := makeFeed(root, "okta", "okta", nil, "boss")
	if err != nil {
		t.Fatal(err)
	}
	secret := shownSecret(t, shown, "Authorization header value:")
	if err := detectPack(root, []string{"install"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAutomate(root, []string{"add", "signal-disabled"}); err != nil {
		t.Fatal(err)
	}
	session(t, root, "ivo@acme.example")
	inb := newInboundServer(root)

	// Okta's verification: echoed with the secret, refused without it.
	r := httptest.NewRequest(http.MethodGet, "/feeds/okta", nil)
	r.Header.Set("X-Okta-Verification-Challenge", "ch-1")
	r.Header.Set("Authorization", secret)
	w := httptest.NewRecorder()
	inb.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"verification":"ch-1"`) {
		t.Fatalf("verification answered %d %s", w.Code, w.Body)
	}
	r.Header.Set("Authorization", "not-the-secret")
	w = httptest.NewRecorder()
	inb.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("a wrong secret was answered %d", w.Code)
	}

	if code := oktaPost(t, inb, secret, "e-1",
		oktaLogEvent("u-1", "user.account.privilege.grant", "admin@acme.example", "mal@acme.example"),
		oktaLogEvent("u-2", "user.lifecycle.suspend", "admin@acme.example", "ivo@acme.example")); code != 200 {
		t.Fatalf("a delivery was answered %d", code)
	}
	inb.process()
	if n := storedFrom(t, root, "okta/system"); n != 2 {
		t.Errorf("%d events stored", n)
	}
	// The rules ran without anybody running them.
	reg, _, _ := finding.Load(findingsPath(root))
	found := false
	for _, f := range reg.All(time.Now()) {
		found = found || f.Source == "okta.admin-privilege-granted"
	}
	if !found {
		recs, _ := audit.Read(auditPath(root))
		for _, rec := range recs {
			if rec.Action == "detect.run" {
				t.Logf("detect.run %s %v", rec.Outcome, rec.Detail)
			}
		}
		t.Error("an administrator role granted in Okta raised nothing")
	}
	// And the suspension reached the sessions here.
	if live, _ := sessionState(t, root, "ivo@acme.example"); live != 0 {
		t.Errorf("%d sessions of a person suspended in Okta are still alive", live)
	}
	// Okta delivers at least once: the same delivery again changes nothing.
	if code := oktaPost(t, inb, secret, "e-1", oktaLogEvent("u-2", "user.lifecycle.suspend", "admin@acme.example", "ivo@acme.example")); code != 200 {
		t.Errorf("a repeated delivery was answered %d", code)
	}
	inb.process()
	if n := storedFrom(t, root, "okta/system"); n != 2 {
		t.Errorf("a repeated delivery was stored again: %d events", n)
	}
	if st := inb.snapshot()["okta"]; st.Refused != 1 || st.Signals != 1 {
		t.Errorf("status %+v", st)
	}
}

func standardHeaders(secret, id string, ts int64, body string) http.Header {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "%s.%d.%s", id, ts, body)
	h := http.Header{}
	h.Set("webhook-id", id)
	h.Set("webhook-timestamp", fmt.Sprint(ts))
	h.Set("webhook-signature", "v1,"+base64.StdEncoding.EncodeToString(m.Sum(nil)))
	return h
}

func TestASignedWebhookIsTakenOnceAndForgeriesAreRefused(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	_, shown, err := makeFeed(root, "webhook", "hook", map[string]string{"mapping": "okta/system"}, "boss")
	if err != nil {
		t.Fatal(err)
	}
	secret := shownSecret(t, shown, "signing secret:")
	inb := newInboundServer(root)
	b, _ := json.Marshal(oktaLogEvent("w-1", "user.session.start", "ada@acme.example", ""))
	post := func(h http.Header, body string) int {
		r := httptest.NewRequest(http.MethodPost, "/feeds/hook", strings.NewReader(body))
		for k, v := range h {
			r.Header[k] = v
		}
		w := httptest.NewRecorder()
		inb.ServeHTTP(w, r)
		return w.Code
	}
	now := time.Now().Unix()
	if c := post(standardHeaders(secret, "msg_1", now, string(b)), string(b)); c != 204 {
		t.Fatalf("a good delivery was answered %d", c)
	}
	if c := post(standardHeaders(secret, "msg_1", now, string(b)), string(b)); c != 200 {
		t.Errorf("the same delivery again was answered %d", c)
	}
	other, _ := inbound.NewWebhookSecret()
	for name, h := range map[string]http.Header{
		"another key":     standardHeaders(other, "msg_2", now, string(b)),
		"ten minutes old": standardHeaders(secret, "msg_3", now-600, string(b)),
		"another body":    standardHeaders(secret, "msg_4", now, string(b)+" "),
	} {
		if c := post(h, string(b)); c != 401 {
			t.Errorf("%s was answered %d", name, c)
		}
	}
	inb.process()
	if n := storedFrom(t, root, "okta/system"); n != 1 {
		t.Errorf("%d events stored from one good delivery", n)
	}
}

// -- shared signals -----------------------------------------------------------

type transmitter struct{ k *rsa.PrivateKey }

func (tr transmitter) jwks() []byte {
	b, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(tr.k.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(tr.k.PublicKey.E)).Bytes())}}})
	return b
}

func (tr transmitter) set(t *testing.T, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"})
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, tr.k, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const (
	ssfIss = "https://acme.okta.com"
	ssfAud = "https://admin.acme.example/feeds/signals"
)

func event(jti, uri string, sub map[string]any, ev map[string]any) map[string]any {
	return map[string]any{"iss": ssfIss, "aud": ssfAud, "jti": jti, "iat": time.Now().Unix(),
		"sub_id": sub, "events": map[string]any{uri: ev}}
}

// A transmitter's events are verified against its keys and acted on as
// they arrive: a compromised credential holds the sessions here, an Okta
// user known only by Okta's id is found through the identity links, and a
// verification event marks the stream verified.
func TestASharedSignalIsVerifiedAndActedOnAtOnce(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tr := transmitter{k}
	push, digest, _ := inbound.NewSecret()
	if err := saveFeeds(root, map[string]inbound.Feed{"signals": {Name: "signals", Kind: inbound.SSF,
		Issuer: ssfIss, Audience: ssfAud, JWKSURI: ssfIss + "/oauth2/v1/keys", TokenHash: digest,
		Alias: "okta", StreamID: "s-1", State: inbound.Digest("state-1")}}); err != nil {
		t.Fatal(err)
	}
	if err := saveAliases(root, map[string]alias{"okta:00u-nia": {Person: "nia@acme.example", How: "linked"}}); err != nil {
		t.Fatal(err)
	}
	for _, tpl := range []string{"signal-compromised", "signal-session-revoked"} {
		if err := cmdAutomate(root, []string{"add", tpl}); err != nil {
			t.Fatal(err)
		}
	}
	session(t, root, "ada@acme.example")
	session(t, root, "nia@acme.example")
	inb := newInboundServer(root)
	ks, _ := oidc.NewKeySet(ssfIss+"/oauth2/v1/keys", func(context.Context, string) ([]byte, error) { return tr.jwks(), nil })
	inb.receivers["signals"] = cachedReceiver{key: ssfIss + "|" + ssfAud + "|" + ssfIss + "/oauth2/v1/keys",
		r: &ssf.Receiver{Issuer: ssfIss, Audience: ssfAud, Keys: ks, Algorithms: []oidc.Algorithm{oidc.RS256}}}

	send := func(token, auth string) (int, string) {
		r := httptest.NewRequest(http.MethodPost, "/feeds/signals", strings.NewReader(token))
		r.Header.Set("Content-Type", "application/secevent+jwt")
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		inb.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	compromised := tr.set(t, event("j-1", "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
		map[string]any{"format": "email", "email": "ada@acme.example"}, map[string]any{"credential_type": "password"}))
	if c, body := send(compromised, ""); c != 401 || !strings.Contains(body, "authentication_failed") {
		t.Errorf("a push without the stream's header: %d %s", c, body)
	}
	if c, body := send(compromised, "Bearer "+push); c != 202 {
		t.Fatalf("a good event: %d %s", c, body)
	}
	revoked := tr.set(t, event("j-2", "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
		map[string]any{"format": "iss_sub", "iss": ssfIss, "sub": "00u-nia"},
		map[string]any{"reason_admin": map[string]any{"en": "Admin cleared sessions"}}))
	if c, _ := send(revoked, "Bearer "+push); c != 202 {
		t.Fatalf("session-revoked was answered %d", c)
	}
	inb.process()
	if live, held := sessionState(t, root, "ada@acme.example"); live != 1 || held != 1 {
		t.Errorf("after a compromised credential, ada has %d sessions, %d held", live, held)
	}
	if live, _ := sessionState(t, root, "nia@acme.example"); live != 0 {
		t.Errorf("a session revoked in Okta left %d alive here", live)
	}
	if n := storedFrom(t, root, "feed/signals"); n != 2 {
		t.Errorf("%d signals stored as events", n)
	}
	// A forged one, and a replayed one.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := transmitter{other}.set(t, event("j-3", "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
		map[string]any{"format": "email", "email": "boss@acme.example"}, map[string]any{}))
	if c, body := send(forged, "Bearer "+push); c != 400 || !strings.Contains(body, "invalid_key") {
		t.Errorf("a forged event: %d %s", c, body)
	}
	if c, _ := send(compromised, "Bearer "+push); c != 202 {
		t.Errorf("a replayed event was answered %d", c)
	}
	inb.process()
	if st := inb.snapshot()["signals"]; st.Signals != 2 || st.Refused != 2 {
		t.Errorf("status %+v", st)
	}
	// Verification, with the state that was asked for.
	verify := tr.set(t, event("j-4", ssf.Verification, map[string]any{"format": "opaque", "id": "s-1"}, map[string]any{"state": "state-1"}))
	if c, _ := send(verify, "Bearer "+push); c != 202 {
		t.Errorf("verification was answered %d", c)
	}
	feeds, _ := loadFeeds(root)
	if feeds["signals"].Verified.IsZero() {
		t.Error("the stream was not marked verified")
	}
}

// From the command line too: an analyst reads feeds and cannot add one,
// switch one off or remove one.
func TestAnAnalystCannotAddAFeedFromATerminal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "sam", "analyst"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := makeFeed(root, "okta", "okta", nil, "boss"); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("t", "sam", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_ = saveJSON(tokensPath(root), ts)
	t.Setenv("QUILZO_TOKEN", secret)
	if err := cmdInbound(root, []string{"list"}); err != nil {
		t.Errorf("an analyst could not list feeds: %v", err)
	}
	for _, c := range [][]string{{"add", "okta", "mine"}, {"off", "okta"}, {"remove", "okta"}} {
		if err := cmdInbound(root, c); err == nil {
			t.Errorf("an analyst ran inbound %v", c)
		}
	}
	feeds, _ := loadFeeds(root)
	if len(feeds) != 1 || feeds["okta"].Off {
		t.Errorf("feeds after an analyst tried: %+v", feeds)
	}
}

// A verification event proves the stream only with the state asked for.
func TestVerificationNeedsTheStateThatWasAskedFor(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tr := transmitter{k}
	if err := saveFeeds(root, map[string]inbound.Feed{"signals": {Name: "signals", Kind: inbound.SSF,
		Issuer: ssfIss, Audience: ssfAud, JWKSURI: ssfIss + "/oauth2/v1/keys", StreamID: "s-1",
		State: inbound.Digest("state-1")}}); err != nil {
		t.Fatal(err)
	}
	inb := newInboundServer(root)
	ks, _ := oidc.NewKeySet(ssfIss+"/oauth2/v1/keys", func(context.Context, string) ([]byte, error) { return tr.jwks(), nil })
	inb.receivers["signals"] = cachedReceiver{key: ssfIss + "|" + ssfAud + "|" + ssfIss + "/oauth2/v1/keys",
		r: &ssf.Receiver{Issuer: ssfIss, Audience: ssfAud, Keys: ks, Algorithms: []oidc.Algorithm{oidc.RS256}}}
	r := httptest.NewRequest(http.MethodPost, "/feeds/signals", strings.NewReader(
		tr.set(t, event("v-1", ssf.Verification, map[string]any{"format": "opaque", "id": "s-1"}, map[string]any{"state": "a-guess"}))))
	r.Header.Set("Content-Type", "application/secevent+jwt")
	inb.ServeHTTP(httptest.NewRecorder(), r)
	if feeds, _ := loadFeeds(root); !feeds["signals"].Verified.IsZero() {
		t.Error("a verification event with another state verified the stream")
	}
}
