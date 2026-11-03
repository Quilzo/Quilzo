// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/mail"
	"github.com/quilzo/quilzo/internal/oauthas"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/saml"
	"github.com/quilzo/quilzo/internal/ssf"
)

// The identity provider's security events, end to end: connected with the
// real command against a stand-in transmitter, pushed through the admin's
// real route, and acted on in the real store.

const (
	txIss      = "https://idp.example"
	txAdmin    = "https://admin.example"
	caepEvent  = "https://schemas.openid.net/secevent/caep/event-type/"
	riscEvent  = "https://schemas.openid.net/secevent/risc/event-type/"
	ssfEvent   = "https://schemas.openid.net/secevent/ssf/event-type/"
	txClientID = "quilzo-stream"
)

var (
	txKeyOnce sync.Once
	txKey     *rsa.PrivateKey
)

// transmitterKey is one signing key for every test here: a 2048-bit key
// takes long enough to make that worth sharing.
func transmitterKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	txKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		txKey = k
	})
	return txKey
}

// transmitter stands in for the identity provider's: its keys, its
// configuration and token endpoint, its stream API, and what it was told.
type transmitter struct {
	t   *testing.T
	key *rsa.PrivateKey

	mu       sync.Mutex
	bearer   string // the Authorization the stream was made with
	aud      string
	state    string // the state verification was last asked with
	asked    int
	deleted  bool
	clientOK bool
	n        int
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func answer(status int, v any) *fetch.Result {
	b, _ := json.Marshal(v)
	return &fetch.Result{Status: status, Body: b}
}

func (x *transmitter) Do(_ context.Context, method, raw string, body []byte, h map[string]string) (*fetch.Result, error) {
	if _, err := fetch.ValidateURL(raw); err != nil {
		return nil, err
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	switch method + " " + raw {
	case "GET " + txIss + "/.well-known/ssf-configuration":
		return answer(200, map[string]any{"issuer": txIss, "jwks_uri": txIss + "/keys",
			"delivery_methods_supported": []string{ssf.PushMethod},
			"configuration_endpoint":     txIss + "/ssf/stream", "status_endpoint": txIss + "/ssf/status",
			"verification_endpoint": txIss + "/ssf/verify"}), nil
	case "GET " + txIss + "/.well-known/oauth-authorization-server":
		return answer(200, map[string]any{"issuer": txIss, "token_endpoint": txIss + "/oauth2/token"}), nil
	case "POST " + txIss + "/oauth2/token":
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(txClientID+":client-secret"))
		if h["Authorization"] != want {
			return answer(401, map[string]any{"error": "invalid_client"}), nil
		}
		x.clientOK = true
		return answer(200, map[string]any{"access_token": "at-1", "token_type": "Bearer"}), nil
	case "POST " + txIss + "/ssf/stream":
		var asked struct {
			Delivery struct {
				Endpoint string `json:"endpoint_url"`
				Auth     string `json:"authorization_header"`
			} `json:"delivery"`
			Events []string `json:"events_requested"`
		}
		_ = json.Unmarshal(body, &asked)
		x.bearer, x.aud = asked.Delivery.Auth, asked.Delivery.Endpoint
		return answer(201, map[string]any{"stream_id": "s-1", "iss": txIss, "aud": asked.Delivery.Endpoint,
			"events_delivered": asked.Events}), nil
	case "POST " + txIss + "/ssf/verify":
		var v struct{ State string }
		_ = json.Unmarshal(body, &v)
		x.state = v.State
		x.asked++
		return &fetch.Result{Status: 204}, nil
	case "GET " + txIss + "/ssf/status?stream_id=s-1":
		return answer(200, map[string]any{"status": "enabled"}), nil
	case "DELETE " + txIss + "/ssf/stream?stream_id=s-1":
		x.deleted = true
		return &fetch.Result{Status: 204}, nil
	case "GET " + txIss + "/keys":
		return answer(200, map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
			"n": b64url(x.key.PublicKey.N.Bytes()), "e": b64url(big.NewInt(int64(x.key.PublicKey.E)).Bytes())}}}), nil
	}
	return &fetch.Result{Status: 404}, nil
}

// event is a security event token from this transmitter.
func (x *transmitter) event(t *testing.T, typ string, sub, claims map[string]any, iat time.Time) string {
	t.Helper()
	x.mu.Lock()
	x.n++
	jti := fmt.Sprintf("jti-%d", x.n)
	aud := x.aud
	x.mu.Unlock()
	if claims == nil {
		claims = map[string]any{}
	}
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"})
	cb, _ := json.Marshal(map[string]any{"iss": txIss, "aud": aud, "jti": jti, "iat": iat.Unix(),
		"sub_id": sub, "events": map[string]any{typ: claims}})
	in := b64url(hb) + "." + b64url(cb)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, x.key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64url(sig)
}

func email(addr string) map[string]any { return map[string]any{"format": "email", "email": addr} }

// signalsCase is a store with an OIDC provider, a stream connected to its
// transmitter, mail to the security contact, and the admin's route.
type signalsCase struct {
	root  string
	tx    *transmitter
	route http.Handler
	sent  *[]mail.Message
	mu    *sync.Mutex
}

func signalsStore(t *testing.T, claim string) *signalsCase {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	if w == nil {
		w = out.New(false)
	}
	old := w
	t.Cleanup(func() { w = old })
	w = out.New(false)
	w.Out = &bytes.Buffer{}
	root := t.TempDir() + "/st"
	t.Cleanup(func() { finishBackground(10 * time.Second) })
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(oidcPath(root), &oidcConfig{Issuer: txIss, ClientID: "quilzo",
		RedirectURI: txAdmin + "/auth/callback", Claim: claim, RequireVerifiedEmail: true}); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	for _, b := range []auth.Binding{
		{Principal: "boss@example.com", Role: auth.RoleAdmin, Resource: "/"},
		{Principal: "dana@example.com", Role: auth.RoleAdmin, Resource: "/"},
		{Principal: "ada@example.com", Role: auth.RoleAuthor, Resource: "/"},
		{Principal: "00u-ada", Role: auth.RoleAuthor, Resource: "/"},
	} {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("security.contact", "mailto:security@example.com", "", "boss@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mailConfigPath(root), []byte(`{"host":"relay.example:587","from":"quilzo@example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &signalsCase{root: root, tx: &transmitter{t: t, key: transmitterKey(t)}, sent: &[]mail.Message{}, mu: &sync.Mutex{}}
	oldMail := deliverMail
	deliverMail = func(_ *mail.Mailer, m mail.Message) error {
		c.mu.Lock()
		defer c.mu.Unlock()
		*c.sent = append(*c.sent, m)
		return nil
	}
	t.Cleanup(func() { deliverMail = oldMail })
	oldClient := signalsClient
	signalsClient = func() ssf.HTTP { return c.tx }
	t.Cleanup(func() { signalsClient = oldClient })
	t.Setenv(signalsSecretEnv, "client-secret")
	return c
}

// connect connects the stream with the real command, and builds the route.
func (c *signalsCase) connect(t *testing.T, provider string) {
	t.Helper()
	if err := cmdSignals(c.root, []string{"connect", "--provider", provider, "--client-id", txClientID}); err != nil {
		t.Fatal(err)
	}
	c.restart(t)
}

// restart is the server started again: a new route, a new receiver, and
// everything it held in memory, the ids it had seen among it, forgotten.
func (c *signalsCase) restart(t *testing.T) {
	t.Helper()
	s, err := open(c.root)
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := loadPolicy(c.root)
	toks, _ := loadTokens(c.root)
	srv, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	srv.Signals = signalsHooks(c.root)
	srv.Shield = newShieldHost(c.root).off
	c.route = srv.Handler()
}

func (c *signalsCase) push(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	return c.pushWith(t, c.tx.bearer, "application/secevent+jwt", token)
}

func (c *signalsCase) pushWith(t *testing.T, authorization, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, admin.SignalsPath, strings.NewReader(body))
	req.RemoteAddr = "198.51.100.7:443"
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	c.route.ServeHTTP(w, req)
	return w
}

// send pushes one event and insists it was accepted.
func (c *signalsCase) send(t *testing.T, typ string, sub, claims map[string]any, iat time.Time) {
	t.Helper()
	if w := c.push(t, c.tx.event(t, typ, sub, claims, iat)); w.Code != http.StatusAccepted {
		t.Fatalf("%s was answered %d: %s", typ, w.Code, w.Body)
	}
}

func (c *signalsCase) mails() []mail.Message {
	finishBackground(10 * time.Second)
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]mail.Message(nil), *c.sent...)
}

// session is a credential somebody holds: a session one way of signing in
// made, or a long-lived token when method is empty.
func session(t *testing.T, root, name, who, method string) string {
	t.Helper()
	ts, _ := loadTokens(root)
	var secret string
	var err error
	if method == "" {
		secret, _, err = ts.Issue(name, who, auth.RoleAuthor, "/", 24*time.Hour, auth.RoleAdmin)
	} else {
		secret, _, err = ts.IssueSession(name, who, auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin, method)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	return secret
}

func stepUpOf(root, secret string) string {
	ts, _ := loadTokens(root)
	tok, err := ts.Authenticate(secret, time.Now())
	if tok == nil {
		return "revoked: " + fmt.Sprint(err)
	}
	return tok.StepUp
}

func signalsActions(t *testing.T, root string) map[string][]audit.Event {
	t.Helper()
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]audit.Event{}
	for _, e := range evs {
		if strings.HasPrefix(e.Action, "signals.") {
			out[e.Action] = append(out[e.Action], e)
		}
	}
	return out
}

func readSignals(t *testing.T, root string) *signalsConfig {
	t.Helper()
	c, err := loadSignals(root)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Connecting asks the transmitter for a stream with a push secret of its
// own, keeps only the secret's digest, and asks for verification.
func TestConnectingAsksTheTransmitterForAStreamAndKeepsOnlyADigest(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	got := readSignals(t, c.root)
	if !c.tx.clientOK || got.Stream != "s-1" || got.Provider != "oidc" || got.Audience != txAdmin+"/sso/signals" ||
		c.tx.aud != txAdmin+"/sso/signals" || c.tx.asked != 1 || got.State == "" || got.Status != "enabled" {
		t.Fatalf("connected as %+v, transmitter %+v", got, c.tx)
	}
	secret := strings.TrimPrefix(c.tx.bearer, "Bearer ")
	if !strings.HasPrefix(secret, signalsPushPrefix) || got.Push != ssf.Digest(secret) {
		t.Fatalf("the push secret was not handed over and kept as a digest: %q", c.tx.bearer)
	}
	raw, _ := os.ReadFile(signalsPath(c.root))
	for _, secretly := range []string{secret, c.tx.state, "client-secret", "at-1"} {
		if strings.Contains(string(raw), secretly) {
			t.Errorf("signals.json holds %q", secretly)
		}
	}
	if len(signalsActions(t, c.root)["signals.connected"]) != 1 {
		t.Error("connecting was not recorded")
	}
	if err := cmdSignals(c.root, []string{"connect", "--provider", "oidc", "--client-id", txClientID}); err == nil {
		t.Error("a second stream was connected over the first")
	}
}

// With a key set and no stream API, the push address and a secret are
// shown once, for the transmitter's own console.
func TestAStreamMadeByHandGetsItsSecretOnceAndCannotBeAskedToVerify(t *testing.T) {
	c := signalsStore(t, "email")
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	if err := cmdSignals(c.root, []string{"connect", "--provider", "oidc", "--jwks", txIss + "/keys"}); err != nil {
		t.Fatal(err)
	}
	var shown struct {
		Push string `json:"push_url"`
		Auth string `json:"authorization"`
	}
	if err := json.Unmarshal(buf.Bytes(), &shown); err != nil || shown.Push != txAdmin+admin.SignalsPath ||
		!strings.HasPrefix(shown.Auth, "Bearer "+signalsPushPrefix) {
		t.Fatalf("shown %s (%v)", buf.Bytes(), err)
	}
	got := readSignals(t, c.root)
	if !got.Manual || got.Push != ssf.Digest(strings.TrimPrefix(shown.Auth, "Bearer ")) || got.State != "" {
		t.Fatalf("kept %+v", got)
	}
	if c.tx.asked != 0 {
		t.Error("a stream made by hand was asked to verify")
	}
	if err := cmdSignals(c.root, []string{"off"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSignals(c.root, []string{"connect", "--provider", "oidc", "--jwks", txIss + "/keys",
		"--client-id", txClientID}); err == nil {
		t.Error("both --jwks and --client-id were taken")
	}
}

// No bearer or the wrong one, the wrong content type, or a body over the
// cap: refused at the admin's route, counted, and nothing acted on.
func TestAPushThatProvesNothingChangesNothing(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	sso := session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO)
	good := c.tx.event(t, caepEvent+"session-revoked", email("ada@example.com"), nil, time.Now())

	if w := c.pushWith(t, "", "application/secevent+jwt", good); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Body.String(), "authentication_failed") {
		t.Errorf("no bearer: %d %s", w.Code, w.Body)
	}
	if w := c.pushWith(t, "Bearer "+signalsPushPrefix+"guessed", "application/secevent+jwt", good); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Body.String(), "authentication_failed") {
		t.Errorf("the wrong bearer: %d %s", w.Code, w.Body)
	}
	if w := c.pushWith(t, c.tx.bearer, "application/json", good); w.Code != http.StatusBadRequest {
		t.Errorf("the wrong content type: %d %s", w.Code, w.Body)
	}
	if w := c.pushWith(t, c.tx.bearer, "application/secevent+jwt", strings.Repeat("e", ssf.MaxToken+1)); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("over the cap: %d %s", w.Code, w.Body)
	}
	if !works(c.root, sso) {
		t.Fatal("a push that proved nothing ended a session")
	}
	if got := readSignals(t, c.root).Counts; got.Refused != 4 || got.Received != 0 {
		t.Errorf("counted %+v", got)
	}
	// One summary for the hour, not one record per refusal.
	if n := len(signalsActions(t, c.root)["signals.refused"]); n != 1 {
		t.Errorf("%d refusal summaries", n)
	}
}

// The same event pushed again is accepted and acted on once.
func TestAReplayedEventIsAcceptedAndActedOnOnceThroughTheRoute(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO)
	tok := c.tx.event(t, caepEvent+"session-revoked", email("ada@example.com"), nil, time.Now())
	for i := 0; i < 2; i++ {
		if w := c.push(t, tok); w.Code != http.StatusAccepted {
			t.Fatalf("push %d: %d %s", i, w.Code, w.Body)
		}
	}
	if n := len(signalsActions(t, c.root)["signals.sessions-ended"]); n != 1 {
		t.Errorf("acted on %d times", n)
	}
}

// A session the provider ended ends here: the one it signed in, and not
// the passkey session, the long-lived token or the app the person connected.
func TestASessionTheProviderEndedEndsHereAndNothingElseDoes(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	sso := session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO)
	pk := session(t, c.root, "passkey:ada@example.com", "ada@example.com", auth.MethodPasskey)
	laptop := session(t, c.root, "laptop", "ada@example.com", "")
	app := grantFor(t, c.root, "ada@example.com")

	c.send(t, caepEvent+"session-revoked", email("Ada@Example.com"), nil, time.Now())
	if works(c.root, sso) {
		t.Error("the provider's session still works")
	}
	for name, secret := range map[string]string{"passkey session": pk, "long-lived token": laptop} {
		if !works(c.root, secret) {
			t.Errorf("the %s ended with the provider's session", name)
		}
	}
	if !appWorks(c.root, app) {
		t.Error("the app's token ended with the provider's session")
	}
	ended := signalsActions(t, c.root)["signals.sessions-ended"]
	if len(ended) != 1 || ended[0].Detail["count"] != "1" || ended[0].Kind != audit.KindService || !ended[0].Verified {
		t.Errorf("recorded %+v", ended)
	}
}

// appWorks is an app's access token, presented to the agent interface it
// was issued for.
func appWorks(root, secret string) bool {
	ts, _ := loadTokens(root)
	_, err := ts.AuthenticateFor(secret, txAdmin+"/mcp", time.Now())
	return err == nil
}

// grantFor connects an app for somebody, and returns its access token.
func grantFor(t *testing.T, root, who string) string {
	t.Helper()
	const res = txAdmin + "/mcp"
	now := time.Now()
	g := oauthas.Grant{ID: "gr_000000000000signal", Principal: who, Client: "https://app.example.com/meta",
		Resource: res, Created: now, Expires: now.Add(24 * time.Hour), Refresh: ssf.Digest("qzrt_app-refresh")}
	writeGrants(t, root, g)
	ts, _ := loadTokens(root)
	secret, _, err := ts.IssueForGrant(who, auth.RoleAuthor, auth.Scope{}, g.Client, g.ID, res, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	return secret
}

// Who an event is about is read the way the bound provider names people,
// and is somebody the policy knows; anything else is counted and left.
func TestASubjectIsMatchedOnlyByTheProvidersOwnRule(t *testing.T) {
	t.Run("claim sub", func(t *testing.T) {
		c := signalsStore(t, "sub")
		c.connect(t, "oidc")
		sso := session(t, c.root, "oidc:00u-ada", "00u-ada", auth.MethodSSO)
		other := session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO)
		c.send(t, caepEvent+"session-revoked", email("ada@example.com"), nil, time.Now())
		c.send(t, caepEvent+"session-revoked", map[string]any{"format": "iss_sub", "iss": "https://other.example", "sub": "00u-ada"}, nil, time.Now())
		if !works(c.root, sso) || !works(c.root, other) {
			t.Fatal("an address, or another issuer's iss_sub, matched under claim sub")
		}
		c.send(t, caepEvent+"session-revoked", map[string]any{"format": "iss_sub", "iss": txIss, "sub": "00u-ada"}, nil, time.Now())
		if works(c.root, sso) {
			t.Error("iss_sub from the OIDC issuer did not end the session")
		}
		if got := readSignals(t, c.root).Counts; got.Unmatched != 2 || got.Acted != 1 {
			t.Errorf("counted %+v", got)
		}
	})
	t.Run("claim email", func(t *testing.T) {
		c := signalsStore(t, "email")
		c.connect(t, "oidc")
		sso := session(t, c.root, "oidc:00u-ada", "00u-ada", auth.MethodSSO)
		c.send(t, caepEvent+"session-revoked", map[string]any{"format": "iss_sub", "iss": txIss, "sub": "00u-ada"}, nil, time.Now())
		c.send(t, caepEvent+"session-revoked", email("nobody@example.com"), nil, time.Now())
		if !works(c.root, sso) {
			t.Error("iss_sub matched under claim email")
		}
		if got := readSignals(t, c.root).Counts; got.Unmatched != 2 || got.Acted != 0 {
			t.Errorf("counted %+v", got)
		}
		if len(signalsActions(t, c.root)["signals.sessions-ended"]) != 0 {
			t.Error("an unmatched event was acted on")
		}
	})
}

// A stream bound to one SAML provider ends that provider's sessions only.
func TestAStreamBoundToASAMLProviderEndsOnlyItsSessions(t *testing.T) {
	c := signalsStore(t, "email")
	for _, sc := range []saml.Config{
		{Name: "okta", URL: txAdmin, EntityID: "http://www.okta.com/x", SSOURL: "https://okta.example/sso",
			NameIDFormat: saml.FormatEmail, Domains: []string{"example.com"}},
		{Name: "other", URL: txAdmin, EntityID: "http://other.example/x", SSOURL: "https://other.example/sso",
			NameIDFormat: saml.FormatEmail},
	} {
		if err := os.MkdirAll(samlDir(c.root), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := saveJSON(samlFile(c.root, sc.Name), sc); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdSignals(c.root, []string{"connect", "--provider", "saml:okta", "--issuer", txIss, "--client-id", txClientID}); err != nil {
		t.Fatal(err)
	}
	c.restart(t)
	okta := session(t, c.root, "saml:okta:ada@example.com", "ada@example.com", auth.MethodSSO)
	other := session(t, c.root, "saml:other:ada@example.com", "ada@example.com", auth.MethodSSO)
	oidcs := session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO)
	c.send(t, riscEvent+"sessions-revoked", email("ada@example.com"), nil, time.Now())
	if works(c.root, okta) {
		t.Error("the bound provider's session still works")
	}
	if !works(c.root, other) || !works(c.root, oidcs) {
		t.Error("another provider's session ended")
	}
	// Never iss_sub, under SAML.
	c.send(t, riscEvent+"sessions-revoked", map[string]any{"format": "iss_sub", "iss": txIss, "sub": "ada@example.com"}, nil, time.Now())
	if readSignals(t, c.root).Counts.Unmatched != 1 {
		t.Error("an iss_sub was matched under SAML")
	}
}

// A credential added changes nothing; one changed ends the sessions.
func TestACredentialChangeEndsSessionsOnlyWhenOneChanged(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	sso := session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO)
	c.send(t, caepEvent+"credential-change", email("ada@example.com"),
		map[string]any{"credential_type": "fido2-roaming", "change_type": "create"}, time.Now())
	if !works(c.root, sso) {
		t.Fatal("a credential added ended a session")
	}
	c.send(t, caepEvent+"credential-change", email("ada@example.com"),
		map[string]any{"credential_type": "password", "change_type": "update"}, time.Now())
	if works(c.root, sso) {
		t.Error("a password changed did not end the session")
	}
}

// A compromised credential ends the provider's sessions, holds the rest
// until the person proves it is them, and tells the security contact.
func TestACompromisedCredentialStepsUpTheRestAndTellsSecurity(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	sso := session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO)
	pk := session(t, c.root, "passkey:ada@example.com", "ada@example.com", auth.MethodPasskey)
	c.send(t, riscEvent+"credential-compromise", email("ada@example.com"),
		map[string]any{"credential_type": "password"}, time.Now())
	if works(c.root, sso) {
		t.Error("the provider's session still works")
	}
	if got := stepUpOf(c.root, pk); !strings.Contains(got, "compromised") {
		t.Errorf("the passkey session was not held: %q", got)
	}
	sent := c.mails()
	if len(sent) != 1 || sent[0].To != "security@example.com" || !strings.Contains(sent[0].Body, "ada@example.com") {
		t.Fatalf("mailed %+v", sent)
	}
	acts := signalsActions(t, c.root)
	if len(acts["signals.step-up"]) != 1 || len(acts["signals.told"]) != 1 {
		t.Errorf("recorded %v", acts)
	}
}

// A disabled account is suspended: every token, every app, and a deny
// that passkey sign-in refuses (internal/admin, which checks the shape this
// asserts).
func TestADisabledAccountIsSuspendedLikeProvisioningSuspends(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	creds := []string{
		session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO),
		session(t, c.root, "passkey:ada@example.com", "ada@example.com", auth.MethodPasskey),
		session(t, c.root, "laptop", "ada@example.com", ""),
	}
	app := grantFor(t, c.root, "ada@example.com")
	c.send(t, riscEvent+"account-disabled", email("ada@example.com"), map[string]any{"reason": "hijacking"}, time.Now())
	for i, secret := range creds {
		if works(c.root, secret) {
			t.Errorf("credential %d still works", i)
		}
	}
	if appWorks(c.root, app) {
		t.Error("the app's token still works")
	}
	// The app's refresh is refused for what it is: the connection ended.
	h := appsServer(c.root, &Caller{Name: "app", Kind: audit.KindService})
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {"qzrt_app-refresh"},
		"client_id": {"https://app.example.com/meta"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	h.Token(rw, req)
	if rw.Code != http.StatusBadRequest || !strings.Contains(rw.Body.String(), "invalid_grant") {
		t.Errorf("a refresh after the suspension: %d %s", rw.Code, rw.Body)
	}
	p, _ := loadPolicy(c.root)
	var deny []auth.Binding
	for _, b := range p.Bindings {
		if b.Deny && b.Principal == "ada@example.com" {
			deny = append(deny, b)
		}
	}
	if len(deny) != 1 || deny[0].GrantedBy != signalsBy || deny[0].Role != auth.RoleReader || deny[0].Resource != "/" ||
		deny[0].Permission != "" || deny[0].OwnOnly || deny[0].Expires != 0 {
		t.Fatalf("the deny is %+v", deny)
	}
	if p.Evaluate("ada@example.com", auth.ActView, "/").Allowed {
		t.Error("suspended, they can still read")
	}
	if s := signalsActions(t, c.root)["signals.suspended"]; len(s) != 1 || s[0].Outcome != audit.Success {
		t.Errorf("recorded %+v", s)
	}
}

// An enabled account loses only this receiver's deny; an older
// account-enabled is refused, and still is after a restart.
func TestAnEnabledAccountLiftsOnlyThisReceiversDenyAndNeverAnOlderOne(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	if _, err := updatePolicy(c.root, func(p *auth.Policy) error {
		p.Bindings = append(p.Bindings, auth.Binding{Principal: "ada@example.com", Role: auth.RoleReader, Resource: "/",
			Deny: true, GrantedBy: scimBy, Note: "suspended: the identity provider deactivated or removed them"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(c.root, []string{"deny", "ada@example.com", "publisher", "--on", "/legal"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	denies := func() map[string]int {
		p, _ := loadPolicy(c.root)
		out := map[string]int{}
		for _, b := range p.Bindings {
			if b.Deny && b.Principal == "ada@example.com" {
				out[b.GrantedBy]++
			}
		}
		return out
	}
	c.send(t, riscEvent+"account-disabled", email("ada@example.com"), nil, now.Add(-10*time.Minute))
	if d := denies(); d[signalsBy] != 1 || d[scimBy] != 1 {
		t.Fatalf("after disabled: %v", d)
	}
	c.send(t, riscEvent+"account-enabled", email("ada@example.com"), nil, now.Add(-5*time.Minute))
	if d := denies(); d[signalsBy] != 0 || d[scimBy] != 1 || len(d) != 2 {
		t.Fatalf("after enabled: %v (want SCIM's and the hand-made one)", d)
	}
	if len(signalsActions(t, c.root)["signals.restored"]) != 1 {
		t.Error("the restoration was not recorded")
	}

	c.send(t, riscEvent+"account-disabled", email("ada@example.com"), nil, now.Add(-3*time.Minute))
	stale := c.tx.event(t, riscEvent+"account-enabled", email("ada@example.com"), nil, now.Add(-20*time.Minute))
	if w := c.push(t, stale); w.Code != http.StatusAccepted {
		t.Fatalf("%d", w.Code)
	}
	if denies()[signalsBy] != 1 {
		t.Fatal("an account-enabled older than the suspension lifted it")
	}
	c.restart(t)
	if w := c.push(t, stale); w.Code != http.StatusAccepted {
		t.Fatalf("%d", w.Code)
	}
	if denies()[signalsBy] != 1 {
		t.Fatal("after a restart, the same old account-enabled lifted the suspension")
	}
	if got := readSignals(t, c.root).Counts.Refused; got != 2 {
		t.Errorf("refused %d", got)
	}
}

// The last person who can grant access is not shut out on the provider's
// word: their sessions end, no deny is added, and the security contact is
// told.
func TestTheLastAdministratorIsNotSuspendedOnTheProvidersWord(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	if _, err := updatePolicy(c.root, func(p *auth.Policy) error {
		kept := p.Bindings[:0]
		for _, b := range p.Bindings {
			if b.Principal != "dana@example.com" {
				kept = append(kept, b)
			}
		}
		p.Bindings = kept
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sso := session(t, c.root, "oidc:boss@example.com", "boss@example.com", auth.MethodSSO)
	laptop := session(t, c.root, "laptop", "boss@example.com", "")
	c.send(t, riscEvent+"account-disabled", email("boss@example.com"), nil, time.Now())
	p, _ := loadPolicy(c.root)
	if !p.Evaluate("boss@example.com", auth.ActGrant, "/").Allowed {
		t.Fatal("the last administrator was denied")
	}
	if works(c.root, sso) {
		t.Error("their session still works")
	}
	if !works(c.root, laptop) {
		t.Error("their long-lived token was revoked, which could leave nobody able to get in")
	}
	if sent := c.mails(); len(sent) != 1 || !strings.Contains(sent[0].Body, "only person who can grant access") {
		t.Errorf("mailed %+v", sent)
	}
	if s := signalsActions(t, c.root)["signals.suspended"]; len(s) != 1 || s[0].Outcome != audit.Failure {
		t.Errorf("recorded %+v", s)
	}
}

// Twenty people an hour; the twenty-first is not acted on, the cap is
// recorded once, and the security contact is told once.
func TestNoMoreThanTwentyPeopleAnHourAreActedOn(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	if _, err := updatePolicy(c.root, func(p *auth.Policy) error {
		for i := 1; i <= 22; i++ {
			p.Bindings = append(p.Bindings, auth.Binding{Principal: fmt.Sprintf("p%d@example.com", i), Role: auth.RoleReader, Resource: "/"})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	last := session(t, c.root, "oidc:p21@example.com", "p21@example.com", auth.MethodSSO)
	for i := 1; i <= 22; i++ {
		c.send(t, caepEvent+"session-revoked", email(fmt.Sprintf("p%d@example.com", i)), nil, time.Now())
	}
	if !works(c.root, last) {
		t.Error("the twenty-first person was acted on")
	}
	// Somebody already acted on this hour is not somebody new.
	c.send(t, caepEvent+"session-revoked", email("p1@example.com"), nil, time.Now())
	acts := signalsActions(t, c.root)
	if len(acts["signals.sessions-ended"]) != 21 || len(acts["signals.capped"]) != 1 {
		t.Errorf("ended %d, capped %d", len(acts["signals.sessions-ended"]), len(acts["signals.capped"]))
	}
	if got := readSignals(t, c.root).Counts.Capped; got != 2 {
		t.Errorf("held back %d", got)
	}
	if sent := c.mails(); len(sent) != 1 || !strings.Contains(sent[0].Body, "within an hour") {
		t.Errorf("mailed %d", len(sent))
	}
}

// Verification with the state it was asked with marks the stream verified,
// and with any other does not; a stream-updated is recorded.
func TestVerificationAndStreamStatusAreRecorded(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	stream := map[string]any{"format": "opaque", "id": "s-1"}
	c.send(t, ssfEvent+"verification", stream, map[string]any{"state": "not-what-was-asked"}, time.Now())
	if !readSignals(t, c.root).Verified.IsZero() {
		t.Fatal("a verification with the wrong state verified the stream")
	}
	c.send(t, ssfEvent+"verification", stream, map[string]any{"state": c.tx.state}, time.Now())
	if got := readSignals(t, c.root); got.Verified.IsZero() || got.State != "" {
		t.Fatalf("the right state did not verify it: %+v", got)
	}
	c.send(t, ssfEvent+"stream-updated", stream, map[string]any{"status": "paused"}, time.Now())
	if got := readSignals(t, c.root).Status; got != "paused" {
		t.Errorf("status %q", got)
	}
	acts := signalsActions(t, c.root)
	if len(acts["signals.verified"]) != 1 || len(acts["signals.stream-status"]) != 1 ||
		acts["signals.stream-status"][0].Detail["status"] != "paused" {
		t.Errorf("recorded %v", acts)
	}
}

// With the shield's "signals" off, the route refuses and nothing is done.
func TestWithSignalsShieldedOffNothingIsActedOn(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	sso := session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO)
	if err := cmdShield(c.root, []string{"feature", "signals", "--reason", "a flaw in the verifier"}); err != nil {
		t.Fatal(err)
	}
	c.restart(t)
	w := c.push(t, c.tx.event(t, caepEvent+"session-revoked", email("ada@example.com"), nil, time.Now()))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Errorf("shielded off, the push was answered %d", w.Code)
	}
	if !works(c.root, sso) || readSignals(t, c.root).Counts.Received != 0 {
		t.Error("shielded off, the event was acted on")
	}
}

// Every record the receiver writes is one the log takes: each action is
// there, and no detail key is one the log refuses.
func TestEverySignalsRecordIsOneTheLogTakes(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	session(t, c.root, "oidc:ada@example.com", "ada@example.com", auth.MethodSSO)
	now := time.Now()
	c.send(t, caepEvent+"session-revoked", email("ada@example.com"), nil, now)
	c.send(t, riscEvent+"credential-compromise", email("ada@example.com"), nil, now)
	c.send(t, riscEvent+"account-disabled", email("ada@example.com"), nil, now)
	c.send(t, riscEvent+"account-enabled", email("ada@example.com"), nil, now.Add(time.Second))
	c.send(t, ssfEvent+"verification", map[string]any{"format": "opaque", "id": "s-1"}, map[string]any{"state": c.tx.state}, now)
	c.send(t, ssfEvent+"stream-updated", map[string]any{"format": "opaque", "id": "s-1"}, map[string]any{"status": "enabled"}, now)
	c.pushWith(t, "", "application/secevent+jwt", "x")
	if err := cmdSignals(c.root, []string{"off"}); err != nil {
		t.Fatal(err)
	}
	finishBackground(10 * time.Second)
	acts := signalsActions(t, c.root)
	for _, want := range []string{"signals.connected", "signals.sessions-ended", "signals.step-up", "signals.suspended",
		"signals.restored", "signals.verified", "signals.stream-status", "signals.refused", "signals.told",
		"signals.disconnected"} {
		if len(acts[want]) == 0 {
			t.Errorf("no %s was written: the log refused it, or nothing wrote it", want)
		}
	}
	for action, evs := range acts {
		for _, e := range evs {
			for k := range e.Detail {
				if why := audit.ForbiddenKey(k); why != "" {
					t.Errorf("%s: %s", action, why)
				}
			}
		}
	}
}

// Turning the stream off deletes it at the transmitter, forgets the
// stream, keeps what stops an old event lifting a suspension, and leaves
// the denies where they are.
func TestTurningTheStreamOffLeavesWhatItDid(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	c.send(t, riscEvent+"account-disabled", email("ada@example.com"), nil, time.Now())
	if err := cmdSignals(c.root, []string{"off"}); err != nil {
		t.Fatal(err)
	}
	got := readSignals(t, c.root)
	if !c.tx.deleted || got.connected() || got.Push != "" || len(got.LastActed) != 1 {
		t.Fatalf("after off: deleted %v, kept %+v", c.tx.deleted, got)
	}
	p, _ := loadPolicy(c.root)
	if p.Evaluate("ada@example.com", auth.ActView, "/").Allowed {
		t.Error("turning the stream off lifted its suspension")
	}
	c.restart(t)
	if w := c.push(t, c.tx.event(t, caepEvent+"session-revoked", email("ada@example.com"), nil, time.Now())); w.Code != http.StatusNotFound {
		t.Errorf("turned off, a push was answered %d", w.Code)
	}
}

// The server asks for verification once a day; a stream that has gone a
// day without answering is a posture finding.
func TestTheServerAsksDailyAndPostureReportsASilentStream(t *testing.T) {
	c := signalsStore(t, "email")
	c.connect(t, "oidc")
	job := signalsJob(c.root)
	if n, err := job.Do(time.Now()); err != nil || c.tx.asked != 1 {
		t.Fatalf("asked again within the day: %d %v, asked %d", n, err, c.tx.asked)
	}
	later := time.Now().Add(25 * time.Hour)
	if _, err := job.Do(later); err != nil || c.tx.asked != 2 {
		t.Fatalf("not asked after a day: %v, asked %d", err, c.tx.asked)
	}
	if len(signalsActions(t, c.root)["signals.verify-asked"]) != 1 {
		t.Error("asking was not recorded")
	}

	if err := updateSignals(c.root, func(s *signalsConfig) error {
		s.Connected = time.Now().Add(-48 * time.Hour)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rep := posture.Scan(Observe(c.root, t.TempDir(), posture.ServerFacts{AdminAddr: "127.0.0.1:8080"}), nil)
	found := false
	for _, f := range rep.Findings {
		if f.Rule == "signals.stream-silent" {
			found = true
		}
	}
	if !found {
		t.Error("a stream two days without an answer is not a finding")
	}
}

// What the command prints and the screen shows say the same thing.
func TestTheStatusSaysWhatTheStreamDid(t *testing.T) {
	c := signalsStore(t, "email")
	if err := cmdSignals(c.root, []string{"status"}); err != nil {
		t.Fatal(err)
	}
	c.connect(t, "oidc")
	c.send(t, caepEvent+"session-revoked", email("nobody@example.com"), nil, time.Now())
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	if err := cmdSignals(c.root, []string{"status"}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Connected bool          `json:"connected"`
		Counts    signalsCounts `json:"counts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil || !got.Connected || got.Counts.Unmatched != 1 {
		t.Fatalf("%s (%v)", buf.Bytes(), err)
	}
	st, err := signalsHooks(c.root).Status()
	if err != nil || st == nil || st.Provider != "oidc" || st.Unmatched != 1 || st.LastType != "session-revoked" {
		t.Errorf("the screen is told %+v (%v)", st, err)
	}
	if strings.Contains(filepath.Base(signalsPath(c.root)), "token") {
		t.Error("an odd name for the file")
	}
}
