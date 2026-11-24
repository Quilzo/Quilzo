// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/connect"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/vault"
)

// oauthProvider is a provider's token and revocation endpoints: each code
// once, a refresh rotating its token (or, keeping, sending none), every
// revocation remembered. codeExtra is more of the code's answer.
type oauthProvider struct {
	mu        sync.Mutex
	forms     []url.Values
	expires   int
	revoked   []string
	issued    int
	verifier  string
	codeExtra string
	keeping   bool
}

func (o *oauthProvider) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		o.mu.Lock()
		defer o.mu.Unlock()
		o.forms = append(o.forms, r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			o.issued++
			switch r.PostForm.Get("grant_type") {
			case "authorization_code":
				if r.PostForm.Get("code") != "the-code" || r.PostForm.Get("code_verifier") == "" ||
					r.PostForm.Get("client_secret") != "app-secret" {
					w.WriteHeader(400)
					w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				o.verifier = r.PostForm.Get("code_verifier")
				w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer","expires_in":` + itoa(o.expires) +
					`,"refresh_token":"rt-1","scope":"calendar"` + o.codeExtra + `}`))
			case "refresh_token":
				if o.keeping {
					w.Write([]byte(`{"access_token":"at-2","token_type":"Bearer","expires_in":3600}`))
					return
				}
				w.Write([]byte(`{"access_token":"at-2","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-2"}`))
			}
		case "/revoke":
			o.revoked = append(o.revoked, r.PostForm.Get("token"))
			w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	// The provider's endpoints over the test server's own certificate: the
	// checked client is what production uses, and refuses this machine.
	was := connectPoster
	connectPoster = func(ctx context.Context, to string, form url.Values) ([]byte, error) {
		resp, err := srv.Client().PostForm(to, form)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var b strings.Builder
		_, err = io.Copy(&b, resp.Body)
		return []byte(b.String()), err
	}
	t.Cleanup(func() { connectPoster = was })
	return srv
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// keyedDemo is the demo store with a keyring, its key supplied as an
// operator would.
func keyedDemo(t *testing.T) string {
	t.Helper()
	root := demoStore(t)
	kr, err := vault.NewKeyring("k1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(keyEnv, vault.EncodeKey(kr.Keys["k1"].Key))
	if err := saveJSON(keyringPath(root), kr); err != nil {
		t.Fatal(err)
	}
	return root
}

// A person connects their account at a provider: PKCE, a state that
// finishes once and only for them, tokens sealed, refreshed when due and
// sent only to the provider's hosts; disconnecting revokes them there.
func TestAPersonConnectsTheirAccount(t *testing.T) {
	root := keyedDemo(t)
	op := &oauthProvider{expires: 30}
	srv := op.serve(t)
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("admin.base_url", "https://cms.example", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := setAgentSecret(root, "acme-oauth", "app-secret", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := cmdConnect(root, []string{"provider", "add", "acme", "--title", "Acme", "--auth-url", srv.URL + "/authorize",
		"--token-url", srv.URL + "/token", "--revocation-url", srv.URL + "/revoke", "--client-id", "quilzo",
		"--client-secret", "acme-oauth", "--scope", "calendar", "--host", "api.acme.example"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdConnect(root, []string{"provider", "add", "leaky", "--title", "Leaky", "--auth-url", "http://id.leaky.example/a",
		"--token-url", "http://id.leaky.example/t", "--client-id", "x", "--host", "api.leaky.example"}); err == nil {
		t.Fatal("a provider reached over plain http was declared")
	}

	to, err := beginConnect(root, "acme", "dana")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(to)
	state := u.Query().Get("state")
	if u.Query().Get("redirect_uri") != "https://cms.example/connections/callback" || u.Query().Get("code_challenge") == "" {
		t.Fatalf("%s", to)
	}
	// Finished in somebody else's session: refused, and spent.
	if _, err := finishConnect(context.Background(), root, state, "the-code", "eve"); err == nil {
		t.Fatal("somebody else finished dana's connection")
	}
	if _, err := finishConnect(context.Background(), root, state, "the-code", "dana"); err == nil {
		t.Fatal("a state finished twice")
	}
	to, _ = beginConnect(root, "acme", "dana")
	u, _ = url.Parse(to)
	if title, err := finishConnect(context.Background(), root, u.Query().Get("state"), "the-code", "dana"); err != nil || title != "Acme" {
		t.Fatalf("%q %v", title, err)
	}
	b, _ := os.ReadFile(connectionsPath(root))
	if strings.Contains(string(b), "at-1") || strings.Contains(string(b), "rt-1") || strings.Contains(string(b), "dana") {
		t.Fatalf("a token or a name is readable in %s", b)
	}
	if mine, _ := myConnections(root, "dana"); len(mine) != 1 || mine[0].Scope != "calendar" {
		t.Fatalf("%+v", mine)
	}
	if mine, _ := myConnections(root, "eve"); len(mine) != 0 {
		t.Fatal("eve sees dana's connection")
	}

	// Due within the minute: refreshed, and the rotated refresh token kept.
	tok, err := connectionToken(context.Background(), root, "acme", "dana", "api.acme.example")
	if err != nil || tok != "at-2" {
		t.Fatalf("%q %v", tok, err)
	}
	if last := op.forms[len(op.forms)-1]; last.Get("grant_type") != "refresh_token" || last.Get("refresh_token") != "rt-1" {
		t.Fatalf("%v", last)
	}
	if tok, _ := connectionToken(context.Background(), root, "acme", "dana", "api.acme.example"); tok != "at-2" {
		t.Fatalf("refreshed again needlessly: %q", tok)
	}
	if _, err := connectionToken(context.Background(), root, "acme", "dana", "evil.example"); err == nil {
		t.Fatal("a token went to a host its provider does not name")
	}
	if _, err := connectionToken(context.Background(), root, "acme", "eve", "api.acme.example"); err == nil {
		t.Fatal("eve's agents used dana's account")
	}
	client := newMCPClientFor(root, "dana")
	if got, err := client.Connection(context.Background(), "acme", "api.acme.example"); err != nil || got != "at-2" {
		t.Fatalf("%q %v", got, err)
	}
	if newMCPClient(root).Connection != nil {
		t.Fatal("a client acting for nobody holds somebody's account")
	}

	if err := revokeConnection(context.Background(), root, "acme", "dana"); err != nil {
		t.Fatal(err)
	}
	if len(op.revoked) != 2 || op.revoked[0] != "rt-2" || op.revoked[1] != "at-2" {
		t.Fatalf("revoked %v", op.revoked)
	}
	if _, err := connectionToken(context.Background(), root, "acme", "dana", "api.acme.example"); err == nil {
		t.Fatal("a disconnected account still answers")
	}
}

// An Instagram account comes with no refresh token. Kept as it came, the
// token lasted an hour and the next use said "connect again"; it is
// exchanged for one lasting sixty days when it is connected, at the
// address Meta documents, and renewed where it is used once it is a day
// old. A renewal that fails while the token still works uses the token as
// it is; one that fails once it has lapsed says to connect again. A
// provider declared by hand names its dialect.
func TestAnInstagramAccountIsRenewedWhereItIsUsed(t *testing.T) {
	root := keyedDemo(t)
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("admin.base_url", "https://cms.example", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := setAgentSecret(root, "instagram-oauth", "app-secret", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	var (
		mu         sync.Mutex
		gets       []*url.URL
		renewFails bool
	)
	wasPost, wasGet := connectPoster, connectGetter
	t.Cleanup(func() { connectPoster, connectGetter = wasPost, wasGet })
	connectPoster = func(_ context.Context, to string, form url.Values) ([]byte, error) {
		if to != "https://api.instagram.com/oauth/access_token" || form.Get("client_secret") != "app-secret" ||
			form.Get("code") != "the-code" {
			return []byte(`{"error_type":"OAuthException","code":400,"error_message":"not this"}`), nil
		}
		return []byte(`{"data":[{"access_token":"ig-short","user_id":"1","permissions":"instagram_business_basic"}]}`), nil
	}
	connectGetter = func(_ context.Context, raw string) (int, http.Header, []byte, error) {
		mu.Lock()
		defer mu.Unlock()
		u, err := url.Parse(raw)
		if err != nil || u.Host != "graph.instagram.com" {
			return 0, nil, nil, err
		}
		gets = append(gets, u)
		q := u.Query()
		switch {
		case u.Path == "/access_token" && q.Get("grant_type") == "ig_exchange_token" && q.Get("access_token") == "ig-short" &&
			q.Get("client_secret") == "app-secret":
			return 200, nil, []byte(`{"access_token":"ig-long-1","token_type":"bearer","expires_in":5184000}`), nil
		case u.Path == "/refresh_access_token" && q.Get("grant_type") == "ig_refresh_token" && !renewFails:
			return 200, nil, []byte(`{"access_token":"ig-long-2","token_type":"bearer","expires_in":5184000}`), nil
		}
		return 400, nil, []byte(`{"error":{"message":"Session has expired","type":"OAuthException","code":190}}`), nil
	}
	asked := func() []*url.URL {
		mu.Lock()
		defer mu.Unlock()
		return append([]*url.URL(nil), gets...)
	}
	// age changes the sealed token as the passing of time would.
	age := func(change func(*connect.Token)) {
		t.Helper()
		key := accountKey("instagram", "dana")
		if err := changeAccounts(root, func(f *accounts, kr *vault.Keyring) error {
			a := f.Accounts[key]
			tok, err := openToken(kr, key, a.Sealed)
			if err != nil {
				return err
			}
			change(&tok)
			a.Sealed, err = sealToken(kr, key, tok)
			f.Accounts[key] = a
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := cmdConnect(root, []string{"provider", "add", "instagram", "--template", "instagram", "--client-id", "ig-app",
		"--client-secret", "instagram-oauth"}); err != nil {
		t.Fatal(err)
	}
	to, err := beginConnect(root, "instagram", "dana")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(to)
	if u.Query().Get("scope") != "instagram_business_basic,instagram_business_content_publish" {
		t.Fatalf("%s", to)
	}
	if title, err := finishConnect(context.Background(), root, u.Query().Get("state"), "the-code", "dana"); err != nil || title != "Instagram" {
		t.Fatalf("%q %v", title, err)
	}
	if tok, err := connectionToken(context.Background(), root, "instagram", "dana", "graph.instagram.com"); err != nil ||
		tok != "ig-long-1" || len(asked()) != 1 {
		t.Fatalf("%q %v %v", tok, err, asked())
	}

	// A day on, it is renewed where it is used, and not again until the
	// next day.
	age(func(tok *connect.Token) { tok.Renew = time.Now().Add(-time.Minute) })
	if tok, err := connectionToken(context.Background(), root, "instagram", "dana", "graph.instagram.com"); err != nil || tok != "ig-long-2" {
		t.Fatalf("%q %v", tok, err)
	}
	if got := asked(); len(got) != 2 || got[1].Path != "/refresh_access_token" || got[1].Query().Get("access_token") != "ig-long-1" {
		t.Fatalf("%v", got)
	}
	if tok, _ := connectionToken(context.Background(), root, "instagram", "dana", "graph.instagram.com"); tok != "ig-long-2" || len(asked()) != 2 {
		t.Fatalf("renewed again needlessly: %q", tok)
	}

	mu.Lock()
	renewFails = true
	mu.Unlock()
	age(func(tok *connect.Token) { tok.Renew = time.Now().Add(-time.Minute) })
	if tok, err := connectionToken(context.Background(), root, "instagram", "dana", "graph.instagram.com"); err != nil || tok != "ig-long-2" {
		t.Fatalf("a token that works was not used when its renewal failed: %q %v", tok, err)
	}
	// Nor when the renewal cannot be asked for, the client secret being
	// unreadable where the token is used (a process started without the
	// variable that carries it): the call failed, a day after connecting,
	// with a token that worked for weeks more.
	mu.Lock()
	renewFails = false
	mu.Unlock()
	kept, err := loadAgentSecrets(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveAgentSecrets(root, agentSecrets{}); err != nil {
		t.Fatal(err)
	}
	if tok, err := connectionToken(context.Background(), root, "instagram", "dana", "graph.instagram.com"); err != nil || tok != "ig-long-2" {
		t.Fatalf("a token that works was not used when its client secret could not be read: %q %v", tok, err)
	}
	if err := saveAgentSecrets(root, kept); err != nil {
		t.Fatal(err)
	}
	age(func(tok *connect.Token) { tok.Expiry = time.Now().Add(-time.Minute) })
	if _, err := connectionToken(context.Background(), root, "instagram", "dana", "graph.instagram.com"); err == nil ||
		!strings.Contains(err.Error(), "connect it again") {
		t.Fatalf("a lapsed token: %v", err)
	}

	if err := cmdConnect(root, []string{"provider", "add", "clips", "--title", "TikTok", "--auth-url", "https://www.tiktok.com/v2/auth/authorize/",
		"--token-url", "https://open.tiktokapis.com/v2/oauth/token/", "--client-id", "aw-key", "--client-secret", "tiktok-oauth",
		"--scope", "user.info.basic", "--scope", "video.upload", "--host", "open.tiktokapis.com", "--dialect", "tiktok"}); err != nil {
		t.Fatal(err)
	}
	to, err = beginConnect(root, "clips", "dana")
	if err != nil {
		t.Fatal(err)
	}
	if u, _ = url.Parse(to); u.Query().Get("client_key") != "aw-key" || u.Query().Get("scope") != "user.info.basic,video.upload" {
		t.Fatalf("%s", to)
	}
	if err := cmdConnect(root, []string{"provider", "add", "odd", "--template", "github", "--client-id", "x", "--dialect", "carrier-pigeon"}); err == nil {
		t.Fatal("a dialect nobody wrote was declared")
	}
}

// A provider declared by hand at a social platform's address speaks that
// platform's dialect, as its template does. Declared so with no --dialect,
// as the audit declared TikTok, it was asked for client_id and its scopes
// separated by spaces, and TikTok refused the request; an Instagram one
// lapsed within the hour. --dialect oauth2 still declares one otherwise,
// and a provider anywhere else is written and asked as it always was.
func TestAProviderDeclaredByHandAtAPlatformSpeaksItsDialect(t *testing.T) {
	root := keyedDemo(t)
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("admin.base_url", "https://cms.example", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	asks := func(name string) url.Values {
		t.Helper()
		to, err := beginConnect(root, name, "dana")
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(to)
		if err != nil {
			t.Fatal(err)
		}
		return u.Query()
	}
	tiktok := func(name string, extra ...string) error {
		return cmdConnect(root, append([]string{"provider", "add", name, "--title", "TikTok",
			"--auth-url", "https://www.tiktok.com/v2/auth/authorize/", "--token-url", "https://open.tiktokapis.com/v2/oauth/token/",
			"--client-id", "aw-key", "--scope", "user.info.basic", "--scope", "video.upload", "--host", "open.tiktokapis.com"}, extra...))
	}

	if err := tiktok("clips", "--client-secret", "tiktok-oauth"); err != nil {
		t.Fatal(err)
	}
	if q := asks("clips"); q.Get("client_key") != "aw-key" || q.Has("client_id") || q.Get("scope") != "user.info.basic,video.upload" ||
		q.Has("code_challenge") {
		t.Fatalf("TikTok declared by hand was asked %v", q)
	}
	if err := tiktok("nosecret"); err == nil || !strings.Contains(err.Error(), "--client-secret") ||
		!strings.Contains(err.Error(), "--dialect oauth2") {
		t.Fatalf("TikTok without its client secret: %v", err)
	}
	if err := tiktok("plain", "--dialect", "oauth2"); err != nil {
		t.Fatal(err)
	}
	if q := asks("plain"); q.Get("client_id") != "aw-key" || q.Get("scope") != "user.info.basic video.upload" {
		t.Fatalf("declared as plain OAuth 2, it was asked %v", q)
	}

	if err := cmdConnect(root, []string{"provider", "add", "gram", "--title", "Instagram",
		"--auth-url", "https://www.instagram.com/oauth/authorize", "--token-url", "https://api.instagram.com/oauth/access_token",
		"--client-id", "ig-app", "--client-secret", "instagram-oauth", "--scope", "instagram_business_basic",
		"--host", "graph.instagram.com"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdConnect(root, []string{"provider", "add", "acme", "--title", "Acme",
		"--auth-url", "https://id.acme.example/authorize", "--token-url", "https://id.acme.example/token",
		"--client-id", "quilzo", "--scope", "calendar.read", "--host", "api.acme.example"}); err != nil {
		t.Fatal(err)
	}
	set, err := loadConnectProviders(root)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]connect.Dialect{"clips": connect.TikTok, "plain": connect.OAuth2,
		"gram": connect.MetaInstagram, "acme": ""} {
		if p, _ := set.get(name); p.Dialect != want {
			t.Errorf("%s was declared in %q, not %q", name, p.Dialect, want)
		}
	}
	if q := asks("acme"); q.Get("client_id") != "quilzo" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("a provider at no platform was asked %v", q)
	}
}

// quilzo connect list, and its --json, say when a connection's tokens end:
// the access token's, and the refresh token's where the provider says.
// A refresh that keeps the refresh token keeps when it ends (LinkedIn's
// lives a year from the first and does not renew). A connection kept
// before these were is said not to be known, and learns them the next
// time it is used. Kept only inside the sealed token, they were never
// shown, and a connection simply stopped one day.
func TestConnectListSaysWhenTokensEnd(t *testing.T) {
	root := keyedDemo(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	t.Setenv("USER", "dana")
	op := &oauthProvider{expires: 30, codeExtra: `,"refresh_token_expires_in":31536000`, keeping: true}
	srv := op.serve(t)
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("admin.base_url", "https://cms.example", "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := setAgentSecret(root, "acme-oauth", "app-secret", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := cmdConnect(root, []string{"provider", "add", "acme", "--title", "Acme", "--auth-url", srv.URL + "/authorize",
		"--token-url", srv.URL + "/token", "--client-id", "quilzo", "--client-secret", "acme-oauth", "--host", "api.acme.example"}); err != nil {
		t.Fatal(err)
	}
	to, _ := beginConnect(root, "acme", "dana")
	u, _ := url.Parse(to)
	if _, err := finishConnect(context.Background(), root, u.Query().Get("state"), "the-code", "dana"); err != nil {
		t.Fatal(err)
	}
	old := w
	t.Cleanup(func() { w = old })
	listed := func() []map[string]any {
		t.Helper()
		var doc bytes.Buffer
		w = out.New(true)
		w.Out = &doc
		if err := cmdConnect(root, []string{"list"}); err != nil {
			t.Fatal(err)
		}
		var got []map[string]any
		if err := json.Unmarshal(doc.Bytes(), &got); err != nil || len(got) != 1 {
			t.Fatalf("%v %s", err, doc.String())
		}
		return got
	}
	said := func() string {
		t.Helper()
		var doc bytes.Buffer
		w = out.New(false)
		w.Out = &doc
		if err := cmdConnect(root, []string{"list"}); err != nil {
			t.Fatal(err)
		}
		return doc.String()
	}
	at := func(doc map[string]any, key string) time.Time {
		t.Helper()
		s, _ := doc[key].(string)
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("%s is %v: %v", key, doc[key], doc)
		}
		return v
	}
	year := time.Now().Add(365 * 24 * time.Hour)
	got := listed()[0]
	if d := at(got, "access_expires").Sub(time.Now()); d < 0 || d > time.Minute {
		t.Errorf("the access token ends in %s", d)
	}
	refresh := at(got, "refresh_expires")
	if d := refresh.Sub(year); d < -time.Minute || d > time.Minute {
		t.Errorf("the refresh token ends %s", refresh)
	}
	if strings.Contains(fmt.Sprint(got), "at-1") || strings.Contains(fmt.Sprint(got), "rt-1") {
		t.Fatalf("a token in the list: %v", got)
	}
	if text := said(); !strings.Contains(text, "refresh token until "+refresh.Local().Format("2 Jan 2006")) {
		t.Errorf("connect list does not say when the refresh token ends:\n%s", text)
	}

	// Due: refreshed, the refresh token kept, and when it ends with it.
	if tok, err := connectionToken(context.Background(), root, "acme", "dana", "api.acme.example"); err != nil || tok != "at-2" {
		t.Fatalf("%q %v", tok, err)
	}
	got = listed()[0]
	if d := at(got, "access_expires").Sub(time.Now()); d < 59*time.Minute || d > time.Hour {
		t.Errorf("the refreshed access token ends in %s", d)
	}
	if !at(got, "refresh_expires").Equal(refresh) {
		t.Errorf("a kept refresh token's end was lost: %v", got)
	}

	// Kept before its ends were: not known, until it is next used.
	raw, _ := os.ReadFile(connectionsPath(root))
	var file map[string]map[string]map[string]any
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, a := range file["accounts"] {
		delete(a, "access_expires")
		delete(a, "refresh_expires")
		delete(a, "renews")
	}
	raw, _ = json.Marshal(file)
	if err := os.WriteFile(connectionsPath(root), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := listed()[0]; got["access_expires"] != nil || got["refresh_expires"] != nil {
		t.Fatalf("an end made up: %v", got)
	}
	if text := said(); !strings.Contains(text, "not known") {
		t.Errorf("an unknown end is not said so:\n%s", text)
	}
	if _, err := connectionToken(context.Background(), root, "acme", "dana", "api.acme.example"); err != nil {
		t.Fatal(err)
	}
	if got := listed()[0]; got["access_expires"] == nil || got["renews"] != true {
		t.Fatalf("not learnt on use: %v", got)
	}

	// One that stops within the week says so, and what to run; one that
	// has stopped says it has. Told to connect it again "before" a time
	// gone by, a person read a connection that no longer worked as one
	// that still did.
	refreshEnds := func(at time.Time) string {
		t.Helper()
		raw, _ := os.ReadFile(connectionsPath(root))
		var file map[string]map[string]map[string]any
		if err := json.Unmarshal(raw, &file); err != nil {
			t.Fatal(err)
		}
		for _, a := range file["accounts"] {
			a["refresh_expires"], a["renews"] = at.UTC().Format(time.RFC3339), true
		}
		raw, _ = json.Marshal(file)
		if err := os.WriteFile(connectionsPath(root), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return said()
	}
	if text := refreshEnds(time.Now().Add(72 * time.Hour)); !strings.Contains(text, "connect it again before") ||
		!strings.Contains(text, "quilzo connect start acme") {
		t.Errorf("one that stops within the week does not say so:\n%s", text)
	}
	if text := refreshEnds(time.Now().Add(-48 * time.Hour)); strings.Contains(text, "connect it again before") ||
		!strings.Contains(text, "stopped working") || !strings.Contains(text, "quilzo connect start acme") {
		t.Errorf("one that has stopped does not say it has:\n%s", text)
	}
}
