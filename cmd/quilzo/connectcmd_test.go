// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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
	"github.com/quilzo/quilzo/internal/vault"
)

// oauthProvider is a provider's token and revocation endpoints: each code
// once, a refresh rotating its token, every revocation remembered.
type oauthProvider struct {
	mu       sync.Mutex
	forms    []url.Values
	expires  int
	revoked  []string
	issued   int
	verifier string
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
					`,"refresh_token":"rt-1","scope":"calendar"}`))
			case "refresh_token":
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
