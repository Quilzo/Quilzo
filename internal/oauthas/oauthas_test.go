// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package oauthas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

const appID = "https://app.example.com/oauth/client.json"

var appDoc = `{"client_id":"` + appID + `","client_name":"Example Assistant",
 "redirect_uris":["https://app.example.com/callback","http://127.0.0.1/cb"],
 "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
 "token_endpoint_auth_method":"none"}`

type fakeTokens struct {
	issued  map[string]Grant
	revoked map[string]bool
}

func (f *fakeTokens) Issue(g Grant, role auth.Role, ttl time.Duration, now time.Time) (string, error) {
	s, _ := newSecret("qz_")
	f.issued[s] = g
	return s, nil
}

func (f *fakeTokens) RevokeGrant(id string) error { f.revoked[id] = true; return nil }

type rig struct {
	*Server
	toks    *fakeTokens
	fetched int
	records []string
	clock   time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{toks: &fakeTokens{issued: map[string]Grant{}, revoked: map[string]bool{}},
		clock: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)}
	store := &Store{Dir: t.TempDir()}
	r.Server = &Server{
		Config: func() Config {
			return Config{Issuer: "https://admin.example.org", Hosts: []string{"app.example.com"}}
		},
		Store: store,
		Directory: &Directory{
			Registered: func() ([]Client, error) { c, _, err := store.Clients(); return c, err },
			Fetch: func(ctx context.Context, u string) ([]byte, time.Duration, error) {
				r.fetched++
				if u == appID {
					return []byte(appDoc), time.Hour, nil
				}
				return nil, 0, errors.New("not found")
			},
		},
		Tokens: r.toks,
		Record: func(a, p string, d map[string]string) { r.records = append(r.records, a) },
		Now:    func() time.Time { return r.clock },
	}
	return r
}

func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authQuery(challenge string) url.Values {
	return url.Values{
		"client_id": {appID}, "redirect_uri": {"https://app.example.com/callback"},
		"response_type": {"code"}, "state": {"xyz"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "resource": {"https://admin.example.org/mcp"},
		"scope": {"mcp:write mcp:read"},
	}
}

func (r *rig) post(t *testing.T, handler http.HandlerFunc, form url.Values) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("a token response may be cached")
	}
	return w.Code, out
}

// connect runs the flow to the token response.
func (r *rig) connect(t *testing.T) (map[string]any, string) {
	t.Helper()
	verifier, challenge := pkce()
	req, err := r.Parse(context.Background(), authQuery(challenge))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(req.Scopes, " ") != "mcp:read mcp:write" {
		t.Fatalf("scopes %v", req.Scopes)
	}
	p, err := r.Hold(req, "dana")
	if err != nil {
		t.Fatal(err)
	}
	taken, err := r.Take(p.ID, "dana")
	if err != nil {
		t.Fatal(err)
	}
	to, err := r.Approve(taken, req.Scopes, true)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(to)
	q := u.Query()
	if u.Host != "app.example.com" || q.Get("state") != "xyz" || q.Get("iss") != "https://admin.example.org" || q.Get("code") == "" {
		t.Fatalf("redirect %s", to)
	}
	code, out := r.post(t, r.Token, url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")},
		"client_id": {appID}, "redirect_uri": {"https://app.example.com/callback"}, "code_verifier": {verifier},
		"resource": {"https://admin.example.org/mcp"}})
	if code != 200 {
		t.Fatalf("redeem: %d %v", code, out)
	}
	return out, q.Get("code")
}

func TestTheWholeFlow(t *testing.T) {
	r := newRig(t)
	out, code := r.connect(t)
	if out["token_type"] != "Bearer" || out["expires_in"] != float64(3600) || out["scope"] != "mcp:read mcp:write" {
		t.Fatalf("%v", out)
	}
	access, _ := out["access_token"].(string)
	g, ok := r.toks.issued[access]
	if !ok || g.Principal != "dana" || g.Client != appID || g.Resource != "https://admin.example.org/mcp" || !g.Vouched {
		t.Fatalf("issued %+v", g)
	}
	grants, _ := r.Store.Grants()
	if len(grants) != 1 || grants[0].Refresh == "" || strings.Contains(grants[0].Refresh, "qzrt_") {
		t.Fatalf("grants %+v", grants)
	}
	// The code is used once; a second use ends what the first got.
	status, _ := r.post(t, r.Token, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {appID}, "redirect_uri": {"https://app.example.com/callback"}, "code_verifier": {strings.Repeat("v", 50)}})
	if status != 400 || !r.toks.revoked[grants[0].ID] {
		t.Fatalf("second redemption: %d, revoked %v", status, r.toks.revoked)
	}
	// Refreshing a grant that ended is refused.
	if status, _ := r.post(t, r.Token, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {out["refresh_token"].(string)}, "client_id": {appID}}); status != 400 {
		t.Fatal("refreshed an ended grant")
	}
	if strings.Join(r.records, ",") != "oauth.consent,oauth.connected,oauth.disconnected" {
		t.Fatalf("records %v", r.records)
	}
}

func TestRefreshRotatesAndACopyEndsTheGrant(t *testing.T) {
	r := newRig(t)
	out, _ := r.connect(t)
	first := out["refresh_token"].(string)
	refresh := func(tok string, extra url.Values) (int, map[string]any) {
		f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {appID}}
		for k, v := range extra {
			f[k] = v
		}
		return r.post(t, r.Token, f)
	}
	status, next := refresh(first, nil)
	if status != 200 || next["refresh_token"] == first || next["access_token"] == out["access_token"] {
		t.Fatalf("refresh: %d %v", status, next)
	}
	// Narrower is allowed; wider needs the person.
	if status, got := refresh(next["refresh_token"].(string), url.Values{"scope": {"mcp:read"}}); status != 200 || got["scope"] != "mcp:read" {
		t.Fatalf("narrowing: %d %v", status, got)
	} else {
		next = got
	}
	if status, _ := refresh(next["refresh_token"].(string), url.Values{"scope": {"mcp:write"}}); status != 400 {
		t.Fatal("a refresh widened the scope")
	}
	// Another app cannot use it.
	if status, _ := r.post(t, r.Token, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {next["refresh_token"].(string)}, "client_id": {"https://evil.example/c.json"}}); status != 400 {
		t.Fatal("another app refreshed")
	}
	// The first refresh token, used again: a copy. The grant ends.
	if status, _ := refresh(first, nil); status != 400 {
		t.Fatal("a spent refresh token worked")
	}
	grants, _ := r.Store.Grants()
	if grants[0].Ended.IsZero() || !r.toks.revoked[grants[0].ID] {
		t.Fatal("a reused refresh token left the grant in force")
	}
	if status, _ := refresh(next["refresh_token"].(string), nil); status != 400 {
		t.Fatal("the current refresh token still worked after a copy was seen")
	}
}

func TestTheCodeIsBoundToEverythingItWasIssuedFor(t *testing.T) {
	cases := map[string]func(url.Values){
		"wrong verifier":   func(f url.Values) { f.Set("code_verifier", strings.Repeat("w", 50)) },
		"short verifier":   func(f url.Values) { f.Set("code_verifier", "abc") },
		"no verifier":      func(f url.Values) { f.Del("code_verifier") },
		"other client":     func(f url.Values) { f.Set("client_id", "https://evil.example/c.json") },
		"other redirect":   func(f url.Values) { f.Set("redirect_uri", "http://127.0.0.1/cb") },
		"other resource":   func(f url.Values) { f.Set("resource", "https://other.example/mcp") },
		"unknown code":     func(f url.Values) { f.Set("code", "qzac_nothing") },
		"no grant type":    func(f url.Values) { f.Del("grant_type") },
		"password grant":   func(f url.Values) { f.Set("grant_type", "password") },
		"client cred.":     func(f url.Values) { f.Set("grant_type", "client_credentials") },
		"duplicate params": func(f url.Values) { f["code"] = append(f["code"], "x") },
	}
	for name, mutate := range cases {
		r := newRig(t)
		verifier, challenge := pkce()
		req, _ := r.Parse(context.Background(), authQuery(challenge))
		p, _ := r.Hold(req, "dana")
		p, _ = r.Take(p.ID, "dana")
		to, _ := r.Approve(p, req.Scopes, false)
		u, _ := url.Parse(to)
		f := url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")},
			"client_id": {appID}, "redirect_uri": {"https://app.example.com/callback"}, "code_verifier": {verifier}}
		mutate(f)
		if status, out := r.post(t, r.Token, f); status == 200 {
			t.Errorf("%s: tokens issued %v", name, out)
		}
		if len(r.toks.issued) != 0 {
			t.Errorf("%s: a token was issued", name)
		}
	}
}

func TestAnExpiredCode(t *testing.T) {
	r := newRig(t)
	verifier, challenge := pkce()
	req, _ := r.Parse(context.Background(), authQuery(challenge))
	p, _ := r.Hold(req, "dana")
	p, _ = r.Take(p.ID, "dana")
	to, _ := r.Approve(p, req.Scopes, false)
	u, _ := url.Parse(to)
	r.clock = r.clock.Add(2 * time.Minute)
	if status, _ := r.post(t, r.Token, url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")},
		"client_id": {appID}, "redirect_uri": {"https://app.example.com/callback"}, "code_verifier": {verifier}}); status != 400 {
		t.Fatal("an expired code was redeemed")
	}
}

func TestTheTokenEndpointRefusesTheWrongShapes(t *testing.T) {
	r := newRig(t)
	for name, build := range map[string]func() *http.Request{
		"GET": func() *http.Request { return httptest.NewRequest("GET", "/oauth/token", nil) },
		"JSON": func() *http.Request {
			q := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(`{}`))
			q.Header.Set("Content-Type", "application/json")
			return q
		},
		"secret": func() *http.Request {
			q := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=refresh_token"))
			q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			q.SetBasicAuth("a", "b")
			return q
		},
		"query": func() *http.Request {
			q := httptest.NewRequest("POST", "/oauth/token?code=x", strings.NewReader("grant_type=authorization_code"))
			q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return q
		},
	} {
		w := httptest.NewRecorder()
		r.Token(w, build())
		if w.Code == 200 {
			t.Errorf("%s: 200", name)
		}
	}
}

func TestAuthorizationRequestsAreChecked(t *testing.T) {
	_, challenge := pkce()
	// Shown to the person: nothing may be sent to an address not proven.
	shown := map[string]func(url.Values){
		"no client":           func(q url.Values) { q.Del("client_id") },
		"unknown registered":  func(q url.Values) { q.Set("client_id", "qzc_nothing") },
		"host not allowed":    func(q url.Values) { q.Set("client_id", "https://evil.example/client.json") },
		"http client id":      func(q url.Values) { q.Set("client_id", "http://app.example.com/client.json") },
		"redirect not listed": func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"redirect prefix":     func(q url.Values) { q.Set("redirect_uri", "https://app.example.com/callback/x") },
		"no redirect":         func(q url.Values) { q.Del("redirect_uri") },
		"two clients":         func(q url.Values) { q.Add("client_id", appID) },
	}
	for name, mutate := range shown {
		r := newRig(t)
		q := authQuery(challenge)
		mutate(q)
		_, err := r.Parse(context.Background(), q)
		var re *RedirectError
		if err == nil || errors.As(err, &re) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Sent back to the app at its proven address.
	sent := map[string]struct {
		mutate func(url.Values)
		code   string
	}{
		"token flow":       {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"plain pkce":       {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"no pkce":          {func(q url.Values) { q.Del("code_challenge") }, "invalid_request"},
		"short challenge":  {func(q url.Values) { q.Set("code_challenge", "abc") }, "invalid_request"},
		"no resource":      {func(q url.Values) { q.Del("resource") }, "invalid_target"},
		"other resource":   {func(q url.Values) { q.Set("resource", "https://admin.example.org/api") }, "invalid_target"},
		"unknown scope":    {func(q url.Values) { q.Set("scope", "mcp:read files:delete") }, "invalid_scope"},
		"offline":          {func(q url.Values) { q.Set("scope", "offline_access") }, "invalid_scope"},
		"long state":       {func(q url.Values) { q.Set("state", strings.Repeat("s", 513)) }, "invalid_request"},
		"resource w/ frag": {func(q url.Values) { q.Set("resource", "https://admin.example.org/mcp#x") }, "invalid_target"},
	}
	for name, c := range sent {
		r := newRig(t)
		q := authQuery(challenge)
		c.mutate(q)
		_, err := r.Parse(context.Background(), q)
		var re *RedirectError
		if !errors.As(err, &re) || re.Code != c.code || re.Redirect != "https://app.example.com/callback" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// What is accepted.
	ok := map[string]func(url.Values){
		"capital host resource": func(q url.Values) { q.Set("resource", "HTTPS://Admin.Example.Org/mcp/") },
		"no scope":              func(q url.Values) { q.Del("scope") },
		"loopback any port":     func(q url.Values) { q.Set("redirect_uri", "http://127.0.0.1:53124/cb") },
		"no state":              func(q url.Values) { q.Del("state") },
	}
	for name, mutate := range ok {
		r := newRig(t)
		q := authQuery(challenge)
		mutate(q)
		if req, err := r.Parse(context.Background(), q); err != nil || len(req.Scopes) == 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAHeldRequestIsForOnePersonOnce(t *testing.T) {
	r := newRig(t)
	_, challenge := pkce()
	req, _ := r.Parse(context.Background(), authQuery(challenge))
	p, _ := r.Hold(req, "dana")
	if _, err := r.Take(p.ID, "sam"); err == nil {
		t.Fatal("somebody else took dana's request")
	}
	if _, err := r.Take(p.ID, "dana"); err == nil {
		t.Fatal("the request survived being shown to somebody else")
	}
	p, _ = r.Hold(req, "dana")
	r.clock = r.clock.Add(11 * time.Minute)
	if _, err := r.Take(p.ID, "dana"); err == nil {
		t.Fatal("an expired request was taken")
	}
	p, _ = r.Hold(req, "dana")
	if to := r.Deny(p); !strings.Contains(to, "error=access_denied") || !strings.Contains(to, "iss=https") || !strings.HasPrefix(to, "https://app.example.com/callback?") {
		t.Fatalf("deny %s", to)
	}
}

func TestMetadataDocumentsAreReadCarefully(t *testing.T) {
	good := `{"client_id":"` + appID + `","client_name":"App","redirect_uris":["https://app.example.com/cb"]}`
	if c, err := ParseDocument(appID, []byte(good)); err != nil || c.Name != "App" {
		t.Fatalf("%v %v", c, err)
	}
	bad := map[string]string{
		"other id":     `{"client_id":"https://evil.example/c.json","client_name":"App","redirect_uris":["https://a.example/cb"]}`,
		"secret":       `{"client_id":"` + appID + `","client_name":"App","client_secret":"s","redirect_uris":["https://a.example/cb"]}`,
		"secret auth":  `{"client_id":"` + appID + `","client_name":"App","token_endpoint_auth_method":"client_secret_basic","redirect_uris":["https://a.example/cb"]}`,
		"jwt auth":     `{"client_id":"` + appID + `","client_name":"App","token_endpoint_auth_method":"private_key_jwt","redirect_uris":["https://a.example/cb"]}`,
		"no name":      `{"client_id":"` + appID + `","redirect_uris":["https://a.example/cb"]}`,
		"rtl name":     `{"client_id":"` + appID + `","client_name":"App‮evil","redirect_uris":["https://a.example/cb"]}`,
		"long name":    `{"client_id":"` + appID + `","client_name":"` + strings.Repeat("a", 101) + `","redirect_uris":["https://a.example/cb"]}`,
		"no redirects": `{"client_id":"` + appID + `","client_name":"App","redirect_uris":[]}`,
		"http remote":  `{"client_id":"` + appID + `","client_name":"App","redirect_uris":["http://a.example/cb"]}`,
		"custom":       `{"client_id":"` + appID + `","client_name":"App","redirect_uris":["javascript:alert(1)"]}`,
		"implicit":     `{"client_id":"` + appID + `","client_name":"App","redirect_uris":["https://a.example/cb"],"response_types":["token"]}`,
		"password":     `{"client_id":"` + appID + `","client_name":"App","redirect_uris":["https://a.example/cb"],"grant_types":["password"]}`,
		"two objects":  good + good,
		"too big":      `{"client_id":"` + appID + `","client_name":"App","redirect_uris":["https://a.example/cb"],"x":"` + strings.Repeat("a", 6000) + `"}`,
	}
	for name, doc := range bad {
		if _, err := ParseDocument(appID, []byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	urls := map[string]bool{
		"https://app.example.com/c.json":      true,
		"https://app.example.com:8443/c.json": true,
		"https://app.example.com/":            false,
		"https://app.example.com":             false,
		"https://u@app.example.com/c.json":    false,
		"https://app.example.com/c.json#f":    false,
		"https://app.example.com/c.json?x=1":  false,
		"https://app.example.com/a/../c.json": false,
		"https://app.example.com/./c.json":    false,
		"http://app.example.com/c.json":       false,
	}
	for u, want := range urls {
		if _, err := CheckMetadataURL(u); (err == nil) != want {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestDocumentsAreCachedButNotErrors(t *testing.T) {
	r := newRig(t)
	cfg := r.Config()
	for i := 0; i < 3; i++ {
		if _, err := r.Directory.Resolve(context.Background(), cfg, appID, r.clock); err != nil {
			t.Fatal(err)
		}
	}
	if r.fetched != 1 {
		t.Fatalf("fetched %d times", r.fetched)
	}
	r.clock = r.clock.Add(2 * time.Hour)
	r.Directory.Resolve(context.Background(), cfg, appID, r.clock)
	if r.fetched != 2 {
		t.Fatal("kept past its age")
	}
	cfg.Hosts = []string{"app.example.com", "other.example"}
	for i := 0; i < 2; i++ {
		r.Directory.Resolve(context.Background(), cfg, "https://other.example/c.json", r.clock)
	}
	if r.fetched != 4 {
		t.Fatalf("an error was cached: %d", r.fetched)
	}
	// No host allowed: nothing is fetched at all.
	cfg.Hosts = nil
	before := r.fetched
	_, err := r.Directory.Resolve(context.Background(), cfg, "https://new.example/c.json", r.clock)
	var na *NotAllowed
	if !errors.As(err, &na) || na.Host != "new.example" || r.fetched != before {
		t.Fatalf("%v", err)
	}
}

func TestRegisteredApps(t *testing.T) {
	r := newRig(t)
	c, err := NewRegistered("Build bot", []string{"http://localhost/cb"}, "sam", r.clock)
	if err != nil || !strings.HasPrefix(c.ID, "qzc_") {
		t.Fatal(c, err)
	}
	r.Store.ChangeClients(func(cs *[]Client, _ *[]string) error { *cs = append(*cs, c); return nil })
	_, challenge := pkce()
	q := authQuery(challenge)
	q.Set("client_id", c.ID)
	q.Set("redirect_uri", "http://localhost:4000/cb")
	if _, err := r.Parse(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{nil, {"ftp://x/cb"}, {"http://example.com/cb"}} {
		if _, err := NewRegistered("x", bad, "sam", r.clock); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, err := NewRegistered("two\nlines", []string{"https://a.example/cb"}, "sam", r.clock); err == nil {
		t.Error("a two-line name")
	}
}

func TestScopesAndRoles(t *testing.T) {
	if RoleFor([]string{"mcp:read", "mcp:publish"}) != auth.RolePublisher || RoleFor(nil) != auth.RoleNone {
		t.Fatal("RoleFor")
	}
	if ScopeFor(auth.RoleAuthor) != "mcp:write" || ScopeFor(auth.RoleAdmin) != "mcp:admin" {
		t.Fatal("ScopeFor")
	}
	if strings.Join(Within(auth.RoleAuthor), " ") != "mcp:read mcp:write" {
		t.Fatal(Within(auth.RoleAuthor))
	}
}

func TestIssuers(t *testing.T) {
	for issuer, ok := range map[string]bool{
		"https://admin.example.com":      true,
		"https://admin.example.com:8443": true,
		"http://127.0.0.1:8080":          true,
		"http://localhost:8080":          true,
		"http://admin.example.com":       false,
		"https://admin.example.com/":     false,
		"https://admin.example.com/x":    false,
		"https://Admin.example.com":      false,
		"https://u:p@admin.example.com":  false,
		"ftp://admin.example.com":        false,
	} {
		if err := CheckIssuer(issuer); (err == nil) != ok {
			t.Errorf("%s: %v", issuer, err)
		}
	}
	cfg := Config{Issuer: "https://a.example"}
	if cfg.Resource() != "https://a.example/mcp" || cfg.MetadataURL() != "https://a.example/.well-known/oauth-protected-resource/mcp" {
		t.Fatal(cfg.Resource(), cfg.MetadataURL())
	}
	md := cfg.AuthorizationMetadata("")
	if md["code_challenge_methods_supported"].([]string)[0] != "S256" || md["client_id_metadata_document_supported"] != true ||
		md["authorization_response_iss_parameter_supported"] != true || md["registration_endpoint"] != nil {
		t.Fatalf("%v", md)
	}
	if rm := cfg.ResourceMetadata(""); rm["resource"] != "https://a.example/mcp" || rm["authorization_servers"].([]string)[0] != "https://a.example" {
		t.Fatalf("%v", rm)
	}
}

func TestLockdownStopsTokens(t *testing.T) {
	r := newRig(t)
	out, _ := r.connect(t)
	r.Admit = func(g Grant, now time.Time) error { return errors.New("the admin is locked down") }
	if status, _ := r.post(t, r.Token, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {out["refresh_token"].(string)}, "client_id": {appID}}); status != 400 {
		t.Fatal("refreshed through a lockdown")
	}
}

func TestRevocation(t *testing.T) {
	r := newRig(t)
	out, _ := r.connect(t)
	req := func(form url.Values) int {
		q := httptest.NewRequest("POST", "/oauth/revoke", strings.NewReader(form.Encode()))
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.Revoke(w, q)
		return w.Code
	}
	// Another app's revocation, or a wrong token, changes nothing and says nothing.
	if req(url.Values{"token": {out["refresh_token"].(string)}, "client_id": {"https://evil.example/c.json"}}) != 200 ||
		req(url.Values{"token": {"nonsense"}, "client_id": {appID}}) != 200 {
		t.Fatal("not 200")
	}
	grants, _ := r.Store.Grants()
	if !grants[0].Ended.IsZero() {
		t.Fatal("ended by another app")
	}
	req(url.Values{"token": {out["refresh_token"].(string)}, "client_id": {appID}})
	grants, _ = r.Store.Grants()
	if grants[0].Ended.IsZero() || !r.toks.revoked[grants[0].ID] {
		t.Fatal("not ended")
	}
	if err := r.End(grants[0].ID, "sam", "x"); err == nil {
		t.Fatal("ended twice")
	}
}

func TestANewConsentReplacesTheOld(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.connect(t)
	grants, _ := r.Store.Grants()
	live := 0
	for _, g := range grants {
		if g.Live(r.clock) {
			live++
		}
	}
	if len(grants) != 2 || live != 1 || !r.toks.revoked[grants[0].ID] {
		t.Fatalf("grants %d live %d", len(grants), live)
	}
	// A month after it ended, it is forgotten.
	r.clock = r.clock.Add(31 * 24 * time.Hour)
	r.Store.changeGrants(r.clock, func(*grantsFile) error { return nil })
	grants, _ = r.Store.Grants()
	if len(grants) != 1 {
		t.Fatalf("kept %d", len(grants))
	}
}

// The shape checks hold even on a request that is otherwise perfect.
func TestAValidRequestInTheWrongShapeIsStillRefused(t *testing.T) {
	r := newRig(t)
	out, _ := r.connect(t)
	send := func(target string, decorate func(*http.Request)) int {
		body := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {out["refresh_token"].(string)}, "client_id": {appID}}
		q := httptest.NewRequest("POST", target, strings.NewReader(body.Encode()))
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if decorate != nil {
			decorate(q)
		}
		w := httptest.NewRecorder()
		r.Token(w, q)
		return w.Code
	}
	if code := send("/oauth/token", func(q *http.Request) { q.SetBasicAuth(appID, "secret") }); code != http.StatusUnauthorized {
		t.Fatalf("a client presenting a secret: %d", code)
	}
	if code := send("/oauth/token?client_id=x", nil); code != http.StatusBadRequest {
		t.Fatalf("parameters in the address: %d", code)
	}
	// And the same request, in the right shape, works: the refusals above
	// were the shape, not the token.
	if code := send("/oauth/token", nil); code != http.StatusOK {
		t.Fatalf("the plain request: %d", code)
	}
}

func TestRedirectMatching(t *testing.T) {
	reg := []string{"http://127.0.0.1/cb", "https://app.example.com/callback"}
	for req, want := range map[string]bool{
		"https://app.example.com/callback":      true,
		"http://127.0.0.1/cb":                   true,
		"http://127.0.0.1:53124/cb":             true,
		"http://127.0.0.1:53124/other":          false,
		"http://127.0.0.1:53124/cb?x=1":         false,
		"https://127.0.0.1:443/cb":              false,
		"http://localhost:53124/cb":             false,
		"https://app.example.com:8443/callback": false,
		"https://app.example.com/callback/":     false,
		"http://app.example.com/callback":       false,
	} {
		if got := RedirectMatches(reg, req); got != want {
			t.Errorf("%s: %v, want %v", req, got, want)
		}
	}
}
