// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a2a"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/oauthas"
)

const testApp = "https://app.example.com/client.json"

type ifaceRig struct {
	srv   *Server
	token string // the editor's, an administrator
	on    bool
	oauth bool
	hosts []string
}

type rigTokens struct{ srv *Server }

func (t rigTokens) Issue(g oauthas.Grant, role auth.Role, ttl time.Duration, now time.Time) (string, error) {
	s, _, err := t.srv.Tokens.IssueForGrant(g.Principal, role, auth.Scope{}, g.Client, g.ID, g.Resource, ttl, now)
	return s, err
}

func (t rigTokens) RevokeGrant(id string) error { t.srv.Tokens.RevokeGrant(id); return nil }

func newIfaceRig(t *testing.T) *ifaceRig {
	t.Helper()
	srv, token := emptyStore(t)
	r := &ifaceRig{srv: srv, token: token, on: true, oauth: true, hosts: []string{"app.example.com"}}
	cfg := func() oauthas.Config {
		return oauthas.Config{Issuer: "https://admin.example.org", Hosts: r.hosts}
	}
	store := &oauthas.Store{Dir: t.TempDir()}
	oa := &oauthas.Server{Config: cfg, Store: store,
		Directory: &oauthas.Directory{
			Registered: func() ([]oauthas.Client, error) { c, _, err := store.Clients(); return c, err },
			Fetch: func(ctx context.Context, u string) ([]byte, time.Duration, error) {
				return []byte(`{"client_id":"` + u + `","client_name":"Example Assistant","redirect_uris":["https://app.example.com/cb"]}`), time.Hour, nil
			}},
		Tokens: rigTokens{srv: srv},
	}
	srv.Interface = &AgentInterface{
		Enabled: func() bool { return r.on },
		Config:  func() (oauthas.Config, bool) { return cfg(), r.oauth },
		OAuth:   oa,
		Build: func(req *http.Request, c *mcp.Caller) (*mcp.Server, error) {
			s := mcp.NewServer("quilzo", "test")
			s.Authorise = func(mcp.Operation) error { return nil }
			s.Register(mcp.Operation{Name: "whoami", NeedsRole: "reader", Summary: "who"},
				func(map[string]any) (any, error) { return "you are " + c.Principal, nil })
			return s, nil
		},
	}
	return r
}

func (r *ifaceRig) do(t *testing.T, method, path, bearer string, body url.Values, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(w, req)
	return w
}

func (r *ifaceRig) mcpCall(t *testing.T, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"quilzo_read","arguments":{"operation":"whoami"},` +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "quilzo_read")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(w, req)
	return w
}

func authorizeURL(challenge string) string {
	return "/oauth/authorize?" + url.Values{
		"client_id": {testApp}, "redirect_uri": {"https://app.example.com/cb"}, "response_type": {"code"},
		"state": {"s1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"resource": {"https://admin.example.org/mcp"}, "scope": {"mcp:read"},
	}.Encode()
}

var reRequest = regexp.MustCompile(`name="request" value="([^"]+)"`)
var reCode = regexp.MustCompile(`code=([A-Za-z0-9_-]+)`)

// connect runs the consent and the token exchange, as an app and a person.
func (r *ifaceRig) connect(t *testing.T) map[string]any {
	t.Helper()
	verifier := strings.Repeat("k", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	w := r.do(t, "GET", authorizeURL(challenge), r.token, nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Example Assistant") || !strings.Contains(w.Body.String(), "app.example.com") {
		t.Fatalf("consent: %d %s", w.Code, w.Body.String())
	}
	m := reRequest.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatal("no request on the consent page")
	}
	w = r.do(t, "POST", "/oauth/authorize", r.token,
		url.Values{"request": {m[1]}, "decision": {"allow"}, "scope": {"mcp:read"}},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Fatalf("onward: %d %s", w.Code, w.Body.String())
	}
	c := reCode.FindStringSubmatch(w.Body.String())
	if c == nil {
		t.Fatalf("no code in %s", w.Body.String())
	}
	w = r.do(t, "POST", "/oauth/token", "", url.Values{"grant_type": {"authorization_code"}, "code": {c[1]},
		"client_id": {testApp}, "redirect_uri": {"https://app.example.com/cb"}, "code_verifier": {verifier},
		"resource": {"https://admin.example.org/mcp"}}, nil)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 || out["access_token"] == nil {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	return out
}

func TestTheInterfaceIsOffUntilTurnedOn(t *testing.T) {
	r := newIfaceRig(t)
	r.on = false
	for _, p := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/oauth/authorize"} {
		if w := r.do(t, "GET", p, r.token, nil, nil); w.Code != 404 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := r.mcpCall(t, r.token); w.Code != 404 {
		t.Fatalf("/mcp while off: %d", w.Code)
	}
	if w := r.do(t, "POST", "/oauth/token", "", url.Values{"grant_type": {"refresh_token"}}, nil); w.Code != 404 {
		t.Fatalf("/oauth/token while off: %d", w.Code)
	}
}

func TestQuilzoTokensWorkWithoutOAuth(t *testing.T) {
	r := newIfaceRig(t)
	r.oauth = false
	w := r.mcpCall(t, r.token)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "you are editor") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = r.mcpCall(t, "")
	if w.Code != 401 || strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("no OAuth set up, yet it advertised one: %q", w.Header().Get("WWW-Authenticate"))
	}
	if w := r.do(t, "GET", "/.well-known/oauth-protected-resource/mcp", "", nil, nil); w.Code != 404 {
		t.Fatal("metadata without an address")
	}
}

func TestDiscovery(t *testing.T) {
	r := newIfaceRig(t)
	w := r.mcpCall(t, "")
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"),
		`resource_metadata="https://admin.example.org/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("%d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		w := r.do(t, "GET", p, "", nil, nil)
		var doc map[string]any
		json.Unmarshal(w.Body.Bytes(), &doc)
		if w.Code != 200 || doc["resource"] != "https://admin.example.org/mcp" {
			t.Fatalf("%s: %d %v", p, w.Code, doc)
		}
	}
	w = r.do(t, "GET", "/.well-known/oauth-authorization-server", "", nil, nil)
	var as map[string]any
	json.Unmarshal(w.Body.Bytes(), &as)
	if as["issuer"] != "https://admin.example.org" || as["token_endpoint"] != "https://admin.example.org/oauth/token" {
		t.Fatalf("%v", as)
	}
}

func TestAnAppConnectsAndItsTokenWorksOnlyAtTheInterface(t *testing.T) {
	r := newIfaceRig(t)
	out := r.connect(t)
	access := out["access_token"].(string)
	w := r.mcpCall(t, access)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "you are editor") {
		t.Fatalf("the app's token at /mcp: %d %s", w.Code, w.Body.String())
	}
	// Anywhere else it is refused, though it acts for an administrator.
	for _, p := range []string{"/", "/people", "/apps", "/security"} {
		if w := r.do(t, "GET", p, access, nil, nil); w.Code == 200 {
			t.Errorf("the app's token opened %s", p)
		}
	}
	if w := r.do(t, "POST", "/people/grant", access, url.Values{"principal": {"mallory"}, "role": {"admin"}},
		map[string]string{"Sec-Fetch-Site": "same-origin"}); w.Code == 303 || w.Code == 200 {
		t.Fatalf("the app's token granted a role: %d", w.Code)
	}
	// The person sees it, and disconnecting it stops the token at once.
	w = r.do(t, "GET", "/apps", r.token, nil, nil)
	if !strings.Contains(w.Body.String(), "Example Assistant") {
		t.Fatalf("not listed: %s", w.Body.String())
	}
	grants, _ := r.srv.Interface.OAuth.Store.Grants()
	w = r.do(t, "POST", "/apps/act", r.token, url.Values{"action": {"disconnect"}, "grant": {grants[0].ID}},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != 303 {
		t.Fatalf("disconnect: %d", w.Code)
	}
	if w := r.mcpCall(t, access); w.Code != 401 {
		t.Fatalf("a disconnected app's token still worked: %d", w.Code)
	}
}

func TestSomebodyArrivingFromTheAppIsBroughtBackAfterSigningIn(t *testing.T) {
	r := newIfaceRig(t)
	target := authorizeURL(strings.Repeat("A", 43))
	// From the app's site: one hop through a page of this site, which
	// carries a SameSite=Strict session.
	w := r.do(t, "GET", target, "", nil, map[string]string{"Sec-Fetch-Site": "cross-site"})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Fatalf("no bounce: %d", w.Code)
	}
	// Still signed out from this site: the sign-in page, and the way back.
	w = r.do(t, "GET", target, "", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	var next *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == nextCookie {
			next = c
		}
	}
	if w.Code != 401 || next == nil || !next.HttpOnly || next.MaxAge != 600 {
		t.Fatalf("sign-in: %d %v", w.Code, next)
	}
	// Signed in, the front door sends them back to the app's request.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.AddCookie(next)
	rec := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != 303 || rec.Header().Get("Location") != target {
		t.Fatalf("not sent back: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// A cookie pointing anywhere else is ignored.
	for _, p := range []string{"/people", "https://evil.example/", "//evil.example/oauth/authorize?", "/oauth/authorize"} {
		bad := &http.Cookie{Name: nextCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(p))}
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+r.token)
		req.AddCookie(bad)
		rec := httptest.NewRecorder()
		r.srv.Handler().ServeHTTP(rec, req)
		if rec.Code == 303 {
			t.Errorf("%q: redirected to %q", p, rec.Header().Get("Location"))
		}
	}
}

func TestAnAppIsNeverGivenMoreThanThePerson(t *testing.T) {
	r := newIfaceRig(t)
	// A reader.
	if err := r.srv.Policy.Grant(auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	rae, _, err := r.srv.Tokens.Issue("rae", "rae", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	u := strings.Replace(authorizeURL(strings.Repeat("B", 43)), "scope=mcp%3Aread", "scope=mcp%3Aread+mcp%3Awrite", 1)
	w := r.do(t, "GET", u, rae, nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "not offered: you cannot do this yourself") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	id := reRequest.FindStringSubmatch(w.Body.String())[1]
	// Asking for write anyway, by editing the form, gets nothing.
	w = r.do(t, "POST", "/oauth/authorize", rae, url.Values{"request": {id}, "decision": {"allow"}, "scope": {"mcp:write"}},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if !strings.Contains(w.Body.String(), "error=access_denied") {
		t.Fatalf("write granted by a reader: %s", w.Body.String())
	}
	// A token carrying more than the person's role offers no more: what is
	// offered is what the access policy gives them.
	big, _, err := r.srv.Tokens.Issue("rae-big", "rae", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	w = r.do(t, "GET", u, big, nil, nil)
	if !strings.Contains(w.Body.String(), "not offered: you cannot do this yourself") ||
		strings.Contains(w.Body.String(), `value="mcp:write" checked`) {
		t.Fatalf("a token's role widened what a reader could give: %s", w.Body.String())
	}
	// And a request held for one person cannot be finished by another.
	w = r.do(t, "GET", authorizeURL(strings.Repeat("C", 43)), rae, nil, nil)
	id = reRequest.FindStringSubmatch(w.Body.String())[1]
	w = r.do(t, "POST", "/oauth/authorize", r.token, url.Values{"request": {id}, "decision": {"allow"}, "scope": {"mcp:read"}},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != 400 || strings.Contains(w.Body.String(), "code=") {
		t.Fatalf("finished somebody else's request: %d", w.Code)
	}
}

func TestAppsFromHostsNotAllowedCannotAsk(t *testing.T) {
	r := newIfaceRig(t)
	r.hosts = nil
	target := authorizeURL(strings.Repeat("D", 43))
	w := r.do(t, "GET", target, r.token, nil, nil)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "Allow apps from app.example.com") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// The administrator allows the host and is returned to the request.
	w = r.do(t, "POST", "/apps/act", r.token, url.Values{"action": {"allow-host"}, "host": {"app.example.com"}, "return": {target}},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != 303 || w.Header().Get("Location") != target {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Location"))
	}
	_, hosts, _ := r.srv.Interface.OAuth.Store.Clients()
	if len(hosts) != 1 || hosts[0] != "app.example.com" {
		t.Fatalf("%v", hosts)
	}
	// Anywhere else to return to is ignored.
	w = r.do(t, "POST", "/apps/act", r.token, url.Values{"action": {"allow-host"}, "host": {"b.example"}, "return": {"https://evil.example/"}},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/apps?") {
		t.Fatalf("returned to %q", loc)
	}
}

func TestOnlyAnAdministratorDecidesWhatMayConnect(t *testing.T) {
	r := newIfaceRig(t)
	r.srv.Policy.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"})
	rae, _, _ := r.srv.Tokens.Issue("rae", "rae", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	for _, action := range []url.Values{
		{"action": {"allow-host"}, "host": {"evil.example"}},
		{"action": {"register"}, "name": {"x"}, "redirects": {"https://evil.example/cb"}},
	} {
		w := r.do(t, "POST", "/apps/act", rae, action, map[string]string{"Sec-Fetch-Site": "same-origin"})
		if w.Code != 403 {
			t.Errorf("%v: %d", action, w.Code)
		}
	}
	// Somebody else's connection is not theirs to end either.
	r.connect(t)
	grants, _ := r.srv.Interface.OAuth.Store.Grants()
	w := r.do(t, "POST", "/apps/act", rae, url.Values{"action": {"disconnect"}, "grant": {grants[0].ID}},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != 403 {
		t.Fatalf("disconnected the editor's app: %d", w.Code)
	}
	// And a person who is not an administrator sees only their own.
	if w := r.do(t, "GET", "/apps", rae, nil, nil); strings.Contains(w.Body.String(), "Example Assistant") {
		t.Fatal("rae sees the editor's connection")
	}
}

func TestRemovingAHostEndsItsConnections(t *testing.T) {
	r := newIfaceRig(t)
	access := r.connect(t)["access_token"].(string)
	w := r.do(t, "POST", "/apps/act", r.token, url.Values{"action": {"remove-host"}, "host": {"app.example.com"}},
		map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != 303 {
		t.Fatalf("%d", w.Code)
	}
	if w := r.mcpCall(t, access); w.Code != 401 {
		t.Fatalf("still connected: %d", w.Code)
	}
}

func TestTheInterfaceRefusesOtherSitesPagesAndReadOnlyTokensStillRead(t *testing.T) {
	r := newIfaceRig(t)
	ro, _, err := r.srv.Tokens.IssueScoped("ro", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.Scope{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if w := r.mcpCall(t, ro); w.Code != 200 {
		t.Fatalf("a read-only token could not read: %d %s", w.Code, w.Body.String())
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/list")
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("another site's page: %d", w.Code)
	}
}

// A page answering with an error status still lets its own script run.
//
// It did not: a handler wrote the status and then rendered, and the status
// sent the headers before the page could add its script's nonce to the
// policy, so every refusal page logged a blocked script. Found by watching
// the consent page's console in Chromium.
func TestErrorPagesKeepTheirScript(t *testing.T) {
	r := newIfaceRig(t)
	r.srv.Policy.Grant(auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"})
	rae, _, _ := r.srv.Tokens.Issue("rae", "rae", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
	for _, w := range []*httptest.ResponseRecorder{
		r.do(t, "GET", "/integrations", rae, nil, nil),
		r.do(t, "GET", "/oauth/authorize?client_id=x", r.token, nil, nil),
	} {
		if w.Code < 400 {
			t.Fatalf("expected a refusal, got %d", w.Code)
		}
		// The headers as sent: a recorder's own map stays writable after the
		// status is written, which is exactly the mistake being caught.
		csp := w.Result().Header.Get("Content-Security-Policy")
		m := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(csp)
		if m == nil || !strings.Contains(html.UnescapeString(w.Body.String()), `nonce="`+m[1]+`"`) {
			t.Errorf("%d page: policy %q does not allow its script", w.Code, csp)
		}
	}
}

// The person an app acted for takes away the receipt of what it did; an
// administrator can too; nobody else can, and cannot tell it exists.
func TestAConnectionsReceiptIsForThePersonItActedFor(t *testing.T) {
	r := newIfaceRig(t)
	r.connect(t)
	asked := ""
	r.srv.Interface.Receipt = func(id string) ([]byte, error) {
		asked = id
		return []byte(`{"format":"quilzo-app-receipt/1","connection":"` + id + `"}`), nil
	}
	grants, _ := r.srv.Interface.OAuth.Store.Grants()
	id := grants[0].ID
	if w := r.do(t, "GET", "/apps", r.token, nil, nil); !strings.Contains(w.Body.String(), "/apps/receipt?id="+id) {
		t.Fatal("Connected apps does not offer the receipt")
	}
	w := r.do(t, "GET", "/apps/receipt?id="+id, r.token, nil, nil)
	if w.Code != 200 || asked != id || !strings.Contains(w.Header().Get("Content-Disposition"), "receipt-"+id+".json") ||
		w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), id) {
		t.Fatalf("%d %q %v", w.Code, asked, w.Header())
	}
	r.srv.Policy.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"})
	rae, _, _ := r.srv.Tokens.Issue("rae", "rae", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	asked = ""
	for _, q := range []string{id, "gr_00000000000000ff", ""} {
		w := r.do(t, "GET", "/apps/receipt?id="+q, rae, nil, nil)
		if w.Code != 303 || asked != "" || !strings.Contains(w.Header().Get("Location"), "no+connection+of+yours") {
			t.Errorf("%q for rae: %d %q", q, w.Code, w.Header().Get("Location"))
		}
	}
}

func TestHowLongAgoIsSaidInWords(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for ago, want := range map[time.Duration]string{
		30 * time.Second: "just now", time.Minute: "1 minute ago", 5 * time.Minute: "5 minutes ago",
		time.Hour: "1 hour ago", 3 * time.Hour: "3 hours ago", 24 * time.Hour: "1 day ago", 72 * time.Hour: "3 days ago",
	} {
		if got := agoAt(now.Add(-ago).Unix(), now); got != want {
			t.Errorf("%s: %q", ago, got)
		}
	}
	if agoAt(0, now) != "never" {
		t.Error("zero is not never")
	}
}

// The gateway answers only for what is offered, with the interface's own
// tokens, listing and calling the far side's tools directly.
func TestTheGatewayAnswersOnlyForWhatIsOffered(t *testing.T) {
	r := newIfaceRig(t)
	r.oauth = false
	r.srv.Interface.Offered = func(name string) bool { return name == "tracker" }
	r.srv.Interface.Gateway = func(req *http.Request, c *mcp.Caller, name string) (*mcp.Server, error) {
		s := mcp.NewServer("gw", "test")
		s.Direct = &mcp.Direct{Tools: []mcp.Tool{{Name: "create_issue", Description: "File an issue.",
			InputSchema: map[string]any{"type": "object"}}},
			Call: func(tool string, args map[string]any) (string, error) {
				return "filed for " + c.Principal + " on " + name, nil
			}}
		return s, nil
	}
	call := func(path, method, name, bearer string) *httptest.ResponseRecorder {
		params := `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`
		if method == "tools/call" {
			params = `{"name":"` + name + `","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}`
		}
		req := httptest.NewRequest("POST", path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+params+`}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", method)
		if name != "" {
			req.Header.Set("Mcp-Name", name)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		r.srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := call("/mcp/gateway/other", "tools/list", "", r.token); w.Code != 404 {
		t.Fatalf("something not offered answered %d", w.Code)
	}
	if w := call("/mcp/gateway/tracker", "tools/list", "", ""); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := call("/mcp/gateway/tracker", "tools/list", "", r.token); w.Code != 200 || !strings.Contains(w.Body.String(), `"create_issue"`) ||
		strings.Contains(w.Body.String(), "quilzo_find") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := call("/mcp/gateway/tracker", "tools/call", "create_issue", r.token); !strings.Contains(w.Body.String(), "filed for editor on tracker") {
		t.Fatalf("%s", w.Body.String())
	}
	if w := call("/mcp/gateway/tracker", "tools/call", "delete_everything", r.token); !strings.Contains(w.Body.String(), `no tool \"delete_everything\" here`) {
		t.Fatalf("%s", w.Body.String())
	}
	r.on = false
	if w := call("/mcp/gateway/tracker", "tools/list", "", r.token); w.Code != 404 {
		t.Fatalf("with the interface off: %d", w.Code)
	}
}

// Tasks from other agents are taken only when turned on, with the
// interface's own tokens.
func TestTasksAreTakenOnlyWhenTurnedOnWithAToken(t *testing.T) {
	r := newIfaceRig(t)
	r.oauth = false
	tasks := false
	r.srv.Interface.Tasks = func() bool { return tasks }
	r.srv.Interface.A2A = func(c *mcp.Caller) a2a.Host {
		return a2a.Host{Agents: func() []string { return []string{"tidy"} },
			Send: func(_ *http.Request, agent, text string) (a2a.Task, error) {
				return a2a.Task{ID: "t1", Status: a2a.TaskStatus{State: a2a.StateCompleted},
					Metadata: map[string]any{"by": c.Principal, "said": text}}, nil
			}}
	}
	post := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/a2a", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":`+
			`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"tidy up"}]}}}`))
		req.Header.Set("A2A-Version", "1.0")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		r.srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := post(r.token); w.Code != 404 {
		t.Fatalf("tasks off: %d", w.Code)
	}
	tasks = true
	if w := post(""); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := post("not-a-token"); w.Code != 401 {
		t.Fatalf("a bad token: %d", w.Code)
	}
	if w := post(r.token); w.Code != 200 || !strings.Contains(w.Body.String(), `"by":"editor"`) || !strings.Contains(w.Body.String(), `"said":"tidy up"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	r.on = false
	if w := post(r.token); w.Code != 404 {
		t.Fatalf("with the interface off: %d", w.Code)
	}
}
