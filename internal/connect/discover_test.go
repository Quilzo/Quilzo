// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeWeb answers addresses from a table.
func fakeWeb(pages map[string]string, challenge string) Getter {
	return func(_ context.Context, u string) (int, http.Header, []byte, error) {
		if u == "https://mcp.tracker.example/mcp" {
			h := http.Header{}
			if challenge != "" {
				h.Set("WWW-Authenticate", `Bearer resource_metadata="`+challenge+`"`)
			}
			return 401, h, nil, nil
		}
		if b, ok := pages[u]; ok {
			return 200, http.Header{}, []byte(b), nil
		}
		return 404, http.Header{}, nil, nil
	}
}

var trackerPRM = `{"resource":"https://mcp.tracker.example/mcp","authorization_servers":["https://auth.tracker.example"],"scopes_supported":["issues:read","issues:write"]}`
var trackerAS = `{"issuer":"https://auth.tracker.example","authorization_endpoint":"https://auth.tracker.example/authorize",
"token_endpoint":"https://auth.tracker.example/token","registration_endpoint":"https://auth.tracker.example/register",
"revocation_endpoint":"https://auth.tracker.example/revoke","code_challenge_methods_supported":["S256"]}`

// A server's authorization is discovered from what it publishes, by its
// challenge or the well-known address; a provider made from it sends the
// resource indicator with every request, and its tokens go to that server
// only.
func TestARemoteServersAuthorizationIsDiscovered(t *testing.T) {
	pages := map[string]string{
		"https://mcp.tracker.example/.well-known/oauth-protected-resource/mcp": trackerPRM,
		"https://auth.tracker.example/.well-known/oauth-authorization-server":  trackerAS,
	}
	for _, challenge := range []string{"", "https://mcp.tracker.example/.well-known/oauth-protected-resource/mcp"} {
		d, err := Discover(context.Background(), fakeWeb(pages, challenge), "https://mcp.tracker.example/mcp")
		if err != nil {
			t.Fatal(err)
		}
		if d.TokenURL != "https://auth.tracker.example/token" || d.RegisterURL == "" || len(d.Scopes) != 2 {
			t.Fatalf("%+v", d)
		}
	}
	d, _ := Discover(context.Background(), fakeWeb(pages, ""), "https://mcp.tracker.example/mcp")
	p, err := FromDiscovered("tracker", "Tracker", "client-123", d)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allows("mcp.tracker.example") || p.Allows("auth.tracker.example") || p.Resource != "https://mcp.tracker.example/mcp" {
		t.Fatalf("%+v", p)
	}
	_, to, err := Begin(p, "https://admin.shop.example/connections/callback", "dana", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := url.Parse(to); u.Query().Get("resource") != "https://mcp.tracker.example/mcp" {
		t.Fatalf("no resource on the authorization request: %s", to)
	}
	var form url.Values
	post := func(_ context.Context, _ string, f url.Values) ([]byte, error) {
		form = f
		return []byte(`{"access_token":"t","token_type":"Bearer"}`), nil
	}
	if _, err := Refresh(context.Background(), post, p, "", "r", time.Now()); err != nil || form.Get("resource") != p.Resource {
		t.Fatalf("no resource on the token request: %v %v", form, err)
	}
}

// What does not hold together is refused: metadata for another server, an
// authorization server that is somebody else, no PKCE, an address not
// https.
func TestADiscoveryThatDoesNotHoldIsRefused(t *testing.T) {
	base := map[string]string{
		"https://mcp.tracker.example/.well-known/oauth-protected-resource/mcp": trackerPRM,
		"https://auth.tracker.example/.well-known/oauth-authorization-server":  trackerAS,
	}
	cases := map[string]func(map[string]string){
		"another resource": func(m map[string]string) {
			m["https://mcp.tracker.example/.well-known/oauth-protected-resource/mcp"] = strings.Replace(trackerPRM, "mcp.tracker", "mcp.other", 1)
		},
		"another issuer": func(m map[string]string) {
			m["https://auth.tracker.example/.well-known/oauth-authorization-server"] = strings.Replace(trackerAS, `"issuer":"https://auth.tracker.example"`, `"issuer":"https://evil.example"`, 1)
		},
		"no pkce": func(m map[string]string) {
			m["https://auth.tracker.example/.well-known/oauth-authorization-server"] = strings.Replace(trackerAS, `"S256"`, `"plain"`, 1)
		},
		"http token endpoint": func(m map[string]string) {
			m["https://auth.tracker.example/.well-known/oauth-authorization-server"] = strings.Replace(trackerAS, "https://auth.tracker.example/token", "http://auth.tracker.example/token", 1)
		},
	}
	for name, change := range cases {
		pages := map[string]string{}
		for k, v := range base {
			pages[k] = v
		}
		change(pages)
		if _, err := Discover(context.Background(), fakeWeb(pages, ""), "https://mcp.tracker.example/mcp"); err == nil {
			t.Errorf("%s: discovered", name)
		}
	}
	if _, err := Discover(context.Background(), fakeWeb(base, ""), "http://mcp.tracker.example/mcp"); err == nil {
		t.Error("an http server")
	}
	if _, err := Discover(context.Background(), fakeWeb(base, "http://mcp.tracker.example/meta"), "https://mcp.tracker.example/mcp"); err == nil {
		t.Error("metadata at an http address")
	}
}

// Registration asks for a public client and takes its id; a server that
// sends back a secret is refused.
func TestRegisteringIsAsAPublicClient(t *testing.T) {
	d := Discovered{RegisterURL: "https://auth.tracker.example/register", Scopes: []string{"issues:read"}}
	var asked map[string]any
	post := func(answer string) JSONPoster {
		return func(_ context.Context, _ string, body []byte) (int, []byte, error) {
			_ = json.Unmarshal(body, &asked)
			return 201, []byte(answer), nil
		}
	}
	id, err := Register(context.Background(), post(`{"client_id":"abc"}`), d, "Quilzo", "https://admin.shop.example/connections/callback")
	if err != nil || id != "abc" || asked["token_endpoint_auth_method"] != "none" {
		t.Fatalf("%q %v %v", id, err, asked)
	}
	if _, err := Register(context.Background(), post(`{"client_id":"abc","client_secret":"s"}`), d, "Quilzo",
		"https://admin.shop.example/connections/callback"); err == nil {
		t.Error("a confidential client taken")
	}
	failing := func(context.Context, string, []byte) (int, []byte, error) { return 0, nil, errors.New("down") }
	if _, err := Register(context.Background(), failing, d, "Quilzo", "https://admin.shop.example/connections/callback"); err == nil {
		t.Error("a failed registration")
	}
	if _, err := Register(context.Background(), post(`{}`), Discovered{}, "Quilzo", "https://x.example/cb"); err == nil {
		t.Error("registered where nothing takes registrations")
	}
}
