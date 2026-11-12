// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/oauthas"
)

// A remote MCP server's sign-in is discovered, this installation is
// registered there, and the provider kept sends its tokens to that server
// alone, for that server alone.
func TestARemoteMCPServersSignInIsDiscovered(t *testing.T) {
	root := keyedDemo(t)
	setConfigs(t, root, map[string]string{"admin.base_url": "https://cms.example"})
	pages := map[string]string{
		"https://mcp.tracker.example/.well-known/oauth-protected-resource/mcp": `{"resource":"https://mcp.tracker.example/mcp",
			"authorization_servers":["https://auth.tracker.example"],"scopes_supported":["issues:read"]}`,
		"https://auth.tracker.example/.well-known/oauth-authorization-server": `{"issuer":"https://auth.tracker.example",
			"authorization_endpoint":"https://auth.tracker.example/authorize","token_endpoint":"https://auth.tracker.example/token",
			"registration_endpoint":"https://auth.tracker.example/register","code_challenge_methods_supported":["S256"]}`,
	}
	wasGet, wasPost := discoverGet, discoverPost
	defer func() { discoverGet, discoverPost = wasGet, wasPost }()
	discoverGet = func(_ context.Context, u string) (int, http.Header, []byte, error) {
		if b, ok := pages[u]; ok {
			return 200, http.Header{}, []byte(b), nil
		}
		return 404, http.Header{}, nil, nil
	}
	var registered map[string]any
	discoverPost = func(_ context.Context, _ string, body []byte) (int, []byte, error) {
		_ = json.Unmarshal(body, &registered)
		return 201, []byte(`{"client_id":"quilzo-77"}`), nil
	}
	if err := cmdConnect(root, []string{"provider", "discover", "tracker", "https://mcp.tracker.example/mcp"}); err != nil {
		t.Fatal(err)
	}
	set, err := loadConnectProviders(root)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := set.get("tracker")
	if !ok || p.ClientID != "quilzo-77" || p.Resource != "https://mcp.tracker.example/mcp" || len(p.Hosts) != 1 ||
		p.Hosts[0] != "mcp.tracker.example" || p.Secret != "" {
		t.Fatalf("%+v", p)
	}
	uris, _ := registered["redirect_uris"].([]any)
	if len(uris) != 1 || uris[0] != "https://cms.example/connections/callback" || registered["token_endpoint_auth_method"] != "none" {
		t.Fatalf("%v", registered)
	}
	// With a client id given, nothing is registered.
	registered = nil
	if err := cmdConnect(root, []string{"provider", "discover", "tracker", "https://mcp.tracker.example/mcp", "--client-id", "given"}); err != nil {
		t.Fatal(err)
	}
	set, _ = loadConnectProviders(root)
	if p, _ := set.get("tracker"); p.ClientID != "given" || registered != nil {
		t.Fatalf("%+v %v", p, registered)
	}
}

// Another Quilzo's agent interface is connected by discovery alone: its
// authorization server takes Client ID Metadata Documents and no
// registrations, so this installation's own document, served by its
// admin, is its client id; and the connection asks for the scopes it is
// told to, which another Quilzo's metadata now lists in full.
//
// Discovery stopped at "takes no registrations: give the client id it
// issued", although the server said it takes metadata documents, the one
// way of registering it offers; and with a client id given by hand the
// connection asked for mcp:read alone, which every write was refused.
func TestAnotherQuilzoIsConnectedByItsMetadataDocument(t *testing.T) {
	root := keyedDemo(t)
	setConfigs(t, root, map[string]string{"admin.base_url": "https://cms.example", "site.name": "Hart's"})
	pages := map[string]string{
		"https://hub.example/.well-known/oauth-protected-resource/mcp": `{"resource":"https://hub.example/mcp",
			"authorization_servers":["https://hub.example"],"scopes_supported":["mcp:read","mcp:write","mcp:publish","mcp:admin"]}`,
		"https://hub.example/.well-known/oauth-authorization-server": `{"issuer":"https://hub.example",
			"authorization_endpoint":"https://hub.example/oauth/authorize","token_endpoint":"https://hub.example/oauth/token",
			"client_id_metadata_document_supported":true,"code_challenge_methods_supported":["S256"],
			"scopes_supported":["mcp:read","mcp:write","mcp:publish","mcp:admin"]}`,
	}
	wasGet, wasPost := discoverGet, discoverPost
	defer func() { discoverGet, discoverPost = wasGet, wasPost }()
	discoverGet = func(_ context.Context, u string) (int, http.Header, []byte, error) {
		if b, ok := pages[u]; ok {
			return 200, http.Header{}, []byte(b), nil
		}
		return 404, http.Header{}, nil, nil
	}
	posted := 0
	discoverPost = func(context.Context, string, []byte) (int, []byte, error) { posted++; return 500, nil, nil }
	if err := cmdConnect(root, []string{"provider", "discover", "hub", "https://hub.example/mcp", "--scope", "mcp:read mcp:write"}); err != nil {
		t.Fatal(err)
	}
	set, err := loadConnectProviders(root)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := set.get("hub")
	const doc = "https://cms.example/connections/client.json"
	if p.ClientID != doc || strings.Join(p.Scopes, " ") != "mcp:read mcp:write" || posted != 0 {
		t.Fatalf("%+v, %d registrations", p, posted)
	}
	// The document the admin serves is one this program's own authorization
	// server takes, sending people back to this admin.
	b, err := connectClientDocument(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := oauthas.ParseDocument(doc, b)
	if err != nil || len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://cms.example/connections/callback" ||
		!strings.Contains(c.Name, "Hart's") {
		t.Fatalf("%+v %v\n%s", c, err, b)
	}
	if err := cmdConnect(root, []string{"provider", "discover", "hub", "https://hub.example/mcp", "--scope", "mcp:read bad\"scope"}); err == nil {
		t.Fatal("a scope that is not one was asked for")
	}
}
