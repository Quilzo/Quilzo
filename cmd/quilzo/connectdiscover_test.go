// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
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

// The scopes a discovery asks for are read wherever --scope stands on the
// line, and a scope left outside the quotes is refused, not dropped.
//
// Two branches met at this command. One gave it --scope, whose value is
// several scopes separated by spaces; the other has every command refuse a
// word it does not take, because the flag package stops at the first one
// and what followed was thrown away. Parsed the old way, `--scope mcp:read
// mcp:write` set up a connection that asked for mcp:read alone and said it
// had worked, which is the connection every write is refused on, and the
// flag written before the names found no names at all.
func TestDiscoverReadsItsScopesWhereverTheyStandAndDropsNone(t *testing.T) {
	root := keyedDemo(t)
	setConfigs(t, root, map[string]string{"admin.base_url": "https://cms.example"})
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
	discoverPost = func(context.Context, string, []byte) (int, []byte, error) { return 500, nil, nil }

	// Left unquoted, the second scope is a word the command does not take:
	// one word more than the two names, whichever of them is the third.
	// Nothing is set up, and the refusal says how the line was meant.
	for _, line := range [][]string{
		{"provider", "discover", "hub", "https://hub.example/mcp", "--scope", "mcp:read", "mcp:write"},
		{"provider", "discover", "--scope", "mcp:read", "mcp:write", "hub", "https://hub.example/mcp"},
		{"provider", "discover", "hub", "https://hub.example/mcp", "mcp:write"},
	} {
		err := cmdConnect(root, line)
		var misused errMisused
		if !errors.As(err, &misused) || !strings.Contains(err.Error(), "does not take") {
			t.Errorf("%v: %v", line, err)
		}
		if set, _ := loadConnectProviders(root); len(set.Providers) != 0 {
			t.Fatalf("%v set up %+v", line, set.Providers)
		}
	}
	err := cmdConnect(root, []string{"provider", "discover", "hub", "https://hub.example/mcp", "--scope", "mcp:read", "mcp:write"})
	if err == nil || !strings.Contains(err.Error(), `--scope "mcp:read mcp:write"`) {
		t.Errorf("the refusal does not say how the scopes are written: %v", err)
	}

	// Before the names or after them, the scopes asked for are the ones kept.
	for _, line := range [][]string{
		{"provider", "discover", "--scope", "mcp:read mcp:write", "hub", "https://hub.example/mcp"},
		{"provider", "discover", "hub", "--scope=mcp:read mcp:write", "https://hub.example/mcp"},
		{"provider", "discover", "hub", "https://hub.example/mcp", "--scope", "mcp:read mcp:write"},
	} {
		if err := cmdConnect(root, line); err != nil {
			t.Fatalf("%v: %v", line, err)
		}
		set, err := loadConnectProviders(root)
		if err != nil {
			t.Fatal(err)
		}
		if p, _ := set.get("hub"); strings.Join(p.Scopes, " ") != "mcp:read mcp:write" {
			t.Errorf("%v asks for %v", line, p.Scopes)
		}
		if err := cmdConnect(root, []string{"provider", "remove", "hub"}); err != nil {
			t.Fatal(err)
		}
	}
}

// Discovery by this installation's metadata document is refused where the
// document could not be one: an admin at http on this machine, which is
// the one address an admin may have that is not https, has no address a
// server may read a client's document from.
//
// It was set up all the same, with the http address as the client id, and
// said so as if it had worked. The other server refuses a client id that
// is not https, and this admin serves no document it cannot make, so the
// person found out at the other side's sign-in page, from its words.
// Registering, the other way in, has always refused such a redirect here.
func TestAMetadataDocumentNobodyCouldReadIsNotAClientID(t *testing.T) {
	root := keyedDemo(t)
	setConfigs(t, root, map[string]string{"admin.base_url": "http://localhost:8080", "site.name": "Hart's"})
	pages := map[string]string{
		"https://hub.example/.well-known/oauth-protected-resource/mcp": `{"resource":"https://hub.example/mcp",
			"authorization_servers":["https://hub.example"],"scopes_supported":["mcp:read"]}`,
		"https://hub.example/.well-known/oauth-authorization-server": `{"issuer":"https://hub.example",
			"authorization_endpoint":"https://hub.example/oauth/authorize","token_endpoint":"https://hub.example/oauth/token",
			"client_id_metadata_document_supported":true,"code_challenge_methods_supported":["S256"]}`,
	}
	wasGet := discoverGet
	defer func() { discoverGet = wasGet }()
	discoverGet = func(_ context.Context, u string) (int, http.Header, []byte, error) {
		if b, ok := pages[u]; ok {
			return 200, http.Header{}, []byte(b), nil
		}
		return 404, http.Header{}, nil, nil
	}
	err := cmdConnect(root, []string{"provider", "discover", "hub", "https://hub.example/mcp"})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("set up with a document at an http address: %v", err)
	}
	set, lerr := loadConnectProviders(root)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if _, ok := set.get("hub"); ok {
		t.Fatal("the provider was kept")
	}
}
