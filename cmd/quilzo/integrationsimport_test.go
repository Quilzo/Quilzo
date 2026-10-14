// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/fetch"
)

const billingAPI = `{
  "openapi": "3.0.3",
  "info": {"title": "Billing API"},
  "servers": [{"url": "https://api.billing.example/v1"}],
  "components": {"securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
  "security": [{"key": []}],
  "paths": {
    "/invoices/{id}": {"get": {"operationId": "getInvoice", "summary": "One invoice",
       "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}]}},
    "/invoices": {"post": {"operationId": "createInvoice", "summary": "Raise one"}}
  }
}`

// An OpenAPI document lists what it offers until a person names what this
// install may call; then exactly that is declared, switched off.
func TestAnOpenAPIImportDeclaresOnlyWhatIsNamedSwitchedOff(t *testing.T) {
	root, _ := identityStore(t)
	doc := filepath.Join(t.TempDir(), "billing.json")
	if err := os.WriteFile(doc, []byte(billingAPI), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := integrationsImport(root, []string{doc}); err != nil {
		t.Fatal(err)
	}
	if set, _ := loadIntegrations(root); len(set.Declared) != 0 {
		t.Fatal("listing what is on offer declared something")
	}
	if err := integrationsImport(root, []string{doc, "--uses", "getInvoice", "--secret", "billing-key"}); err != nil {
		t.Fatal(err)
	}
	set, _ := loadIntegrations(root)
	if len(set.Declared) != 1 {
		t.Fatalf("declared %d", len(set.Declared))
	}
	in := set.Declared[0]
	if in.Enabled || in.Kind != agent.IntegrationHTTP || in.Auth != "header:X-API-Key" || len(in.Operations) != 1 || in.Writes {
		t.Errorf("declared %+v", in)
	}
	if err := integrationsImport(root, []string{doc, "--uses", "getInvoice"}); err == nil {
		t.Error("the same name was declared twice")
	}
}

// A REST API offered through the gateway is called by another vendor's
// agent as an MCP tool: only its pinned operations, with Quilzo's key.
func TestTheGatewayOffersARESTAPIsPinnedOperations(t *testing.T) {
	root, pol := identityStore(t)
	if err := pol.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	var sentTo, key string
	restTransport = func(_ context.Context, method, url string, _ []byte, headers map[string]string) (*fetch.Result, error) {
		sentTo, key = method+" "+url, headers["X-API-Key"]
		return &fetch.Result{Status: 200, Body: []byte(`{"id":"7","amount":12}`)}, nil
	}
	t.Cleanup(func() { restTransport = nil })
	t.Setenv("QUILZO_SECRET_BILLING_KEY", "k3y")
	set := agent.Integrations{Declared: []agent.Integration{{Name: "billing", Kind: agent.IntegrationHTTP, Enabled: true,
		Purpose: "read invoices", Endpoint: "api.billing.example", Path: "/v1", Auth: "header:X-API-Key", Secret: "billing-key",
		Uses: []string{"getInvoice"}, Gateway: &agent.GatewayPolicy{Role: "reader"},
		Operations: []agent.Operation{{Name: "getInvoice", Method: "GET", Path: "/invoices/{id}",
			Params: []agent.OperationParam{{Name: "id", In: "path"}}}}}}}
	if err := saveJSON(integrationsPath(root), set); err != nil {
		t.Fatal(err)
	}
	// Not pinned: not offered.
	srv, err := gatewayServer(httptest.NewRequest("POST", "/mcp/gateway/billing", nil), root, "billing", appToken("rae", auth.RoleAuthor))
	if err != nil || len(srv.Direct.Tools) != 0 {
		t.Fatalf("an unpinned operation was offered: %v %+v", err, srv)
	}
	if err := integrationsPin(root, []string{"billing"}); err != nil {
		t.Fatal(err)
	}
	srv, err = gatewayServer(httptest.NewRequest("POST", "/mcp/gateway/billing", nil), root, "billing", appToken("rae", auth.RoleAuthor))
	if err != nil || len(srv.Direct.Tools) != 1 || srv.Direct.Tools[0].Name != "getInvoice" {
		t.Fatalf("%v %+v", err, srv)
	}
	out, err := srv.Direct.Call("getInvoice", map[string]any{"id": "7"})
	if err != nil || !strings.Contains(out, `"amount":12`) {
		t.Fatalf("%q %v", out, err)
	}
	if sentTo != "GET https://api.billing.example/v1/invoices/7" || key != "k3y" {
		t.Errorf("sent %q with key %q", sentTo, key)
	}
}
