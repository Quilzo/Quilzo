// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package apiimport

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
)

const invoices = `{
  "openapi": "3.1.0",
  "info": {"title": "Billing API", "description": "Invoices and customers.\nMore text."},
  "servers": [{"url": "https://api.billing.example/v1"}],
  "components": {
    "securitySchemes": {"token": {"type": "http", "scheme": "bearer"}},
    "parameters": {"Id": {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}},
    "schemas": {"Invoice": {"type": "object", "properties": {"amount": {"type": "number"}, "customer": {"$ref": "#/components/schemas/Customer"}}},
                "Customer": {"type": "object", "properties": {"email": {"type": "string"}}}}
  },
  "security": [{"token": []}],
  "paths": {
    "/invoices": {
      "get": {"operationId": "listInvoices", "summary": "List invoices",
              "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}},
                             {"name": "X-Tenant", "in": "header", "schema": {"type": "string"}}]},
      "post": {"operationId": "createInvoice", "summary": "Raise an invoice",
               "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Invoice"}}}}}
    },
    "/invoices/{id}": {
      "parameters": [{"$ref": "#/components/parameters/Id"}],
      "get": {"operationId": "getInvoice", "summary": "One invoice"},
      "delete": {"summary": "Cancel an invoice"},
      "patch": {"operationId": "notes", "parameters": [{"$ref": "https://evil.example/params.json#/X"}],
                "requestBody": {"content": {"application/json": {"schema": {"$ref": "https://evil.example/schema.json"}}}}}
    }
  }
}`

func TestAnOpenAPIDocumentListsWhatItOffersAndDeclaresNothingUnasked(t *testing.T) {
	imp, err := OpenAPI([]byte(invoices), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Integration.Operations) != 0 || len(imp.Integration.Uses) != 0 {
		t.Fatal("operations were declared that nobody named")
	}
	var names []string
	for _, o := range imp.Available {
		names = append(names, o.Method+" "+o.Name)
	}
	got := strings.Join(names, ", ")
	for _, want := range []string{"GET listInvoices", "POST createInvoice", "GET getInvoice", "DELETE delete_invoices_id", "PATCH notes"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is not on offer: %s", want, got)
		}
	}
}

func TestOnlyTheNamedOperationsAreDeclaredSwitchedOff(t *testing.T) {
	imp, err := OpenAPI([]byte(invoices), Options{Uses: []string{"listInvoices", "getInvoice", "createInvoice"}, Secret: "billing-token"})
	if err != nil {
		t.Fatal(err)
	}
	in := imp.Integration
	if in.Enabled {
		t.Error("an imported integration arrived switched on")
	}
	if in.Name != "billing-api" || in.Endpoint != "api.billing.example" || in.Path != "/v1" || in.Auth != "" || !in.Writes {
		t.Errorf("declared %+v", in)
	}
	if !strings.HasPrefix(in.Purpose, "Billing API: Invoices and customers.") || strings.Contains(in.Purpose, "More text") {
		t.Errorf("purpose %q", in.Purpose)
	}
	ops := map[string]agent.Operation{}
	for _, o := range in.Operations {
		ops[o.Name] = o
	}
	if len(ops) != 3 {
		t.Fatalf("%d operations declared", len(ops))
	}
	if p := ops["getInvoice"].Params; len(p) != 1 || p[0].Name != "id" || p[0].In != "path" {
		t.Errorf("getInvoice params %+v", p)
	}
	for _, p := range ops["listInvoices"].Params {
		if p.In == "header" {
			t.Error("a header parameter was imported")
		}
	}
	if b := string(ops["createInvoice"].Body); !strings.Contains(b, `"email"`) || strings.Contains(b, "$ref") {
		t.Errorf("the body schema was not followed locally: %s", b)
	}
	notes := strings.Join(imp.Notes, "\n")
	if !strings.Contains(notes, "X-Tenant") || !strings.Contains(notes, "2 other operations") {
		t.Errorf("notes:\n%s", notes)
	}
}

func TestNothingOutsideTheDocumentIsFollowed(t *testing.T) {
	imp, err := OpenAPI([]byte(invoices), Options{Uses: []string{"notes", "getInvoice"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range imp.Integration.Operations {
		if o.Name == "notes" && string(o.Body) != `{"type":"object"}` {
			t.Errorf("an external schema was used: %s", o.Body)
		}
	}
	if notes := strings.Join(imp.Notes, "\n"); !strings.Contains(notes, "evil.example/params.json") ||
		!strings.Contains(notes, "not fetched") {
		t.Errorf("the external references were not named:\n%s", notes)
	}
}

func TestADocumentThatCannotBeReachedSafelyIsRefused(t *testing.T) {
	for name, doc := range map[string]string{
		"swagger 2":       `{"swagger": "2.0", "paths": {}}`,
		"plain http":      strings.Replace(invoices, "https://api.billing.example", "http://api.billing.example", 1),
		"server template": strings.Replace(invoices, "https://api.billing.example/v1", "https://{region}.billing.example", 1),
		"no operations":   `{"openapi": "3.0.3", "info": {"title": "x"}, "servers": [{"url": "https://x.example"}], "paths": {}}`,
	} {
		if _, err := OpenAPI([]byte(doc), Options{Uses: []string{"getInvoice"}}); err == nil {
			t.Errorf("%s was imported", name)
		}
	}
	if _, err := OpenAPI([]byte(invoices), Options{Uses: []string{"nope"}}); err == nil {
		t.Error("an operation the document lacks was declared")
	}
	// An API key in a query string is not imported.
	q := strings.Replace(invoices, `{"type": "http", "scheme": "bearer"}`, `{"type": "apiKey", "in": "query", "name": "key"}`, 1)
	imp, err := OpenAPI([]byte(q), Options{Uses: []string{"getInvoice"}})
	if err != nil || imp.Integration.Auth != "" || !strings.Contains(strings.Join(imp.Notes, " "), "logs") {
		t.Errorf("a query key: %v %+v", err, imp)
	}
	h := strings.Replace(invoices, `{"type": "http", "scheme": "bearer"}`, `{"type": "apiKey", "in": "header", "name": "X-API-Key"}`, 1)
	if imp, err := OpenAPI([]byte(h), Options{Uses: []string{"getInvoice"}}); err != nil || imp.Integration.Auth != "header:X-API-Key" {
		t.Errorf("a header key: %v", err)
	}
}

func TestAnMCPRegistryEntryBecomesAServerDeclaration(t *testing.T) {
	doc := `{"name": "io.github.acme/tracker", "description": "Issues in the Acme tracker",
	  "remotes": [{"type": "sse", "url": "https://old.acme.example/sse"}, {"type": "streamable-http", "url": "https://mcp.acme.example/mcp"}],
	  "packages": [{"registryType": "npm", "identifier": "@acme/tracker-mcp"}]}`
	if !IsServerJSON([]byte(doc)) || IsServerJSON([]byte(invoices)) {
		t.Fatal("the two kinds of document are not told apart")
	}
	imp, err := MCPServer([]byte(doc), Options{Uses: []string{"list_issues"}})
	if err != nil {
		t.Fatal(err)
	}
	in := imp.Integration
	if in.Kind != agent.IntegrationMCP || in.Name != "tracker" || in.Endpoint != "mcp.acme.example" || in.Path != "/mcp" || in.Enabled {
		t.Errorf("declared %+v", in)
	}
	if !strings.Contains(strings.Join(imp.Notes, " "), "@acme/tracker-mcp") {
		t.Error("the package was not mentioned")
	}
	if _, err := MCPServer([]byte(`{"name": "x", "packages": [{"registryType": "npm", "identifier": "y"}]}`), Options{}); err == nil {
		t.Error("a package-only server was declared with nowhere to reach")
	}
}
