// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/fetch"
)

func billing() agent.Integration {
	return agent.Integration{
		Name: "billing", Kind: agent.IntegrationHTTP, Enabled: true, Purpose: "Read and raise invoices",
		Endpoint: "api.billing.example", Path: "/v1/", Writes: true, Secret: "billing-token",
		Uses: []string{"getInvoice", "createInvoice"},
		Operations: []agent.Operation{
			{Name: "getInvoice", Method: "GET", Path: "/invoices/{id}", Description: "One invoice",
				Params: []agent.OperationParam{{Name: "id", In: "path"}, {Name: "expand", In: "query", Type: "boolean"}}},
			{Name: "createInvoice", Method: "POST", Path: "/invoices",
				Body: json.RawMessage(`{"type":"object","properties":{"amount":{"type":"number"}}}`)},
			{Name: "deleteInvoice", Method: "DELETE", Path: "/invoices/{id}",
				Params: []agent.OperationParam{{Name: "id", In: "path"}}},
		},
	}
}

type sent struct {
	method, url string
	body        string
	headers     map[string]string
}

func restClient(status int, answer string) (*Client, *[]sent) {
	var calls []sent
	return &Client{
		Secrets: func(string) (string, error) { return "s3cret", nil },
		DoMethod: func(_ context.Context, method, url string, body []byte, headers map[string]string) (*fetch.Result, error) {
			calls = append(calls, sent{method, url, string(body), headers})
			return &fetch.Result{Status: status, Body: []byte(answer)}, nil
		},
	}, &calls
}

func TestARESTIntegrationsOperationsAreItsTools(t *testing.T) {
	in := billing()
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	c, _ := restClient(200, "{}")
	tools, err := c.Tools(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, tl := range tools {
		allowed[tl.Name] = tl.Allowed
		if tl.Definition == "" {
			t.Errorf("%s has no definition to pin", tl.Name)
		}
	}
	if !allowed["getInvoice"] || allowed["deleteInvoice"] || len(tools) != 3 {
		t.Errorf("tools %v", allowed)
	}
	var schema map[string]any
	_ = json.Unmarshal(tools[0].InputSchema, &schema)
	if schema["additionalProperties"] != false {
		t.Error("an operation's schema invites arguments it does not declare")
	}
}

func TestARESTCallIsBuiltOnlyFromItsDeclaration(t *testing.T) {
	in := billing()
	c, calls := restClient(200, `{"id":"a/b","amount":3}`)
	out, err := c.Call(context.Background(), in, "getInvoice", map[string]any{"id": "a/b", "expand": true})
	if err != nil {
		t.Fatal(err)
	}
	got := (*calls)[0]
	if got.method != "GET" || got.url != "https://api.billing.example/v1/invoices/a%2Fb?expand=true" {
		t.Errorf("sent %s %s", got.method, got.url)
	}
	if got.headers["Authorization"] != "Bearer s3cret" || !strings.Contains(out, `"amount":3`) {
		t.Errorf("headers %v, answer %s", got.headers, out)
	}
	if _, err := c.Call(context.Background(), in, "createInvoice", map[string]any{"body": map[string]any{"amount": 5}}); err != nil {
		t.Fatal(err)
	}
	if got := (*calls)[1]; got.method != "POST" || got.body != `{"amount":5}` || got.headers["Content-Type"] != "application/json" {
		t.Errorf("sent %+v", got)
	}

	in.Auth = "header:X-API-Key"
	if _, err := c.Call(context.Background(), in, "getInvoice", map[string]any{"id": "7"}); err != nil {
		t.Fatal(err)
	}
	if h := (*calls)[2].headers; h["X-API-Key"] != "s3cret" || h["Authorization"] != "" {
		t.Errorf("headers %v", h)
	}
}

func TestARESTCallRefusesWhatItWasNotDeclaredToTake(t *testing.T) {
	in := billing()
	c, calls := restClient(200, "{}")
	for name, args := range map[string]map[string]any{
		"an undeclared parameter": {"id": "7", "admin": true},
		"a missing path value":    {},
		"a path that climbs":      {"id": ".."},
		"a value that is a list":  {"id": []any{"1"}},
	} {
		if _, err := c.Call(context.Background(), in, "getInvoice", args); err == nil {
			t.Errorf("%s was sent", name)
		}
	}
	if _, err := c.Call(context.Background(), in, "deleteInvoice", map[string]any{"id": "7"}); err == nil {
		t.Error("an operation the install did not agree to was called")
	}
	if len(*calls) != 0 {
		t.Errorf("%d requests went out", len(*calls))
	}
}

func TestAREDeclaredOperationIsRefusedUntilPinnedAgain(t *testing.T) {
	in := billing()
	c, calls := restClient(200, "{}")
	tools, _ := c.Tools(context.Background(), in)
	in.Pins = map[string]string{"getInvoice": tools[0].Definition}
	if _, err := c.Call(context.Background(), in, "getInvoice", map[string]any{"id": "7"}); err != nil {
		t.Fatal(err)
	}
	var told string
	c.Changed = func(_ agent.Integration, tool, _, _ string) { told = tool }
	in.Operations[0].Path = "/admin/invoices/{id}"
	if _, err := c.Call(context.Background(), in, "getInvoice", map[string]any{"id": "7"}); err == nil {
		t.Fatal("an operation edited after it was pinned was called")
	}
	if told != "getInvoice" || len(*calls) != 1 {
		t.Errorf("told %q, %d requests", told, len(*calls))
	}
}

func TestARESTErrorSaysWhatTheServerAnswered(t *testing.T) {
	c, _ := restClient(403, `{"error":"forbidden"}`)
	_, err := c.Call(context.Background(), billing(), "getInvoice", map[string]any{"id": "7"})
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("err %v", err)
	}
}
