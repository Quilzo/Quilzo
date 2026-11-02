// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// An integration that acts with a connected account goes with the token
// of the person the client acts for, asked for the integration's host; a
// client acting for nobody refuses it rather than calling anonymously.
func TestAConnectedIntegrationGoesAsItsPerson(t *testing.T) {
	in := billing()
	in.Secret, in.Connection = "", "acme"
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	c, calls := restClient(200, `{"id":"a","amount":3}`)
	if _, err := c.Call(context.Background(), in, "getInvoice", map[string]any{"id": "a"}); err == nil ||
		!strings.Contains(err.Error(), "acts for nobody") || len(*calls) != 0 {
		t.Fatalf("called with nobody's account: %v", err)
	}
	var asked [2]string
	c.Connection = func(_ context.Context, provider, host string) (string, error) {
		asked = [2]string{provider, host}
		return "dana-token", nil
	}
	if _, err := c.Call(context.Background(), in, "getInvoice", map[string]any{"id": "a"}); err != nil {
		t.Fatal(err)
	}
	if asked != [2]string{"acme", "api.billing.example"} || (*calls)[0].headers["Authorization"] != "Bearer dana-token" {
		t.Fatalf("%v %v", asked, (*calls)[0].headers)
	}
	c.Connection = func(context.Context, string, string) (string, error) { return "", errors.New("not connected") }
	if _, err := c.Call(context.Background(), in, "getInvoice", map[string]any{"id": "a"}); err == nil || len(*calls) != 1 {
		t.Fatalf("called without the person's account: %v", err)
	}
}

// A declaration is one credential or the other, and an integration acting
// for a person is never offered to other vendors' agents.
func TestAConnectedIntegrationIsDeclaredSo(t *testing.T) {
	in := billing()
	in.Connection = "acme"
	if in.Validate() == nil {
		t.Error("a secret and a connection")
	}
	in.Secret = ""
	in.Connection = "Acme Corp"
	if in.Validate() == nil {
		t.Error("a connection that is not a provider's name")
	}
}
