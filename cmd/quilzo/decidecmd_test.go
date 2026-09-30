// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/decide"
)

const ticketDecider = `{"name": "ticket", "title": "Ticket triage", "questions": [
  {"name": "queue", "ask": "Which team?", "kind": "choice", "options": ["billing", "returns"]}]}`

// TestADecisionGoesThroughTheGatewayOverHTTP.
func TestADecisionGoesThroughTheGatewayOverHTTP(t *testing.T) {
	root := publishedShop(t)
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":` +
			`"{\"answers\": {\"queue\": {\"value\": \"returns\", \"confidence\": 0.9}}}"}}]}`))
	}))
	defer model.Close()
	if err := cmdGateway(root, []string{"route", "add", "local", "--url", model.URL + "/v1", "--model", "m"}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "d.json")
	os.WriteFile(file, []byte(ticketDecider), 0o600)
	if err := cmdDecide(root, []string{"set", file}); err != nil {
		t.Fatal(err)
	}
	d, err := loadDecider(root, "ticket")
	if err != nil {
		t.Fatal(err)
	}
	m, why := deciderModel(root, "ticket")
	if m == nil {
		t.Fatal(why)
	}
	res, err := decide.Decide(context.Background(), d, m, map[string]any{"body": "refund please"})
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := res.Get("queue"); a.Escalate || a.Value != "returns" {
		t.Fatalf("%+v", res)
	}
	if err := cmdDecide(root, []string{"ask", "ticket", `{"body": "refund please"}`}); err != nil {
		t.Fatal(err)
	}
	// Recorded against the decider's own budget line.
	b, _ := os.ReadFile(usagePath(root))
	if !strings.Contains(string(b), `"consumer":"decider:ticket"`) {
		t.Fatalf("usage not recorded for the decider: %s", b)
	}
}
