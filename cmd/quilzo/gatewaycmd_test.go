// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
)

// modelServer speaks the chat completions protocol, or fails.
func modelServer(t *testing.T, fail bool, calls *int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(calls, 1)
		if fail {
			http.Error(w, "overloaded", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":` +
			`"{\"answer\": \"Opened ink bottles cannot be returned [1].\", \"action\": null}"}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAChatbotFallsBackAcrossRoutesAndStopsAtItsBudget, over real HTTP.
func TestAChatbotFallsBackAcrossRoutesAndStopsAtItsBudget(t *testing.T) {
	root := publishedShop(t)
	var downCalls, upCalls int64
	down := modelServer(t, true, &downCalls)
	up := modelServer(t, false, &upCalls)

	for _, args := range [][]string{
		{"route", "add", "primary", "--url", down.URL + "/v1", "--model", "big"},
		{"route", "add", "backup", "--url", up.URL + "/v1", "--model", "small"},
		{"budget", "chatbot:help", "--chars-per-day", "6000"},
	} {
		if err := cmdGateway(root, args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help", "--model"}); err != nil {
		t.Fatal(err)
	}
	a, _ := loadAssistant(root, "help")
	idx, err := assistantIndex(root, a)
	if err != nil {
		t.Fatal(err)
	}
	m, why := assistantModelAt(root, a)
	if m == nil {
		t.Fatalf("no model: %s", why)
	}

	ans, err := assistant.Respond(context.Background(), a, idx, m, "can I return opened ink")
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != "model" || atomic.LoadInt64(&downCalls) == 0 || atomic.LoadInt64(&upCalls) == 0 {
		t.Fatalf("mode %s, primary %d calls, backup %d: %s", ans.Mode, downCalls, upCalls, ans.Note)
	}

	// Spend the budget; the chatbot keeps answering, from its pages.
	var last assistant.Answer
	for i := 0; i < 40; i++ {
		last, _ = assistant.Respond(context.Background(), a, idx, m, "can I return opened ink")
		if last.Mode == "extractive" {
			break
		}
	}
	if last.Mode != "extractive" || !strings.Contains(last.Note, "over budget") ||
		!strings.Contains(last.Text, "cannot be returned") {
		t.Fatalf("over budget: mode %s note %q text %q", last.Mode, last.Note, last.Text)
	}

	// The ledger says who spent what, and holds no question.
	b, _ := os.ReadFile(usagePath(root))
	if !strings.Contains(string(b), `"consumer":"chatbot:help"`) ||
		strings.Contains(string(b), "opened ink") {
		t.Fatalf("ledger: %s", b)
	}
}

func TestAKeyIsNamedNeverGiven(t *testing.T) {
	root := publishedShop(t)
	err := cmdGateway(root, []string{"route", "add", "hosted", "--url",
		"https://api.example/v1", "--model", "m", "--key-env", "sk-live-1234"})
	if err == nil {
		t.Fatal("a key was accepted where a variable name belongs")
	}
	if _, serr := os.Stat(gatewayPath(root)); !os.IsNotExist(serr) {
		t.Fatal("a refused route was written")
	}
}
