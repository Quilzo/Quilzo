// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
)

// A chatbot can name the model that answers it first, by its route or by
// the model a route serves, with the gateway's other routes behind it; or
// be kept to that route alone, when its visitors' words may go nowhere
// else, and then it quotes its pages rather than ask another route.
func TestAChatbotChoosesTheModelThatAnswersIt(t *testing.T) {
	root := publishedShop(t)
	var cheapCalls, strongCalls int64
	cheap := modelServer(t, false, &cheapCalls)
	strong := modelServer(t, true, &strongCalls)
	for _, args := range [][]string{
		{"route", "add", "cheap", "--url", cheap.URL + "/v1", "--model", "small"},
		{"route", "add", "strong", "--url", strong.URL + "/v1", "--model", "big"},
	} {
		if err := cmdGateway(root, args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	ask := func(name string) assistant.Answer {
		t.Helper()
		a, err := loadAssistant(root, name)
		if err != nil {
			t.Fatal(err)
		}
		idx, err := assistantIndex(root, a)
		if err != nil {
			t.Fatal(err)
		}
		m, why := assistantModelAt(root, a)
		if m == nil {
			t.Fatalf("%s: no model: %s", name, why)
		}
		ans, err := assistant.Respond(context.Background(), a, idx, m, "can I return opened ink")
		if err != nil {
			t.Fatal(err)
		}
		return ans
	}

	// By the model a route serves: the strong route first, which fails,
	// and the cheap one behind it answers.
	if err := cmdAssistant(root, []string{"add", "sales", "--title", "Sales", "--model", "--route", "big"}); err != nil {
		t.Fatal(err)
	}
	if ans := ask("sales"); ans.Mode != "model" || atomic.LoadInt64(&strongCalls) == 0 || atomic.LoadInt64(&cheapCalls) == 0 {
		t.Fatalf("mode %s, strong %d, cheap %d: %s", ans.Mode, strongCalls, cheapCalls, ans.Note)
	}

	// Kept to the strong route alone: it fails, nothing else is asked, and
	// the chatbot quotes its pages.
	before := atomic.LoadInt64(&cheapCalls)
	if err := cmdAssistant(root, []string{"add", "eu", "--title", "EU", "--model", "--route", "strong", "--route-only"}); err != nil {
		t.Fatal(err)
	}
	if ans := ask("eu"); ans.Mode != "extractive" || atomic.LoadInt64(&cheapCalls) != before {
		t.Fatalf("a chatbot kept to one route was answered by another: mode %s, %s", ans.Mode, ans.Note)
	}

	// Kept to a route nobody serves: no model at all, and why.
	if err := cmdAssistant(root, []string{"add", "gone", "--title", "Gone", "--model", "--route", "nowhere", "--route-only"}); err != nil {
		t.Fatal(err)
	}
	a, _ := loadAssistant(root, "gone")
	if m, why := assistantModelAt(root, a); m != nil || !strings.Contains(why, "no route serves") {
		t.Fatalf("%v %q", m, why)
	}
	// Kept to one route and naming none is refused where it is declared.
	if err := cmdAssistant(root, []string{"add", "bad", "--title", "Bad", "--route-only"}); err == nil {
		t.Fatal("a chatbot kept to no route was declared")
	}
}
