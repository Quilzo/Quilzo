// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A chatbot that reads a collection answers from its published records,
// and one that does not, does not.
func TestAChatbotAnswersFromRecords(t *testing.T) {
	root := demoStore(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	ask := func(collections string) assistant.Answer {
		t.Helper()
		args := []string{"add", "shop", "--title", "Shop"}
		if collections != "" {
			args = append(args, "--collections", collections)
		}
		_ = cmdAssistant(root, []string{"remove", "shop"})
		if err := cmdAssistant(root, args); err != nil {
			t.Fatal(err)
		}
		a, _ := loadAssistant(root, "shop")
		idx, err := assistantIndex(root, a)
		if err != nil {
			t.Fatal(err)
		}
		ans, err := assistant.Respond(context.Background(), a, idx, nil, "how big is the desk blotter?")
		if err != nil {
			t.Fatal(err)
		}
		return ans
	}
	ans := ask("products")
	found := false
	for _, s := range ans.Sources {
		if s.Record != "" && s.Title == "Desk blotter" {
			found = true
		}
	}
	if ans.Refused || !found || !strings.Contains(ans.Text, "600") {
		t.Fatalf("not answered from the record: %+v", ans)
	}
	for _, s := range ask("").Sources {
		if s.Record != "" {
			t.Fatal("a chatbot that reads no collection read a record")
		}
	}
}
