// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/collection"
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

// A chatbot that reads products tells a visitor the price the Buy button
// charges. It read every field of the record, the written price among them,
// and that was a copy kept by hand: after a price change from 1200 to 1300
// it answered £12.00 beside the price of 1300 the button charged.
func TestAChatbotSaysThePriceThatIsCharged(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tree, _, err := collection.PutMany(s, "", "products", []collection.Record{{Fields: map[string]any{
		"name": "Indigo ink", "price": 1300.0, "currency": "GBP", "price_display": "£12.00"}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ps, err := recordPassages(s, tree, []string{"products"})
	if err != nil || len(ps) != 1 {
		t.Fatalf("%d passage(s): %v", len(ps), err)
	}
	if text := ps[0].Text; !strings.Contains(text, "price display: £13.00") || strings.Contains(text, "£12.00") {
		t.Errorf("the chatbot reads the price as:\n%s", text)
	}
}
