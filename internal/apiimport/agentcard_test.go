// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package apiimport

import (
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
)

const card = `{"name":"Travel Desk","description":"Books trains and hotels.\nMore.","url":"https://agents.travel.example/a2a",
"skills":[{"id":"book-train","name":"Book a train","description":"a seat"},{"id":"cancel","name":"Cancel"}]}`

// An agent card becomes a declaration of that agent, switched off, reaching
// the host the card speaks at, with its skills on offer.
func TestAnAgentCardIsImported(t *testing.T) {
	if !IsAgentCard([]byte(card)) || IsAgentCard([]byte(`{"openapi":"3.1.0","url":"x","skills":[1]}`)) {
		t.Fatal("not told apart")
	}
	imp, err := AgentCard([]byte(card), Options{Uses: []string{"book-train"}})
	if err != nil {
		t.Fatal(err)
	}
	in := imp.Integration
	if in.Kind != agent.IntegrationA2A || in.Endpoint != "agents.travel.example" || in.Name != "travel-desk" ||
		in.Purpose != "Books trains and hotels." || in.Enabled || len(imp.Available) != 2 {
		t.Fatalf("%+v %+v", in, imp.Available)
	}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := AgentCard([]byte(`{"name":"x","url":"http://agents.travel.example/a2a","skills":[{"id":"a"}]}`), Options{}); err == nil {
		t.Fatal("an http card")
	}
	if _, err := AgentCard([]byte(card), Options{Endpoint: "other.example"}); err == nil {
		t.Fatal("a card for another host")
	}
}
