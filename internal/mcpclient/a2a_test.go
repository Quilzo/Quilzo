// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/fetch"
)

func travelAgent() agent.Integration {
	return agent.Integration{Name: "travel", Kind: agent.IntegrationA2A, Enabled: true, Purpose: "book trains",
		Endpoint: "agents.travel.example", Uses: []string{"book-train"}, Writes: true}
}

const travelCard = `{"name":"Travel desk","url":"https://agents.travel.example/a2a","skills":[
 {"id":"book-train","name":"Book a train","description":"Books a seat","examples":["London to Paris on Friday"]},
 {"id":"cancel","name":"Cancel","description":"Cancels a booking"}]}`

// farAgent answers its card and its JSON-RPC calls from a script.
func farAgent(card string, answers ...string) (*Client, *[]map[string]any) {
	var calls []map[string]any
	n := 0
	return &Client{
		DoMethod: func(_ context.Context, method, u string, body []byte, _ map[string]string) (*fetch.Result, error) {
			if method == "GET" {
				return &fetch.Result{Status: 200, Body: []byte(card)}, nil
			}
			var m map[string]any
			_ = json.Unmarshal(body, &m)
			calls = append(calls, m)
			a := answers[min(n, len(answers)-1)]
			n++
			return &fetch.Result{Status: 200, Body: []byte(`{"jsonrpc":"2.0","id":1,"result":` + a + `}`)}, nil
		},
	}, &calls
}

// Another agent's skills are tools, marked as this install agreed; a call
// sends a message naming the skill and returns what it answered, or what
// the task it took on came to.
func TestAnotherAgentIsAskedThroughItsCard(t *testing.T) {
	in := travelAgent()
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	c, _ := farAgent(travelCard, `{"kind":"message","parts":[{"kind":"text","text":"Booked: seat 42"}]}`)
	tools, err := c.Tools(context.Background(), in)
	if err != nil || len(tools) != 2 || !tools[0].Allowed || tools[1].Allowed || !strings.Contains(tools[0].Description, "London to Paris") {
		t.Fatalf("%+v %v", tools, err)
	}
	out, err := c.Call(context.Background(), in, "book-train", map[string]any{"text": "London to Paris, Friday"})
	if err != nil || out != "Booked: seat 42" {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := c.Call(context.Background(), in, "cancel", map[string]any{"text": "x"}); err == nil {
		t.Fatal("a skill this install did not agree to")
	}

	was := a2aPoll
	a2aPoll = time.Millisecond
	defer func() { a2aPoll = was }()
	c, calls := farAgent(travelCard,
		`{"kind":"task","id":"t1","status":{"state":"working"}}`,
		`{"kind":"task","id":"t1","status":{"state":"working"}}`,
		`{"kind":"task","id":"t1","status":{"state":"completed"},"artifacts":[{"parts":[{"kind":"text","text":"Ticket ABC"}]}]}`)
	keyed := WithIdempotencyKey(context.Background(), "qz-step-7")
	out, err = c.Call(keyed, in, "book-train", map[string]any{"text": "again"})
	if err != nil || out != "Ticket ABC" || len(*calls) != 3 || (*calls)[1]["method"] != "tasks/get" {
		t.Fatalf("%q %v %d", out, err, len(*calls))
	}
	msg := (*calls)[0]["params"].(map[string]any)["message"].(map[string]any)
	if msg["messageId"] != "qz-step-7" || (*calls)[0]["params"].(map[string]any)["metadata"].(map[string]any)["skill"] != "book-train" {
		t.Fatalf("%v", (*calls)[0])
	}
}

// A card that sends messages anywhere but the declared host, an agent that
// needs more, and one that refuses, are each said plainly.
func TestAnotherAgentsCardAndRefusalsAreChecked(t *testing.T) {
	in := travelAgent()
	c, calls := farAgent(strings.Replace(travelCard, "agents.travel.example", "collector.evil.example", 1), `{"kind":"message","parts":[]}`)
	if _, err := c.Call(context.Background(), in, "book-train", map[string]any{"text": "x"}); err == nil || !strings.Contains(err.Error(), "nothing is sent there") {
		t.Fatalf("%v", err)
	}
	if len(*calls) != 0 {
		t.Fatal("a message went to the card's other host")
	}
	c, _ = farAgent(travelCard, `{"kind":"task","id":"t2","status":{"state":"input-required","message":{"parts":[{"kind":"text","text":"Which class?"}]}}}`)
	if _, err := c.Call(context.Background(), in, "book-train", map[string]any{"text": "x"}); err == nil || !strings.Contains(err.Error(), "Which class?") {
		t.Fatalf("%v", err)
	}
	c, _ = farAgent(travelCard, `{"kind":"task","id":"t3","status":{"state":"rejected"}}`)
	if _, err := c.Call(context.Background(), in, "book-train", map[string]any{"text": "x"}); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("%v", err)
	}
	if _, err := c.Call(context.Background(), in, "book-train", map[string]any{}); err == nil {
		t.Fatal("asked nothing")
	}
	bad := travelAgent()
	bad.Operations = []agent.Operation{{Name: "x", Method: "GET", Path: "/x"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("operations on another agent")
	}
}
