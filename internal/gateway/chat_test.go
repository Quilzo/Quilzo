// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
)

// chatty is a route's model that takes conversations and keeps what it was
// sent.
type chatty struct {
	name  string
	got   []assist.ChatRequest
	reply assist.ChatReply
	err   error
}

func (c *chatty) Name() string { return c.name }
func (c *chatty) Complete(context.Context, string, string) (string, error) {
	return "", errors.New("not this")
}
func (c *chatty) Chat(_ context.Context, r assist.ChatRequest) (assist.ChatReply, error) {
	c.got = append(c.got, r)
	return c.reply, c.err
}

const screen = "data:image/png;base64,iVBORw0KGgo="

func chatGateway(routes []Route, models map[string]*chatty) *Gateway {
	return New(Config{Routes: routes}, func(r Route) (Model, error) { return models[r.Name], nil }, nil)
}

func talk(text string, images int) assist.ChatRequest {
	parts := []assist.Part{{Type: "text", Text: text}}
	for i := 0; i < images; i++ {
		parts = append(parts, assist.Part{Type: "image_url", ImageURL: &assist.ImageURL{URL: screen}})
	}
	return assist.ChatRequest{Messages: []assist.ChatMessage{{Role: "user", Content: parts}},
		Tools: []assist.ChatTool{{Type: "function", Function: assist.ToolFunction{Name: "click"}}}}
}

// A tool the model chose comes back, its arguments with what was masked
// put back; and what may not leave for the route never reached it.
func TestAConversationIsMaskedOnTheWayOutAndRestoredOnTheWayBack(t *testing.T) {
	m := &chatty{name: "local"}
	g := chatGateway([]Route{{Name: "hosted", Model: "x"}}, map[string]*chatty{"hosted": m})
	m.reply = assist.ChatReply{Message: assist.ChatMessage{Role: "assistant",
		ToolCalls: []assist.ToolCall{{ID: "1", Type: "function", Function: assist.FunctionCall{Name: "type"}}}},
		Finish: "tool_calls"}
	req := talk("email mira.k@mailhost.net about card 5425233430109903", 0)
	r, err := g.For("agent:x").(*bound).Chat(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sent := m.got[0].Messages[0].Text()
	if strings.Contains(sent, "mira.k@mailhost.net") || strings.Contains(sent, "5425233430109903") {
		t.Fatalf("personal data left for a route not allowed it: %q", sent)
	}
	if r.Finish != "tool_calls" || r.Message.ToolCalls[0].Function.Name != "type" {
		t.Errorf("the tool call did not come back: %+v", r)
	}

	// A placeholder in the model's tool arguments is restored.
	ph := sent[strings.Index(sent, "email ")+6:]
	ph = ph[:strings.Index(ph, " ")]
	m.reply.Message.ToolCalls[0].Function.Arguments = `{"to":"` + ph + `"}`
	r, err = g.For("agent:x").(*bound).Chat(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Message.ToolCalls[0].Function.Arguments, "mira.k@mailhost.net") {
		t.Errorf("the arguments came back as %q", r.Message.ToolCalls[0].Function.Arguments)
	}
}

// A picture goes only to a route allowed personal data; the gateway falls
// through to one that is, and refuses when there is none.
func TestAPictureGoesOnlyToARouteAllowedPersonalData(t *testing.T) {
	hosted, local := &chatty{name: "hosted"}, &chatty{name: "local"}
	g := chatGateway([]Route{{Name: "hosted", Model: "x"}, {Name: "local", Model: "y", Personal: true}},
		map[string]*chatty{"hosted": hosted, "local": local})
	if _, err := g.For("agent:x").(*bound).Chat(context.Background(), talk("what is on the screen", 1)); err != nil {
		t.Fatal(err)
	}
	if len(hosted.got) != 0 || len(local.got) != 1 {
		t.Fatalf("hosted got %d, local %d", len(hosted.got), len(local.got))
	}
	only := chatGateway([]Route{{Name: "hosted", Model: "x"}}, map[string]*chatty{"hosted": hosted})
	if _, err := only.For("agent:x").(*bound).Chat(context.Background(), talk("what is on the screen", 1)); err == nil ||
		!strings.Contains(err.Error(), "personal data") {
		t.Errorf("a picture with no route allowed it: %v", err)
	}
}

// A picture given as a web address, an unknown role or a strange part is
// refused before anything is sent.
func TestAConversationThisWillNotSendIsRefused(t *testing.T) {
	m := &chatty{name: "local"}
	g := chatGateway([]Route{{Name: "local", Model: "y", Personal: true}}, map[string]*chatty{"local": m})
	for name, req := range map[string]assist.ChatRequest{
		"remote picture": {Messages: []assist.ChatMessage{{Role: "user", Content: []assist.Part{{Type: "image_url",
			ImageURL: &assist.ImageURL{URL: "https://evil.example/leak.png?secret=1"}}}}}},
		"svg": {Messages: []assist.ChatMessage{{Role: "user", Content: []assist.Part{{Type: "image_url",
			ImageURL: &assist.ImageURL{URL: "data:image/svg+xml;base64,PHN2Zz4="}}}}}},
		"role":  {Messages: []assist.ChatMessage{{Role: "root", Content: []assist.Part{{Type: "text", Text: "x"}}}}},
		"part":  {Messages: []assist.ChatMessage{{Role: "user", Content: []assist.Part{{Type: "input_audio"}}}}},
		"empty": {},
	} {
		if _, err := g.For("agent:x").(*bound).Chat(context.Background(), req); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if len(m.got) != 0 {
		t.Errorf("%d refused conversations reached the model", len(m.got))
	}
}
