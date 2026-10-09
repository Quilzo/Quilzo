// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assist

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The conversation goes out in the shape every chat completions server
// reads: text as a string, a picture as parts, the tools offered; and the
// tool the model chose comes back, with no text at all.
func TestAConversationGoesOutAndAToolCallComesBack(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,
			"tool_calls":[{"id":"c1","type":"function","function":{"name":"click","arguments":"{\"ref\":\"e12\"}"}}]}}],
			"usage":{"prompt_tokens":1200,"completion_tokens":9}}`)
	}))
	defer srv.Close()
	h := &HTTPModel{BaseURL: srv.URL, Model: "m", Client: srv.Client()}
	req := ChatRequest{
		Messages: []ChatMessage{
			{Role: "system", Content: []Part{{Type: "text", Text: "you operate a browser"}}},
			{Role: "user", Content: []Part{{Type: "text", Text: "submit the form"},
				{Type: "image_url", ImageURL: &ImageURL{URL: "data:image/png;base64,iVBORw0KGgo="}}}},
		},
		Tools:      []ChatTool{{Type: "function", Function: ToolFunction{Name: "click", Parameters: json.RawMessage(`{"type":"object"}`)}}},
		ToolChoice: "auto",
	}
	r, err := h.Chat(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	msgs := got["messages"].([]any)
	if s, ok := msgs[0].(map[string]any)["content"].(string); !ok || s != "you operate a browser" {
		t.Errorf("a text-only message went out as %v", msgs[0])
	}
	parts, ok := msgs[1].(map[string]any)["content"].([]any)
	if !ok || len(parts) != 2 || parts[1].(map[string]any)["type"] != "image_url" {
		t.Errorf("a message with a picture went out as %v", msgs[1])
	}
	if tools := got["tools"].([]any); len(tools) != 1 || got["tool_choice"] != "auto" {
		t.Errorf("tools %v choice %v", got["tools"], got["tool_choice"])
	}
	if r.Finish != "tool_calls" || len(r.Message.ToolCalls) != 1 || r.Message.ToolCalls[0].Function.Arguments != `{"ref":"e12"}` ||
		r.Message.Text() != "" || !r.Usage.Reported || r.Usage.In != 1200 {
		t.Errorf("reply %+v", r)
	}
	// A message carrying only tool calls writes its content as null.
	b, _ := json.Marshal(r.Message)
	if !strings.Contains(string(b), `"content":null`) {
		t.Errorf("an assistant turn with only tool calls is %s", b)
	}
}
