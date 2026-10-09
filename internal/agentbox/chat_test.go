// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
)

func askBox(t *testing.T, h *Models, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// A program that offers tools, or shows the model a screen, gets the
// conversation answered whole, with the tool the model chose; one that
// only talks still goes through the text path.
func TestTheBoxPassesPicturesAndToolsThroughWhole(t *testing.T) {
	var whole []assist.ChatRequest
	texts := 0
	h := &Models{Secret: "s3cret",
		Complete: func(context.Context, string, string) (string, int, int, error) { texts++; return "hello", 3, 1, nil },
		Chat: func(_ context.Context, req assist.ChatRequest) (assist.ChatReply, error) {
			whole = append(whole, req)
			return assist.ChatReply{Message: assist.ChatMessage{Role: "assistant", ToolCalls: []assist.ToolCall{
				{ID: "c1", Type: "function", Function: assist.FunctionCall{Name: "click", Arguments: `{"ref":"e3"}`}}}},
				Usage: assist.Usage{In: 1500, Out: 8, Reported: true}}, nil
		}}
	code, out := askBox(t, h, `{"model":"x","messages":[{"role":"user","content":"hi"}]}`)
	if code != 200 || texts != 1 || len(whole) != 0 {
		t.Fatalf("text: %d texts=%d whole=%d %v", code, texts, len(whole), out)
	}
	code, out = askBox(t, h, `{"model":"x","messages":[{"role":"user","content":[{"type":"text","text":"what now"},
		{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]}],
		"tools":[{"type":"function","function":{"name":"click","parameters":{"type":"object"}}}],"tool_choice":"auto"}`)
	if code != 200 || len(whole) != 1 || whole[0].Images() != 1 || len(whole[0].Tools) != 1 || whole[0].ToolChoice != "auto" {
		t.Fatalf("whole: %d %+v %v", code, whole, out)
	}
	choice := out["choices"].([]any)[0].(map[string]any)
	msg := choice["message"].(map[string]any)
	if choice["finish_reason"] != "tool_calls" || msg["content"] != nil || len(msg["tool_calls"].([]any)) != 1 {
		t.Errorf("the tool call came back as %v", choice)
	}
	// A picture by address is refused here, before any model is asked.
	code, _ = askBox(t, h, `{"model":"x","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://evil.example/p.png"}}]}]}`)
	if code != http.StatusBadRequest || len(whole) != 1 {
		t.Errorf("a picture by address: %d, whole %d", code, len(whole))
	}
	// And a run whose model takes text only says so rather than dropping
	// the picture and answering something else.
	h.Chat = nil
	code, out = askBox(t, h, `{"model":"x","messages":[{"role":"user","content":"x"}],"tools":[{"type":"function","function":{"name":"click"}}]}`)
	if code != http.StatusBadRequest || !strings.Contains(out["error"].(map[string]any)["message"].(string), "text only") {
		t.Errorf("no conversation model: %d %v", code, out)
	}
}
