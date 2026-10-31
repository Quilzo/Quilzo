// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// What a request asks of the answer, a format or a stop sequence, needs
// the whole conversation path even with no tool or picture: the text path
// would answer without it. A field nothing reads is refused before any
// model is asked, and what the gateway says of the request is passed on
// as the caller's to fix or the model's failing.
func TestWhatARequestAsksOfTheAnswerIsCarriedOrRefused(t *testing.T) {
	var whole []assist.ChatRequest
	texts := 0
	var fail error
	h := &Models{Secret: "s3cret",
		Complete: func(context.Context, string, string) (string, int, int, error) { texts++; return "hello", 3, 1, nil },
		Chat: func(_ context.Context, req assist.ChatRequest) (assist.ChatReply, error) {
			whole = append(whole, req)
			return assist.ChatReply{Message: assist.ChatMessage{Role: "assistant",
				Content: []assist.Part{{Type: "text", Text: `{"ok":true}`}}}}, fail
		}}
	for _, more := range []string{`"response_format":{"type":"json_object"}`, `"stop":"END"`, `"temperature":0.2`,
		`"reasoning_effort":"low"`} {
		whole = nil
		code, out := askBox(t, h, `{"model":"x","messages":[{"role":"user","content":"hi"}],`+more+`}`)
		if code != 200 || len(whole) != 1 || texts != 0 {
			t.Errorf("%s: %d whole=%d texts=%d %v", more, code, len(whole), texts, out)
		}
	}
	if whole[0].ReasoningEffort != "low" {
		t.Errorf("the effort was not carried: %+v", whole[0])
	}
	whole = nil
	code, out := askBox(t, h, `{"model":"x","messages":[{"role":"user","content":"hi"}],"seed":7}`)
	if code != http.StatusBadRequest || len(whole) != 0 || texts != 0 ||
		!strings.Contains(out["error"].(map[string]any)["message"].(string), "seed") {
		t.Errorf("a seed: %d %v", code, out)
	}
	for err, want := range map[error]int{
		fmt.Errorf("%w: no route takes a format", assist.ErrCannotHonour): http.StatusBadRequest,
		fmt.Errorf("%w: not JSON", assist.ErrNotHonoured):                 http.StatusBadGateway,
		errors.New("over budget"):                                         http.StatusTooManyRequests,
	} {
		fail = err
		if code, out := askBox(t, h, `{"model":"x","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_object"}}`); code != want {
			t.Errorf("%v: %d %v", err, code, out)
		}
	}
	h.Chat = nil
	code, out = askBox(t, h, `{"model":"x","messages":[{"role":"user","content":"hi"}],"response_format":{"type":"json_object"}}`)
	if code != http.StatusBadRequest || texts != 0 || !strings.Contains(out["error"].(map[string]any)["message"].(string), "text only") {
		t.Errorf("a format with no conversation model: %d %v", code, out)
	}
}
