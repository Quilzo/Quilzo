// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const answerSchema = `{"type":"object","properties":{"city":{"type":"string"},"degrees":{"type":"number"}},
	"required":["city","degrees"],"additionalProperties":false}`

// What a caller asked of the answer goes to the model under the names
// chat completions give it, the caller's temperature in place of the
// route's.
func TestWhatTheCallerAskedOfTheAnswerIsSent(t *testing.T) {
	h, got := sent(t, 0)
	route := 0.7
	h.Params = Params{Temperature: &route}
	req := clickRequest()
	temp, top := 0.2, 0.5
	req.Temperature, req.TopP = &temp, &top
	req.Stop = []string{"END", "\n\n"}
	req.ReasoningEffort = "high"
	req.OneToolCall = true
	req.ResponseFormat = &ResponseFormat{Type: "json_schema", Schema: json.RawMessage(answerSchema), Strict: true}
	if _, err := h.Chat(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	g := *got
	if g["temperature"] != 0.2 || g["top_p"] != 0.5 || g["reasoning_effort"] != "high" || g["parallel_tool_calls"] != false {
		t.Errorf("sent %v", g)
	}
	if stop, _ := json.Marshal(g["stop"]); string(stop) != `["END","\n\n"]` {
		t.Errorf("stop went out as %s", stop)
	}
	f, _ := g["response_format"].(map[string]any)
	s, _ := f["json_schema"].(map[string]any)
	if f["type"] != "json_schema" || s["name"] != "answer" || s["strict"] != true || s["schema"] == nil {
		t.Errorf("response_format went out as %v", g["response_format"])
	}
	req.ResponseFormat = &ResponseFormat{Type: "json_object"}
	req.Temperature, req.Stop, req.ReasoningEffort, req.OneToolCall = nil, nil, "", false
	if _, err := h.Chat(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal((*got)["response_format"]); string(b) != `{"type":"json_object"}` {
		t.Errorf("json_object went out as %s", b)
	}
	for _, k := range []string{"stop", "reasoning_effort", "parallel_tool_calls"} {
		if _, ok := (*got)[k]; ok {
			t.Errorf("%s was sent when nobody asked: %v", k, *got)
		}
	}
	if (*got)["temperature"] != 0.7 {
		t.Errorf("without the caller's own, the route's temperature was not sent: %v", *got)
	}
}

// A request asking what no model could be sent is refused before anything
// is sent.
func TestAnAnswerThatCannotBeAskedForIsRefused(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for name, change := range map[string]func(*ChatRequest){
		"five stop sequences":     func(r *ChatRequest) { r.Stop = []string{"a", "b", "c", "d", "e"} },
		"an empty stop sequence":  func(r *ChatRequest) { r.Stop = []string{""} },
		"a temperature of 3":      func(r *ChatRequest) { r.Temperature = f(3) },
		"a top_p of 0":            func(r *ChatRequest) { r.TopP = f(0) },
		"an effort of extreme":    func(r *ChatRequest) { r.ReasoningEffort = "extreme" },
		"a schema with no schema": func(r *ChatRequest) { r.ResponseFormat = &ResponseFormat{Type: "json_schema"} },
		"a format of yaml":        func(r *ChatRequest) { r.ResponseFormat = &ResponseFormat{Type: "yaml"} },
		"an object with a schema": func(r *ChatRequest) {
			r.ResponseFormat = &ResponseFormat{Type: "json_object", Schema: json.RawMessage(answerSchema)}
		},
		"a schema named oddly": func(r *ChatRequest) {
			r.ResponseFormat = &ResponseFormat{Type: "json_schema", Name: "a b", Schema: json.RawMessage(answerSchema)}
		},
		"a required call with nothing to call": func(r *ChatRequest) { r.Tools, r.ToolChoice = nil, "required" },
	} {
		r := clickRequest()
		change(&r)
		if r.Check() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func turn(text string, calls ...string) ChatReply {
	m := ChatMessage{Role: "assistant"}
	if text != "" {
		m.Content = []Part{{Type: "text", Text: text}}
	}
	for i, c := range calls {
		m.ToolCalls = append(m.ToolCalls, ToolCall{ID: string(rune('a' + i)), Type: "function",
			Function: FunctionCall{Name: c, Arguments: "{}"}})
	}
	return ChatReply{Message: m, Finish: "stop"}
}

// What the request asked for is held to on what came back: a stop
// sequence the model wrote past is cut at, and anything else not given is
// an error, never a pass.
func TestAnAnswerIsHeldToWhatWasAskedOfIt(t *testing.T) {
	req := clickRequest()
	req.Stop = []string{"###", "END"}
	r, err := req.Honour(turn("Paris is sunny.END and then more ### and more", "click"))
	if err != nil || r.Message.Text() != "Paris is sunny." || len(r.Message.ToolCalls) != 0 || r.Finish != "stop" {
		t.Errorf("a stop sequence was not cut at: %+v %v", r, err)
	}
	if r, _ := req.Honour(turn("nothing to cut", "click")); r.Message.Text() != "nothing to cut" || len(r.Message.ToolCalls) != 1 {
		t.Errorf("an answer without a stop sequence was changed: %+v", r)
	}

	for _, c := range []struct {
		name   string
		change func(*ChatRequest)
		reply  ChatReply
		ok     bool
	}{
		{"no call where none was allowed", func(r *ChatRequest) { r.ToolChoice = "none" }, turn("done"), true},
		{"a call where none was allowed", func(r *ChatRequest) { r.ToolChoice = "none" }, turn("", "click"), false},
		{"a call where one was required", func(r *ChatRequest) { r.ToolChoice = "required" }, turn("", "type"), true},
		{"words where a call was required", func(r *ChatRequest) { r.ToolChoice = "required" }, turn("I would rather not"), false},
		{"the named tool", func(r *ChatRequest) { r.ToolChoice, r.ToolChoiceName = "required", "click" }, turn("", "click"), true},
		{"another tool than the one named", func(r *ChatRequest) { r.ToolChoice, r.ToolChoiceName = "required", "click" },
			turn("", "type"), false},
		{"one call where one was allowed", func(r *ChatRequest) { r.OneToolCall = true }, turn("", "click"), true},
		{"two calls where one was allowed", func(r *ChatRequest) { r.OneToolCall = true }, turn("", "click", "type"), false},
		{"an object where one was asked", func(r *ChatRequest) { r.ResponseFormat = &ResponseFormat{Type: "json_object"} },
			turn(`{"city":"Paris"}`), true},
		{"prose where an object was asked", func(r *ChatRequest) { r.ResponseFormat = &ResponseFormat{Type: "json_object"} },
			turn("It is sunny in Paris."), false},
		{"a list where an object was asked", func(r *ChatRequest) { r.ResponseFormat = &ResponseFormat{Type: "json_object"} },
			turn(`["Paris"]`), false},
		{"an answer that fits its strict schema", strictly, turn(`{"city":"Paris","degrees":18}`), true},
		{"an answer that does not fit its strict schema", strictly, turn(`{"city":"Paris"}`), false},
		{"an answer with a field its strict schema does not have", strictly,
			turn(`{"city":"Paris","degrees":18,"role":"admin"}`), false},
		{"a schema that is not strict, and JSON that does not fit it", func(r *ChatRequest) {
			r.ResponseFormat = &ResponseFormat{Type: "json_schema", Schema: json.RawMessage(answerSchema)}
		}, turn(`{"city":"Paris"}`), true},
		{"a schema that is not strict, and prose", func(r *ChatRequest) {
			r.ResponseFormat = &ResponseFormat{Type: "json_schema", Schema: json.RawMessage(answerSchema)}
		}, turn("Paris, 18"), false},
		{"an answer cut short by its limit", strictly, ChatReply{Message: turn(`{"city":"Pa`).Message, Finish: "length"}, true},
		{"a call where the answer has a schema", strictly, turn("", "click"), true},
		{"a refusal where the answer has a schema", strictly,
			ChatReply{Message: ChatMessage{Role: "assistant", Refusal: "I cannot help with that."}}, true},
	} {
		r := clickRequest()
		c.change(&r)
		_, err := r.Honour(c.reply)
		if c.ok && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrNotHonoured) {
			t.Errorf("%s was passed: %v", c.name, err)
		}
	}
}

func strictly(r *ChatRequest) {
	r.ResponseFormat = &ResponseFormat{Type: "json_schema", Schema: json.RawMessage(answerSchema), Strict: true}
}

// A model declining to answer is read apart from its text, and sent on in
// a later turn as what it said.
func TestARefusalIsReadAndSentOnAsWhatTheModelSaid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":null,"refusal":"I cannot help with that."}}]}`)
	}))
	defer srv.Close()
	h := &HTTPModel{BaseURL: srv.URL, Model: "m", Client: srv.Client()}
	r, err := h.Chat(context.Background(), clickRequest())
	if err != nil || r.Message.Refusal != "I cannot help with that." || r.Message.Text() != "" {
		t.Fatalf("%+v %v", r, err)
	}
	b, _ := json.Marshal(r.Message)
	if !strings.Contains(string(b), `"content":"I cannot help with that."`) || strings.Contains(string(b), `"refusal"`) {
		t.Errorf("a refusal went on as %s", b)
	}
}
