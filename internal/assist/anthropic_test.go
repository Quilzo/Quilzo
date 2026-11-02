// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// anthropicAt is a model speaking Anthropic's Messages API at a test
// server, which hands each request to see and answers with answer.
func anthropicAt(t *testing.T, answer func(w http.ResponseWriter, body map[string]any)) (*HTTPModel, chan *http.Request) {
	t.Helper()
	seen := make(chan *http.Request, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(b, &body); err != nil {
			t.Errorf("the body is not JSON: %s", b)
		}
		r2 := r.Clone(context.Background())
		r2.Body = io.NopCloser(strings.NewReader(string(b)))
		seen <- r2
		answer(w, body)
	}))
	t.Cleanup(srv.Close)
	return &HTTPModel{BaseURL: srv.URL + "/v1", APIKey: "sk-ant-test", Model: "claude-test", Client: srv.Client(),
		Auth: "header:x-api-key", Wire: WireAnthropic}, seen
}

func bodyOf(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

const onePixel = "data:image/png;base64,iVBORw0KGgo="

// A conversation goes as the Messages API takes it: the system prompt in
// its own field, a picture as a base64 block, a tool call as tool_use, a
// tool's results in the next user turn together, the key in x-api-key and
// the version this speaks; and a thinking block in the answer is not
// passed on.
func TestAConversationIsSentAsTheMessagesAPITakesIt(t *testing.T) {
	m, seen := anthropicAt(t, func(w http.ResponseWriter, _ map[string]any) {
		w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-test",
			"content":[{"type":"thinking","thinking":"","signature":"sig"},
				{"type":"text","text":"Checking the "},{"type":"text","text":"calendar."},
				{"type":"tool_use","id":"toolu_2","name":"calendar","input":{"day":"monday"}}],
			"stop_reason":"tool_use",
			"usage":{"input_tokens":100,"output_tokens":20,"cache_creation_input_tokens":5,"cache_read_input_tokens":7}}`))
	})
	m.Params.Temperature = new(float64) // never sent on this wire
	req := ChatRequest{MaxTokens: 1024, ToolChoice: "auto", Messages: []ChatMessage{
		{Role: "system", Content: []Part{{Type: "text", Text: "Be brief."}}},
		{Role: "developer", Content: []Part{{Type: "text", Text: "Use the tools."}}},
		{Role: "user", Content: []Part{{Type: "text", Text: "What is on?"}, {Type: "image_url", ImageURL: &ImageURL{URL: onePixel}}}},
		{Role: "assistant", ToolCalls: []ToolCall{
			{ID: "toolu_1", Type: "function", Function: FunctionCall{Name: "calendar", Arguments: `{"day":"sunday"}`}},
			{ID: "toolu_0", Type: "function", Function: FunctionCall{Name: "weather", Arguments: ``}}}},
		{Role: "tool", ToolCallID: "toolu_1", Content: []Part{{Type: "text", Text: "nothing"}}},
		{Role: "tool", ToolCallID: "toolu_0", Content: []Part{{Type: "text", Text: "sun"}}},
		{Role: "user", Content: []Part{{Type: "text", Text: "And monday?"}}},
	}, Tools: []ChatTool{
		{Type: "function", Function: ToolFunction{Name: "calendar", Description: "What is on a day",
			Parameters: json.RawMessage(`{"type":"object","properties":{"day":{"type":"string"}}}`)}},
		{Type: "function", Function: ToolFunction{Name: "weather"}},
	}}
	reply, err := m.Chat(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	r := <-seen
	if r.URL.Path != "/v1/messages" || r.Header.Get("X-Api-Key") != "sk-ant-test" || r.Header.Get("Authorization") != "" ||
		r.Header.Get("Anthropic-Version") != AnthropicVersion || r.Header.Get("Anthropic-Beta") != "" {
		t.Fatalf("%s %v", r.URL.Path, r.Header)
	}
	body := bodyOf(t, r)
	for _, f := range []string{"temperature", "top_p", "top_k", "stream", "output_config", "inference_geo", "fallbacks"} {
		if _, ok := body[f]; ok {
			t.Errorf("%s was sent: %v", f, body[f])
		}
	}
	if body["system"] != "Be brief.\n\nUse the tools." || body["max_tokens"] != float64(AnthropicMinMaxTokens) ||
		body["model"] != "claude-test" {
		t.Errorf("%v %v %v", body["system"], body["max_tokens"], body["model"])
	}
	want := `[{"content":[{"text":"What is on?","type":"text"},{"source":{"data":"iVBORw0KGgo=","media_type":"image/png","type":"base64"},"type":"image"}],"role":"user"},` +
		`{"content":[{"id":"toolu_1","input":{"day":"sunday"},"name":"calendar","type":"tool_use"},{"id":"toolu_0","input":{},"name":"weather","type":"tool_use"}],"role":"assistant"},` +
		`{"content":[{"content":"nothing","tool_use_id":"toolu_1","type":"tool_result"},{"content":"sun","tool_use_id":"toolu_0","type":"tool_result"},{"text":"And monday?","type":"text"}],"role":"user"}]`
	if got := asJSON(body["messages"]); got != want {
		t.Errorf("messages:\n%s\nwant\n%s", got, want)
	}
	if got := asJSON(body["tools"]); got != `[{"description":"What is on a day","input_schema":{"properties":{"day":{"type":"string"}},"type":"object"},"name":"calendar"},{"input_schema":{"properties":{},"type":"object"},"name":"weather"}]` {
		t.Errorf("tools: %s", got)
	}
	if got := asJSON(body["tool_choice"]); got != `{"type":"auto"}` {
		t.Errorf("tool_choice: %s", got)
	}
	if reply.Message.Text() != "Checking the calendar." || reply.Finish != "tool_calls" || len(reply.Message.ToolCalls) != 1 {
		t.Fatalf("%+v", reply)
	}
	c := reply.Message.ToolCalls[0]
	if c.ID != "toolu_2" || c.Type != "function" || c.Function.Name != "calendar" || c.Function.Arguments != `{"day":"monday"}` {
		t.Errorf("%+v", c)
	}
	if reply.Usage != (Usage{In: 112, Out: 20, Reported: true}) {
		t.Errorf("usage %+v", reply.Usage)
	}
}

// A forced choice goes as the Messages API writes one, unless the route
// says its model refuses a forced choice; a limit above the most any
// model writes is lowered to it.
func TestAToolChoiceAndALimitGoAsTheAPITakesThem(t *testing.T) {
	m, seen := anthropicAt(t, func(w http.ResponseWriter, _ map[string]any) {
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	})
	tools := []ChatTool{{Type: "function", Function: ToolFunction{Name: "a"}}, {Type: "function", Function: ToolFunction{Name: "b"}}}
	msgs := []ChatMessage{{Role: "user", Content: []Part{{Type: "text", Text: "go"}}}}
	for _, c := range []struct {
		choice, name string
		auto         bool
		want         string
	}{
		{"required", "", false, `{"type":"any"}`},
		{"required", "b", false, `{"name":"b","type":"tool"}`},
		{"required", "b", true, `{"type":"auto"}`},
		{"none", "", false, `{"type":"none"}`},
		{"", "", false, `null`},
	} {
		m.Params.AutoToolChoice = c.auto
		if _, err := m.Chat(context.Background(), ChatRequest{Messages: msgs, Tools: tools, ToolChoice: c.choice, ToolChoiceName: c.name}); err != nil {
			t.Fatal(err)
		}
		body := bodyOf(t, <-seen)
		if got := asJSON(body["tool_choice"]); got != c.want {
			t.Errorf("%+v: %s", c, got)
		}
		if body["max_tokens"] != float64(AnthropicDefaultMaxTokens) {
			t.Errorf("no limit asked for: %v", body["max_tokens"])
		}
	}
}

// What a route chooses for Anthropic's models is sent when it is set,
// and the fallback with the beta it needs, beside any the profile names.
func TestEffortGeoAndFallbackAreSentWhenSet(t *testing.T) {
	m, seen := anthropicAt(t, func(w http.ResponseWriter, _ map[string]any) {
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	})
	m.Params = Params{Effort: "high", Geo: "us", Fallback: true}
	m.Headers = map[string]string{"anthropic-beta": "some-beta-2026-01-01", "anthropic-version": "2023-06-01"}
	if out, u, err := m.CompleteMetered(context.Background(), "be brief", "hi"); err != nil || out != "ok" || !u.Reported {
		t.Fatalf("%q %+v %v", out, u, err)
	}
	r := <-seen
	if r.Header.Get("Anthropic-Beta") != "some-beta-2026-01-01,"+anthropicFallbackBeta ||
		r.Header.Get("Anthropic-Version") != "2023-06-01" {
		t.Errorf("a profile's headers were not kept: %v", r.Header)
	}
	body := bodyOf(t, r)
	if asJSON(body["output_config"]) != `{"effort":"high"}` || body["inference_geo"] != "us" || body["fallbacks"] != "default" ||
		body["system"] != "be brief" {
		t.Errorf("%v", body)
	}
}

// A request the model's safeguards stop is Declined, with the reason the
// provider gave: not an empty answer a chatbot would show as one.
func TestARefusalIsDeclinedNotAnEmptyAnswer(t *testing.T) {
	m, _ := anthropicAt(t, func(w http.ResponseWriter, _ map[string]any) {
		w.Write([]byte(`{"model":"claude-test","content":[],"stop_reason":"refusal",
			"stop_details":{"type":"refusal","category":"cyber","explanation":"x"},"usage":{"input_tokens":9,"output_tokens":0}}`))
	})
	_, err := m.Complete(context.Background(), "s", "u")
	var d *Declined
	if !errors.As(err, &d) || d.Category != "cyber" || d.Model != "claude-test" || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("%v", err)
	}
}

// A provider's error status is a StatusError as from any provider, so the
// gateway judges it the same way.
func TestAnAnthropicErrorIsAStatusError(t *testing.T) {
	m, _ := anthropicAt(t, func(w http.ResponseWriter, _ map[string]any) {
		w.WriteHeader(529)
		w.Write([]byte(`{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`))
	})
	_, err := m.Complete(context.Background(), "s", "u")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 529 || !strings.Contains(se.Body, "overloaded_error") {
		t.Fatalf("%v", err)
	}
}

// sse writes server-sent events as the Messages API streams them.
func sse(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range events {
		var head struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal([]byte(e), &head)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", head.Type, e)
	}
}

var streamedTurn = []string{
	`{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[],"stop_reason":null,"usage":{"input_tokens":50,"output_tokens":1,"cache_read_input_tokens":10}}}`,
	`{"type":"ping"}`,
	`{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
	`{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}`,
	`{"type":"content_block_stop","index":0}`,
	`{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`,
	`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Here is "}}`,
	`{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"the plan."}}`,
	`{"type":"content_block_stop","index":1}`,
	`{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_9","name":"write_page","input":{}}}`,
	`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"title\": \"Ho"}}`,
	`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"me\"}"}}`,
	`{"type":"content_block_stop","index":2}`,
	`{"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":42}}`,
	`{"type":"message_stop"}`,
}

// A request that may write at length is streamed, and the stream read
// whole: text from its deltas, a tool call's arguments from its pieces,
// the usage from its start and its end.
func TestALongAnswerIsStreamedAndReadWhole(t *testing.T) {
	m, seen := anthropicAt(t, func(w http.ResponseWriter, body map[string]any) {
		if body["stream"] != true {
			t.Errorf("a long answer was not streamed: %v", body["stream"])
		}
		sse(w, streamedTurn...)
	})
	reply, err := m.Chat(context.Background(), ChatRequest{MaxTokens: 64000,
		Messages: []ChatMessage{{Role: "user", Content: []Part{{Type: "text", Text: "plan the site"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	r := <-seen
	if r.Header.Get("Accept") != "text/event-stream" || bodyOf(t, r)["max_tokens"] != float64(64000) {
		t.Errorf("%v", r.Header)
	}
	if reply.Message.Text() != "Here is the plan." || reply.Finish != "tool_calls" || len(reply.Message.ToolCalls) != 1 ||
		reply.Message.ToolCalls[0].Function.Arguments != `{"title": "Home"}` || reply.Message.ToolCalls[0].ID != "toolu_9" {
		t.Fatalf("%+v", reply)
	}
	if reply.Usage != (Usage{In: 60, Out: 42, Reported: true}) {
		t.Errorf("usage %+v", reply.Usage)
	}
}

// A stream that fails says how, as the status it stands for; one cut
// short is an error, not the half of an answer it carried; one that
// refuses mid-way is Declined.
func TestAStreamThatFailsIsAnError(t *testing.T) {
	ask := ChatRequest{MaxTokens: 32000, Messages: []ChatMessage{{Role: "user", Content: []Part{{Type: "text", Text: "go"}}}}}
	for name, c := range map[string]struct {
		events []string
		check  func(error) bool
	}{
		"overloaded": {append(streamedTurn[:2:2], `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`),
			func(err error) bool {
				var se *StatusError
				return errors.As(err, &se) && se.Code == 529
			}},
		"cut short": {streamedTurn[:8], func(err error) bool { return err != nil && strings.Contains(err.Error(), "ended") }},
		"bad arguments": {append(append([]string{}, streamedTurn[:10]...),
			`{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"ti"}}`,
			`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":3}}`, `{"type":"message_stop"}`),
			func(err error) bool { return err != nil && strings.Contains(err.Error(), "not JSON") }},
		"too many blocks": {[]string{streamedTurn[0], `{"type":"content_block_start","index":5000,"content_block":{"type":"text","text":""}}`},
			func(err error) bool { return err != nil && strings.Contains(err.Error(), "blocks") }},
		"refused": {[]string{streamedTurn[0],
			`{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":"bio"}},"usage":{"output_tokens":0}}`,
			`{"type":"message_stop"}`},
			func(err error) bool {
				var d *Declined
				return errors.As(err, &d) && d.Category == "bio"
			}},
	} {
		m, _ := anthropicAt(t, func(w http.ResponseWriter, _ map[string]any) { sse(w, c.events...) })
		reply, err := m.Chat(context.Background(), ask)
		if !c.check(err) {
			t.Errorf("%s: %+v %v", name, reply, err)
		}
	}
}

// What the Messages API cannot carry is refused before anything is sent:
// a tool call whose arguments are not an object, a result naming no call,
// a conversation with nothing in it but a system prompt.
func TestWhatTheMessagesAPICannotCarryIsRefused(t *testing.T) {
	m, seen := anthropicAt(t, func(w http.ResponseWriter, _ map[string]any) { t.Error("sent") })
	for name, msgs := range map[string][]ChatMessage{
		"array arguments": {{Role: "user", Content: []Part{{Type: "text", Text: "go"}}},
			{Role: "assistant", ToolCalls: []ToolCall{{ID: "t1", Type: "function", Function: FunctionCall{Name: "a", Arguments: `[1]`}}}}},
		"no call id":    {{Role: "user", Content: []Part{{Type: "text", Text: "go"}}}, {Role: "tool", Content: []Part{{Type: "text", Text: "x"}}}},
		"only a system": {{Role: "system", Content: []Part{{Type: "text", Text: "be brief"}}}},
		"only space":    {{Role: "user", Content: []Part{{Type: "text", Text: "  \n"}}}},
	} {
		if _, err := m.Chat(context.Background(), ChatRequest{Messages: msgs}); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if len(seen) != 0 {
		t.Error("a refused conversation reached the provider")
	}
	if _, err := m.Paint(context.Background(), "a cat", ""); err == nil {
		t.Error("a model that answers in words was asked to draw")
	}
}
