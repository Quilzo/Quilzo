// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package modelapi

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
)

func TestAnOpenAIRequestIsReadAsOneConversation(t *testing.T) {
	req, err := ReadOpenAI(strings.NewReader(`{"model":"gpt-x","stream":true,"max_completion_tokens":300,
		"tool_choice":{"type":"function","function":{"name":"lookup"}},
		"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}],
		"messages":[{"role":"developer","content":"Be brief."},{"role":"user","content":[{"type":"text","text":"Hi"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if req.Model != "gpt-x" || !req.Stream || req.Chat.MaxTokens != 300 || req.Chat.ToolChoice != "required" ||
		len(req.Chat.Messages) != 2 || req.Chat.Messages[1].Text() != "Hi" {
		t.Errorf("%+v", req)
	}
	if _, err := ReadOpenAI(strings.NewReader(`{"messages":[{"role":"user","content":[{"type":"image_url",
		"image_url":{"url":"https://example.com/a.png"}}]}]}`)); err == nil {
		t.Error("a picture by its web address was accepted")
	}
}

func TestAnAnthropicRequestIsReadAsTheSameConversation(t *testing.T) {
	req, err := ReadAnthropic(strings.NewReader(`{"model":"claude-x","max_tokens":500,
		"system":[{"type":"text","text":"You file tickets."}],
		"tool_choice":{"type":"any"},
		"tools":[{"name":"file_ticket","description":"File one","input_schema":{"type":"object"}}],
		"messages":[
		 {"role":"user","content":"The printer is on fire"},
		 {"role":"assistant","content":[{"type":"thinking","thinking":"..."},{"type":"text","text":"Filing it."},
		   {"type":"tool_use","id":"tu_1","name":"file_ticket","input":{"title":"fire"}}]},
		 {"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","content":[{"type":"text","text":"T-9"}]},
		   {"type":"text","text":"Thanks"},
		   {"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := req.Chat
	roles := []string{}
	for _, m := range c.Messages {
		roles = append(roles, m.Role)
	}
	if strings.Join(roles, ",") != "system,user,assistant,tool,user" {
		t.Fatalf("roles %v", roles)
	}
	if c.Messages[0].Text() != "You file tickets." || c.MaxTokens != 500 || c.ToolChoice != "required" {
		t.Errorf("%+v", c)
	}
	a := c.Messages[2]
	if a.Text() != "Filing it." || len(a.ToolCalls) != 1 || a.ToolCalls[0].Function.Arguments != `{"title":"fire"}` {
		t.Errorf("the model's turn %+v", a)
	}
	if c.Messages[3].ToolCallID != "tu_1" || c.Messages[3].Text() != "T-9" || c.Messages[4].Images() != 1 {
		t.Errorf("the tool's result and what followed %+v %+v", c.Messages[3], c.Messages[4])
	}
	if len(c.Tools) != 1 || c.Tools[0].Function.Name != "file_ticket" {
		t.Errorf("tools %+v", c.Tools)
	}
	for name, body := range map[string]string{
		"a picture by its web address": `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://example.com/a.png"}}]}]}`,
		"a tool the provider runs":     `{"tools":[{"type":"web_search_20250305","name":"web_search"}],"messages":[{"role":"user","content":"hi"}]}`,
		"a document block":             `{"messages":[{"role":"user","content":[{"type":"document","source":{}}]}]}`,
		"a system role in the list":    `{"messages":[{"role":"system","content":"hi"}]}`,
	} {
		if _, err := ReadAnthropic(strings.NewReader(body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAnAnswerIsWrittenInTheShapeAskedFor(t *testing.T) {
	reply := assist.ChatReply{Message: assist.ChatMessage{Role: "assistant",
		Content: []assist.Part{{Type: "text", Text: "Filed."}},
		ToolCalls: []assist.ToolCall{{ID: "c1", Type: "function",
			Function: assist.FunctionCall{Name: "file_ticket", Arguments: `{"title":"fire"}`}}}},
		Usage: assist.Usage{In: 12, Out: 3}}

	w := httptest.NewRecorder()
	WriteAnthropic(w, "quilzo", Request{}, reply)
	var msg struct {
		Content []struct {
			Type, Text, Name string
			Input            map[string]any
		}
		StopReason string `json:"stop_reason"`
		Usage      struct {
			In  int `json:"input_tokens"`
			Out int `json:"output_tokens"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.Content) != 2 || msg.Content[1].Name != "file_ticket" || msg.Content[1].Input["title"] != "fire" ||
		msg.StopReason != "tool_use" || msg.Usage.In != 12 {
		t.Errorf("%s", w.Body)
	}

	w = httptest.NewRecorder()
	WriteAnthropic(w, "quilzo", Request{Stream: true}, reply)
	stream := w.Body.String()
	for _, e := range []string{"message_start", "content_block_start", "input_json_delta", "message_delta", "message_stop"} {
		if !strings.Contains(stream, e) {
			t.Errorf("the stream has no %s:\n%s", e, stream)
		}
	}

	w = httptest.NewRecorder()
	WriteOpenAI(w, "quilzo", Request{}, reply)
	var cc struct {
		Choices []struct {
			Finish  string `json:"finish_reason"`
			Message struct {
				ToolCalls []assist.ToolCall `json:"tool_calls"`
			}
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cc); err != nil || cc.Choices[0].Finish != "tool_calls" ||
		len(cc.Choices[0].Message.ToolCalls) != 1 {
		t.Errorf("%s %v", w.Body, err)
	}

	w = httptest.NewRecorder()
	AnthropicError(w, 429, "spent")
	if w.Code != 429 || !strings.Contains(w.Body.String(), "rate_limit_error") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

func TestAResponsesRequestIsReadAsTheSameConversation(t *testing.T) {
	req, err := ReadResponses(strings.NewReader(`{"model":"agent/x","instructions":"Be brief.","max_output_tokens":64,
		"tools":[{"type":"function","name":"get_weather","parameters":{"type":"object"}}],
		"input":[{"role":"user","content":"Weather in Paris?"},
		 {"type":"reasoning","id":"rs_1","summary":[]},
		 {"type":"message","role":"assistant","content":[{"type":"output_text","text":"Looking."}]},
		 {"type":"function_call","call_id":"c1","name":"get_weather","arguments":"{\"city\":\"Paris\"}"},
		 {"type":"function_call_output","call_id":"c1","output":"18C"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := req.Chat
	roles := []string{}
	for _, m := range c.Messages {
		roles = append(roles, m.Role)
	}
	if strings.Join(roles, ",") != "system,user,assistant,tool" || c.Messages[2].Text() != "Looking." ||
		len(c.Messages[2].ToolCalls) != 1 || c.Messages[3].ToolCallID != "c1" || c.MaxTokens != 64 || len(c.Tools) != 1 {
		t.Fatalf("%+v", c)
	}
	if r, err := ReadResponses(strings.NewReader(`{"input":"hi"}`)); err != nil || r.Chat.Messages[0].Text() != "hi" {
		t.Errorf("%+v %v", r, err)
	}
	for name, body := range map[string]string{
		"a conversation kept elsewhere": `{"input":"hi","previous_response_id":"resp_1"}`,
		"a tool the provider runs":      `{"input":"hi","tools":[{"type":"web_search"}]}`,
	} {
		if _, err := ReadResponses(strings.NewReader(body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	w := httptest.NewRecorder()
	WriteResponses(w, "quilzo", Request{Stream: true}, assist.ChatReply{Message: assist.ChatMessage{Role: "assistant",
		ToolCalls: []assist.ToolCall{{ID: "c2", Type: "function", Function: assist.FunctionCall{Name: "get_weather", Arguments: "{}"}}}}})
	for _, e := range []string{"response.created", "response.function_call_arguments.done", "response.completed"} {
		if !strings.Contains(w.Body.String(), "event: "+e+"\n") {
			t.Errorf("the stream has no %s", e)
		}
	}
}
