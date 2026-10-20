// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package modelapi

import (
	"strings"
	"testing"
)

// A choice naming one tool stays that tool in every shape the door reads,
// where it used to be widened to any tool, so a model could call one the
// caller had not asked for.
func TestANamedToolChoiceStaysNamedInEveryShape(t *testing.T) {
	open, err := ReadOpenAI(strings.NewReader(`{"model":"m","tool_choice":{"type":"function","function":{"name":"lookup"}},
		"tools":[{"type":"function","function":{"name":"lookup"}},{"type":"function","function":{"name":"delete"}}],
		"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil || open.Chat.ToolChoice != "required" || open.Chat.ToolChoiceName != "lookup" {
		t.Errorf("openai: %+v %v", open.Chat, err)
	}
	resp, err := ReadResponses(strings.NewReader(`{"model":"m","input":"hi","tool_choice":{"type":"function","name":"lookup"},
		"tools":[{"type":"function","name":"lookup"},{"type":"function","name":"delete"}]}`))
	if err != nil || resp.Chat.ToolChoice != "required" || resp.Chat.ToolChoiceName != "lookup" {
		t.Errorf("responses: %+v %v", resp.Chat, err)
	}
	anth, err := ReadAnthropic(strings.NewReader(`{"model":"m","max_tokens":10,"tool_choice":{"type":"tool","name":"lookup"},
		"tools":[{"name":"lookup","input_schema":{"type":"object"}},{"name":"delete","input_schema":{"type":"object"}}],
		"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil || anth.Chat.ToolChoice != "required" || anth.Chat.ToolChoiceName != "lookup" {
		t.Errorf("anthropic: %+v %v", anth.Chat, err)
	}
	any, err := ReadAnthropic(strings.NewReader(`{"model":"m","max_tokens":10,"tool_choice":{"type":"any"},
		"tools":[{"name":"lookup","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil || any.Chat.ToolChoice != "required" || any.Chat.ToolChoiceName != "" {
		t.Errorf("anthropic any: %+v %v", any.Chat, err)
	}
	// A choice of a tool the request does not offer is refused, not sent.
	if _, err := ReadAnthropic(strings.NewReader(`{"model":"m","max_tokens":10,"tool_choice":{"type":"tool","name":"wipe"},
		"tools":[{"name":"lookup","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"hi"}]}`)); err == nil {
		t.Error("a choice of a tool not offered was accepted")
	}
	if _, err := ReadOpenAI(strings.NewReader(`{"model":"m","tool_choice":{"type":"function","function":{"name":"wipe"}},
		"tools":[{"type":"function","function":{"name":"lookup"}}],"messages":[{"role":"user","content":"hi"}]}`)); err == nil {
		t.Error("openai: a choice of a tool not offered was accepted")
	}
}
