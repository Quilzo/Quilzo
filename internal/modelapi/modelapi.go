// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package modelapi reads and writes the shapes an agent framework speaks
// to a model: OpenAI's chat completions and responses, and Anthropic's
// messages.
//
// Each is read into one conversation (internal/assist's ChatRequest), so
// what answers them, the model gateway, never knows which shape a caller
// used, and an agent built for either provider is pointed at Quilzo by
// changing its base address and its key, nothing else.
//
// What neither shape can carry through here is refused rather than
// dropped: a picture given as a web address (the provider would fetch it
// from wherever it points), a part of a kind this does not send, a tool
// that is not a function. An agent told its picture was ignored can do
// something about it; one whose picture silently vanished answers about a
// picture it never saw.
//
// An answer is written whole. A request that asked for a stream gets the
// whole answer as one stream, in the events its shape expects, which
// every client that asked for a stream reads.
package modelapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
)

// MaxRequest is the most a request may be: room for a few screens, since
// a picture is a few hundred kilobytes encoded and assist.ChatRequest.Check
// bounds how many there may be.
const MaxRequest = 24 << 20

// Request is a conversation as either shape asked for it.
type Request struct {
	// Model is the model the caller named, which is its own business:
	// the gateway decides which route answers.
	Model  string
	Chat   assist.ChatRequest
	Stream bool
}

// OpenAI's chat completions.

type openaiRequest struct {
	Model               string               `json:"model"`
	Messages            []assist.ChatMessage `json:"messages"`
	Tools               []assist.ChatTool    `json:"tools"`
	ToolChoice          json.RawMessage      `json:"tool_choice"`
	MaxTokens           int                  `json:"max_tokens"`
	MaxCompletionTokens int                  `json:"max_completion_tokens"`
	Stream              bool                 `json:"stream"`
}

// ReadOpenAI reads a chat completion request.
func ReadOpenAI(r io.Reader) (Request, error) {
	var in openaiRequest
	if err := json.NewDecoder(io.LimitReader(r, MaxRequest)).Decode(&in); err != nil {
		return Request{}, fmt.Errorf("the request is not a chat completion: %w", err)
	}
	out := Request{Model: in.Model, Stream: in.Stream, Chat: assist.ChatRequest{
		Messages: in.Messages, Tools: in.Tools, MaxTokens: in.MaxTokens}}
	if out.Chat.MaxTokens == 0 {
		out.Chat.MaxTokens = in.MaxCompletionTokens
	}
	if len(in.ToolChoice) > 0 {
		// A choice naming one function is read as "required", which is
		// what it asks for in every case this can honour.
		var s string
		if json.Unmarshal(in.ToolChoice, &s) == nil {
			out.Chat.ToolChoice = s
		} else {
			out.Chat.ToolChoice = "required"
		}
	}
	if err := out.Chat.Check(); err != nil {
		return Request{}, err
	}
	return out, nil
}

// WriteOpenAI writes the model's turn as a chat completion.
func WriteOpenAI(w http.ResponseWriter, model string, reply assist.ChatReply, stream bool) {
	text, calls := reply.Message.Text(), reply.Message.ToolCalls
	finish := reply.Finish
	if finish == "" {
		finish = "stop"
		if len(calls) > 0 {
			finish = "tool_calls"
		}
	}
	id := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	in, out := reply.Usage.In, reply.Usage.Out
	usage := map[string]int{"prompt_tokens": in, "completion_tokens": out, "total_tokens": in + out}
	message := map[string]any{"role": "assistant", "content": text}
	if len(calls) > 0 {
		message["tool_calls"] = calls
		if text == "" {
			message["content"] = nil
		}
	}
	if stream {
		// A stream's tool calls carry their position.
		delta := map[string]any{"role": "assistant", "content": message["content"]}
		if len(calls) > 0 {
			indexed := make([]map[string]any, len(calls))
			for i, c := range calls {
				indexed[i] = map[string]any{"index": i, "id": c.ID, "type": c.Type, "function": c.Function}
			}
			delta["tool_calls"] = indexed
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		chunk := map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": model,
			"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
			"usage":   usage}
		b, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", b)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "object": "chat.completion", "created": time.Now().Unix(),
		"model": model, "usage": usage,
		"choices": []any{map[string]any{"index": 0, "finish_reason": finish, "message": message}}})
}

// OpenAIError writes a refusal as an OpenAI client reads one.
func OpenAIError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": msg, "type": "quilzo"}})
}

// WriteModels lists the models a caller may name.
func WriteModels(w http.ResponseWriter, names []string) {
	data := make([]any, 0, len(names))
	for _, n := range names {
		data = append(data, map[string]any{"id": n, "object": "model", "owned_by": "quilzo"})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
}

// Anthropic's messages.

type anthropicRequest struct {
	Model      string             `json:"model"`
	System     json.RawMessage    `json:"system"`
	Messages   []anthropicMessage `json:"messages"`
	Tools      []anthropicTool    `json:"tools"`
	ToolChoice *struct {
		Type string `json:"type"`
	} `json:"tool_choice"`
	MaxTokens int  `json:"max_tokens"`
	Stream    bool `json:"stream"`
}

type anthropicMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	// Type is set only on a tool the provider runs itself (a web search,
	// a computer), which nothing here can run.
	Type string `json:"type"`
}

type anthropicBlock struct {
	Type   string `json:"type"`
	Text   string `json:"text"`
	Source *struct {
		Type      string `json:"type"`
		MediaType string `json:"media_type"`
		Data      string `json:"data"`
	} `json:"source"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

// blocks reads content given as a string or as a list of blocks.
func blocks(raw json.RawMessage) ([]anthropicBlock, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []anthropicBlock{{Type: "text", Text: s}}, nil
	}
	var out []anthropicBlock
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.New("a message's content is text or a list of blocks")
	}
	return out, nil
}

// part is a text or picture block as a part of a message.
func part(b anthropicBlock) (assist.Part, error) {
	switch b.Type {
	case "text":
		return assist.Part{Type: "text", Text: b.Text}, nil
	case "image":
		if b.Source == nil || b.Source.Type != "base64" {
			return assist.Part{}, errors.New("a picture is sent as base64 data, never as a web address: " +
				"the provider would fetch it from wherever it points")
		}
		return assist.Part{Type: "image_url", ImageURL: &assist.ImageURL{
			URL: "data:" + b.Source.MediaType + ";base64," + b.Source.Data}}, nil
	}
	return assist.Part{}, fmt.Errorf("%q is not a block this sends; text, image, tool_use and tool_result are", b.Type)
}

// ReadAnthropic reads a messages request.
func ReadAnthropic(r io.Reader) (Request, error) {
	var in anthropicRequest
	if err := json.NewDecoder(io.LimitReader(r, MaxRequest)).Decode(&in); err != nil {
		return Request{}, fmt.Errorf("the request is not a messages request: %w", err)
	}
	out := Request{Model: in.Model, Stream: in.Stream, Chat: assist.ChatRequest{MaxTokens: in.MaxTokens}}
	system, err := blocks(in.System)
	if err != nil {
		return Request{}, fmt.Errorf("system: %w", err)
	}
	var sys strings.Builder
	for _, b := range system {
		if b.Type != "text" {
			return Request{}, errors.New("the system prompt is text")
		}
		if sys.Len() > 0 {
			sys.WriteString("\n")
		}
		sys.WriteString(b.Text)
	}
	if sys.Len() > 0 {
		out.Chat.Messages = append(out.Chat.Messages, assist.ChatMessage{Role: "system",
			Content: []assist.Part{{Type: "text", Text: sys.String()}}})
	}
	for _, m := range in.Messages {
		bs, err := blocks(m.Content)
		if err != nil {
			return Request{}, err
		}
		switch m.Role {
		case "user":
			// A tool's results come first, each its own message, as the
			// other shape carries them; what the person said follows.
			var said []assist.Part
			for _, b := range bs {
				if b.Type != "tool_result" {
					p, err := part(b)
					if err != nil {
						return Request{}, err
					}
					said = append(said, p)
					continue
				}
				result, err := blocks(b.Content)
				if err != nil {
					return Request{}, fmt.Errorf("a tool's result: %w", err)
				}
				var text strings.Builder
				if b.IsError {
					text.WriteString("(the tool failed) ")
				}
				for _, rb := range result {
					if rb.Type != "text" {
						return Request{}, errors.New("a tool's result is passed on as text only")
					}
					text.WriteString(rb.Text)
				}
				out.Chat.Messages = append(out.Chat.Messages, assist.ChatMessage{Role: "tool", ToolCallID: b.ToolUseID,
					Content: []assist.Part{{Type: "text", Text: text.String()}}})
			}
			if len(said) > 0 {
				out.Chat.Messages = append(out.Chat.Messages, assist.ChatMessage{Role: "user", Content: said})
			}
		case "assistant":
			msg := assist.ChatMessage{Role: "assistant"}
			for _, b := range bs {
				switch b.Type {
				case "text":
					msg.Content = append(msg.Content, assist.Part{Type: "text", Text: b.Text})
				case "thinking", "redacted_thinking":
					// The model's own reasoning from an earlier turn, which
					// another route could not read and does not need.
				case "tool_use":
					args := string(b.Input)
					if args == "" || args == "null" {
						args = "{}"
					}
					msg.ToolCalls = append(msg.ToolCalls, assist.ToolCall{ID: b.ID, Type: "function",
						Function: assist.FunctionCall{Name: b.Name, Arguments: args}})
				default:
					return Request{}, fmt.Errorf("%q is not a block this sends in the model's turn", b.Type)
				}
			}
			out.Chat.Messages = append(out.Chat.Messages, msg)
		default:
			return Request{}, fmt.Errorf("%q is not a role here: user or assistant, with the system prompt apart", m.Role)
		}
	}
	for _, t := range in.Tools {
		if t.Type != "" && t.Type != "custom" {
			return Request{}, fmt.Errorf("%s is a tool the provider runs itself, and nothing here runs it", t.Name)
		}
		out.Chat.Tools = append(out.Chat.Tools, assist.ChatTool{Type: "function",
			Function: assist.ToolFunction{Name: t.Name, Description: t.Description, Parameters: t.InputSchema}})
	}
	if c := in.ToolChoice; c != nil {
		switch c.Type {
		case "auto", "none":
			out.Chat.ToolChoice = c.Type
		case "any", "tool":
			out.Chat.ToolChoice = "required"
		default:
			return Request{}, fmt.Errorf("tool_choice is auto, any, tool or none, not %q", c.Type)
		}
	}
	if err := out.Chat.Check(); err != nil {
		return Request{}, err
	}
	return out, nil
}

// WriteAnthropic writes the model's turn as a message.
func WriteAnthropic(w http.ResponseWriter, model string, reply assist.ChatReply, stream bool) {
	content := []map[string]any{}
	if text := reply.Message.Text(); text != "" {
		content = append(content, map[string]any{"type": "text", "text": text})
	}
	for _, c := range reply.Message.ToolCalls {
		input := json.RawMessage(c.Function.Arguments)
		if !json.Valid(input) {
			input = json.RawMessage("{}")
		}
		content = append(content, map[string]any{"type": "tool_use", "id": c.ID, "name": c.Function.Name, "input": input})
	}
	stop := "end_turn"
	switch {
	case len(reply.Message.ToolCalls) > 0:
		stop = "tool_use"
	case reply.Finish == "length":
		stop = "max_tokens"
	}
	id := fmt.Sprintf("msg_%d", time.Now().UnixNano())
	usage := map[string]int{"input_tokens": reply.Usage.In, "output_tokens": reply.Usage.Out}
	msg := map[string]any{"id": id, "type": "message", "role": "assistant", "model": model,
		"content": content, "stop_reason": stop, "stop_sequence": nil, "usage": usage}
	w.Header().Set("Cache-Control", "no-store")
	if !stream {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(msg)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	event := func(name string, v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, b)
	}
	start := map[string]any{}
	for k, v := range msg {
		start[k] = v
	}
	start["content"], start["stop_reason"] = []any{}, nil
	start["usage"] = map[string]int{"input_tokens": reply.Usage.In, "output_tokens": 0}
	event("message_start", map[string]any{"type": "message_start", "message": start})
	for i, c := range content {
		first := map[string]any{}
		var delta map[string]any
		for k, v := range c {
			first[k] = v
		}
		if c["type"] == "text" {
			first["text"] = ""
			delta = map[string]any{"type": "text_delta", "text": c["text"]}
		} else {
			first["input"] = map[string]any{}
			delta = map[string]any{"type": "input_json_delta", "partial_json": string(c["input"].(json.RawMessage))}
		}
		event("content_block_start", map[string]any{"type": "content_block_start", "index": i, "content_block": first})
		event("content_block_delta", map[string]any{"type": "content_block_delta", "index": i, "delta": delta})
		event("content_block_stop", map[string]any{"type": "content_block_stop", "index": i})
	}
	event("message_delta", map[string]any{"type": "message_delta",
		"delta": map[string]any{"stop_reason": stop, "stop_sequence": nil},
		"usage": map[string]int{"output_tokens": reply.Usage.Out}})
	event("message_stop", map[string]any{"type": "message_stop"})
}

// AnthropicError writes a refusal as an Anthropic client reads one.
func AnthropicError(w http.ResponseWriter, code int, msg string) {
	kind := "api_error"
	switch code {
	case http.StatusBadRequest:
		kind = "invalid_request_error"
	case http.StatusUnauthorized:
		kind = "authentication_error"
	case http.StatusForbidden:
		kind = "permission_error"
	case http.StatusNotFound:
		kind = "not_found_error"
	case http.StatusTooManyRequests:
		kind = "rate_limit_error"
	case http.StatusServiceUnavailable:
		kind = "overloaded_error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]any{"type": kind, "message": msg}})
}

// WriteAnthropicModels lists the models a caller may name, as an
// Anthropic client reads the list.
func WriteAnthropicModels(w http.ResponseWriter, names []string) {
	data := make([]any, 0, len(names))
	for _, n := range names {
		data = append(data, map[string]any{"type": "model", "id": n, "display_name": n,
			"created_at": "1970-01-01T00:00:00Z"})
	}
	first, last := "", ""
	if len(names) > 0 {
		first, last = names[0], names[len(names)-1]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "has_more": false, "first_id": first, "last_id": last})
}

// OpenAI's responses.
//
// The newer of OpenAI's two shapes, and the one its own agent SDK speaks
// by default. Served without keeping anything: a request that continues a
// response kept on the far side (previous_response_id, conversation) is
// refused, since nothing here keeps conversations, and the client is told
// to send the whole of it, as every SDK can.

type responsesRequest struct {
	Model              string          `json:"model"`
	Instructions       string          `json:"instructions"`
	Input              json.RawMessage `json:"input"`
	Tools              []responsesTool `json:"tools"`
	ToolChoice         json.RawMessage `json:"tool_choice"`
	MaxOutputTokens    int             `json:"max_output_tokens"`
	Stream             bool            `json:"stream"`
	PreviousResponseID string          `json:"previous_response_id"`
	Conversation       json.RawMessage `json:"conversation"`
}

type responsesTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type responsesItem struct {
	Type      string          `json:"type"`
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	CallID    string          `json:"call_id"`
	Name      string          `json:"name"`
	Arguments string          `json:"arguments"`
	Output    json.RawMessage `json:"output"`
}

type responsesPart struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	Refusal  string `json:"refusal"`
	ImageURL string `json:"image_url"`
}

// responsesParts reads an item's content: a string or a list of parts.
func responsesParts(raw json.RawMessage) ([]assist.Part, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []assist.Part{{Type: "text", Text: s}}, nil
	}
	var parts []responsesPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return nil, errors.New("an item's content is text or a list of parts")
	}
	var out []assist.Part
	for _, p := range parts {
		switch p.Type {
		case "input_text", "output_text", "text":
			out = append(out, assist.Part{Type: "text", Text: p.Text})
		case "refusal":
			out = append(out, assist.Part{Type: "text", Text: p.Refusal})
		case "input_image":
			out = append(out, assist.Part{Type: "image_url", ImageURL: &assist.ImageURL{URL: p.ImageURL}})
		default:
			return nil, fmt.Errorf("%q is not a part this sends; text and pictures are", p.Type)
		}
	}
	return out, nil
}

// ReadResponses reads a responses request.
func ReadResponses(r io.Reader) (Request, error) {
	var in responsesRequest
	if err := json.NewDecoder(io.LimitReader(r, MaxRequest)).Decode(&in); err != nil {
		return Request{}, fmt.Errorf("the request is not a responses request: %w", err)
	}
	if in.PreviousResponseID != "" || (len(in.Conversation) > 0 && string(in.Conversation) != "null") {
		return Request{}, errors.New("nothing here keeps conversations: send the whole conversation as input, " +
			"without previous_response_id or conversation")
	}
	out := Request{Model: in.Model, Stream: in.Stream, Chat: assist.ChatRequest{MaxTokens: in.MaxOutputTokens}}
	if in.Instructions != "" {
		out.Chat.Messages = append(out.Chat.Messages, assist.ChatMessage{Role: "system",
			Content: []assist.Part{{Type: "text", Text: in.Instructions}}})
	}
	var items []responsesItem
	var s string
	switch {
	case json.Unmarshal(in.Input, &s) == nil:
		items = []responsesItem{{Type: "message", Role: "user", Content: in.Input}}
	case json.Unmarshal(in.Input, &items) != nil:
		return Request{}, errors.New("input is text or a list of items")
	}
	for _, it := range items {
		switch it.Type {
		case "", "message":
			parts, err := responsesParts(it.Content)
			if err != nil {
				return Request{}, err
			}
			out.Chat.Messages = append(out.Chat.Messages, assist.ChatMessage{Role: it.Role, Content: parts})
		case "function_call":
			// Calls the model made together are one turn.
			n := len(out.Chat.Messages)
			if n == 0 || out.Chat.Messages[n-1].Role != "assistant" {
				out.Chat.Messages = append(out.Chat.Messages, assist.ChatMessage{Role: "assistant"})
				n++
			}
			args := it.Arguments
			if args == "" {
				args = "{}"
			}
			last := &out.Chat.Messages[n-1]
			last.ToolCalls = append(last.ToolCalls, assist.ToolCall{ID: it.CallID, Type: "function",
				Function: assist.FunctionCall{Name: it.Name, Arguments: args}})
		case "function_call_output":
			parts, err := responsesParts(it.Output)
			if err != nil {
				return Request{}, fmt.Errorf("a tool's result: %w", err)
			}
			var text strings.Builder
			for _, p := range parts {
				if p.Type != "text" {
					return Request{}, errors.New("a tool's result is passed on as text only")
				}
				text.WriteString(p.Text)
			}
			out.Chat.Messages = append(out.Chat.Messages, assist.ChatMessage{Role: "tool", ToolCallID: it.CallID,
				Content: []assist.Part{{Type: "text", Text: text.String()}}})
		case "reasoning":
			// The model's own reasoning from an earlier turn, which another
			// route could not read and does not need.
		default:
			return Request{}, fmt.Errorf("%q is an item for a tool the provider runs itself, and nothing here runs it", it.Type)
		}
	}
	for _, t := range in.Tools {
		if t.Type != "function" {
			return Request{}, fmt.Errorf("%s is a tool the provider runs itself, and nothing here runs it", t.Type)
		}
		out.Chat.Tools = append(out.Chat.Tools, assist.ChatTool{Type: "function",
			Function: assist.ToolFunction{Name: t.Name, Description: t.Description, Parameters: t.Parameters}})
	}
	if len(in.ToolChoice) > 0 {
		var choice string
		if json.Unmarshal(in.ToolChoice, &choice) == nil {
			out.Chat.ToolChoice = choice
		} else {
			out.Chat.ToolChoice = "required"
		}
	}
	if err := out.Chat.Check(); err != nil {
		return Request{}, err
	}
	return out, nil
}

// WriteResponses writes the model's turn as a response.
func WriteResponses(w http.ResponseWriter, model string, reply assist.ChatReply, stream bool) {
	now := time.Now()
	id := fmt.Sprintf("resp_%d", now.UnixNano())
	var output []map[string]any
	if text := reply.Message.Text(); text != "" || len(reply.Message.ToolCalls) == 0 {
		output = append(output, map[string]any{"type": "message", "id": fmt.Sprintf("msg_%d", now.UnixNano()),
			"status": "completed", "role": "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}}})
	}
	for i, c := range reply.Message.ToolCalls {
		output = append(output, map[string]any{"type": "function_call", "id": fmt.Sprintf("fc_%d_%d", now.UnixNano(), i),
			"call_id": c.ID, "name": c.Function.Name, "arguments": c.Function.Arguments, "status": "completed"})
	}
	status, incomplete := "completed", any(nil)
	if reply.Finish == "length" {
		status, incomplete = "incomplete", map[string]any{"reason": "max_output_tokens"}
	}
	in, out := reply.Usage.In, reply.Usage.Out
	resp := map[string]any{"id": id, "object": "response", "created_at": now.Unix(), "status": status,
		"model": model, "output": output, "error": nil, "incomplete_details": incomplete,
		"instructions": nil, "metadata": map[string]any{}, "parallel_tool_calls": true,
		"tool_choice": "auto", "tools": []any{}, "store": false, "text": map[string]any{"format": map[string]any{"type": "text"}},
		"truncation": "disabled", "temperature": nil, "top_p": nil,
		"usage": map[string]any{"input_tokens": in, "output_tokens": out, "total_tokens": in + out,
			"input_tokens_details": map[string]int{"cached_tokens": 0}, "output_tokens_details": map[string]int{"reasoning_tokens": 0}}}
	w.Header().Set("Cache-Control", "no-store")
	if !stream {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	seq := 0
	event := func(name string, v map[string]any) {
		v["type"], v["sequence_number"] = name, seq
		seq++
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, b)
	}
	started := map[string]any{}
	for k, v := range resp {
		started[k] = v
	}
	started["status"], started["output"], started["usage"] = "in_progress", []any{}, nil
	event("response.created", map[string]any{"response": started})
	event("response.in_progress", map[string]any{"response": started})
	for i, item := range output {
		itemID := item["id"]
		if item["type"] == "message" {
			text := item["content"].([]any)[0].(map[string]any)["text"]
			opening := map[string]any{"type": "message", "id": itemID, "status": "in_progress", "role": "assistant", "content": []any{}}
			empty := map[string]any{"type": "output_text", "text": "", "annotations": []any{}}
			event("response.output_item.added", map[string]any{"output_index": i, "item": opening})
			event("response.content_part.added", map[string]any{"item_id": itemID, "output_index": i, "content_index": 0, "part": empty})
			event("response.output_text.delta", map[string]any{"item_id": itemID, "output_index": i, "content_index": 0, "delta": text, "logprobs": []any{}})
			event("response.output_text.done", map[string]any{"item_id": itemID, "output_index": i, "content_index": 0, "text": text, "logprobs": []any{}})
			event("response.content_part.done", map[string]any{"item_id": itemID, "output_index": i, "content_index": 0,
				"part": item["content"].([]any)[0]})
		} else {
			opening := map[string]any{}
			for k, v := range item {
				opening[k] = v
			}
			opening["arguments"], opening["status"] = "", "in_progress"
			event("response.output_item.added", map[string]any{"output_index": i, "item": opening})
			event("response.function_call_arguments.delta", map[string]any{"item_id": itemID, "output_index": i, "delta": item["arguments"]})
			event("response.function_call_arguments.done", map[string]any{"item_id": itemID, "output_index": i, "arguments": item["arguments"]})
		}
		event("response.output_item.done", map[string]any{"output_index": i, "item": item})
	}
	done := "response.completed"
	if status == "incomplete" {
		done = "response.incomplete"
	}
	event(done, map[string]any{"response": resp})
}
