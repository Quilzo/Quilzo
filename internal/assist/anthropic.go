// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Anthropic's Messages API, spoken natively.
//
// # Why not its OpenAI-compatible endpoint
//
// Anthropic serves one, and a route could use it with no code here. But
// what an operator chooses Anthropic for is missing from it: where the
// model runs (inference_geo, which its documentation says that endpoint
// does not take), how hard the model thinks (output_config.effort), a
// declined request answered by another of Anthropic's models (fallbacks),
// and why a model stopped (a refusal is its own stop reason here, and an
// empty answer there).
//
// # What is sent
//
// The conversation, as the Messages API takes it: system prompts as its
// system field, pictures as base64 image blocks, tools with their input
// schemas, a tool's result as a tool_result block in the user's turn.
// Version 2026-10-21 of the API, which refuses temperature, top_p and
// top_k on every model, so this never sends them; a route that sets them
// is refused where it is made (gateway.Route.CheckWire).
//
// max_tokens is required. The newest models think before they answer and
// count that thinking within the limit, so a limit set for a short answer
// is raised to AnthropicMinMaxTokens: a 1,024-token limit could be spent
// on thinking and leave no answer. A request that may write more than
// AnthropicStreamAbove is streamed, as the API asks of long answers, and
// read whole here.
//
// # What is read
//
// Text and tool calls. Thinking, which the newest models return empty
// unless asked, and blocks of kinds this does not know are the model's
// own working, not its answer, and are not passed on. A refusal is an
// error, Declined, not an empty answer: see its comment.

// AnthropicVersion is the version of the Messages API this speaks.
const AnthropicVersion = "2026-10-21"

// Limits on the output a request asks for.
const (
	AnthropicDefaultMaxTokens = 16000
	AnthropicMinMaxTokens     = 4096
	AnthropicMaxMaxTokens     = 128000
	// AnthropicStreamAbove is the most a request asks for without a
	// stream: a longer answer can outlast a connection nobody reads from.
	AnthropicStreamAbove = 16000
)

// anthropicFallbackBeta is the beta the fallbacks field needs.
const anthropicFallbackBeta = "server-side-fallback-2026-07-01"

// Declined is a request a model would not answer: the provider's
// safeguards stopped it (Anthropic's stop_reason "refusal").
//
// It is the request's trouble, not the route's: the route is not rested,
// and the gateway does not send the request on to its next route. Routing
// round a safeguard to whichever provider has fewer is not a fallback.
// A route that wants a declined request answered asks Anthropic to answer
// it with another of its own models (Params.Fallback).
type Declined struct {
	Model string
	// Category is the provider's reason, such as "cyber" or "bio", when
	// it gives one.
	Category string
}

func (e *Declined) Error() string {
	if e.Category != "" {
		return fmt.Sprintf("%s declined to answer this (%s)", e.Model, e.Category)
	}
	return e.Model + " declined to answer this"
}

// anthropicMaxTokens is the output limit a request asks for.
func anthropicMaxTokens(asked int) int {
	switch {
	case asked <= 0:
		return AnthropicDefaultMaxTokens
	case asked < AnthropicMinMaxTokens:
		return AnthropicMinMaxTokens
	case asked > AnthropicMaxMaxTokens:
		return AnthropicMaxMaxTokens
	}
	return asked
}

// anthropicBody is a conversation as the Messages API takes it.
func anthropicBody(model string, req ChatRequest, p Params, stream bool) (map[string]any, error) {
	system, msgs, err := anthropicMessages(req.Messages)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"model": model, "max_tokens": anthropicMaxTokens(req.MaxTokens), "messages": msgs}
	if system != "" {
		body["system"] = system
	}
	if len(req.Tools) > 0 {
		tools := make([]map[string]any, 0, len(req.Tools))
		for _, t := range req.Tools {
			schema := json.RawMessage(bytes.TrimSpace(t.Function.Parameters))
			if len(schema) == 0 || bytes.Equal(schema, []byte("null")) {
				schema = json.RawMessage(`{"type":"object","properties":{}}`)
			}
			tool := map[string]any{"name": t.Function.Name, "input_schema": schema}
			if t.Function.Description != "" {
				tool["description"] = t.Function.Description
			}
			tools = append(tools, tool)
		}
		body["tools"] = tools
		switch {
		case req.ToolChoice == "required" && p.AutoToolChoice:
			body["tool_choice"] = map[string]string{"type": "auto"}
		case req.ToolChoiceName != "":
			body["tool_choice"] = map[string]string{"type": "tool", "name": req.ToolChoiceName}
		case req.ToolChoice == "required":
			body["tool_choice"] = map[string]string{"type": "any"}
		case req.ToolChoice == "auto", req.ToolChoice == "none":
			body["tool_choice"] = map[string]string{"type": req.ToolChoice}
		}
	}
	if p.Effort != "" {
		body["output_config"] = map[string]string{"effort": p.Effort}
	}
	if p.Geo != "" {
		body["inference_geo"] = p.Geo
	}
	if p.Fallback {
		body["fallbacks"] = "default"
	}
	if stream {
		body["stream"] = true
	}
	return body, nil
}

// anthropicMessages splits a conversation into the system prompt and the
// turns, as the Messages API takes them: system and developer messages
// joined into one system prompt; a tool's result in the user's turn; two
// turns by the same speaker made one.
func anthropicMessages(in []ChatMessage) (string, []map[string]any, error) {
	type turn struct {
		role   string
		blocks []map[string]any
	}
	var system []string
	var turns []turn
	add := func(role string, blocks []map[string]any) {
		if len(blocks) == 0 {
			return
		}
		if n := len(turns); n > 0 && turns[n-1].role == role {
			turns[n-1].blocks = append(turns[n-1].blocks, blocks...)
			return
		}
		turns = append(turns, turn{role, blocks})
	}
	for i, m := range in {
		switch m.Role {
		case "system", "developer":
			if t := strings.TrimSpace(m.Text()); t != "" {
				system = append(system, t)
			}
		case "user":
			blocks, err := anthropicParts(m.Content)
			if err != nil {
				return "", nil, fmt.Errorf("message %d: %w", i, err)
			}
			add("user", blocks)
		case "assistant":
			blocks, err := anthropicParts(m.Content)
			if err != nil {
				return "", nil, fmt.Errorf("message %d: %w", i, err)
			}
			for _, c := range m.ToolCalls {
				args := bytes.TrimSpace([]byte(c.Function.Arguments))
				if len(args) == 0 {
					args = []byte("{}")
				}
				var obj map[string]any
				if json.Unmarshal(args, &obj) != nil || obj == nil {
					return "", nil, fmt.Errorf("message %d: the arguments of the call to %s are not a JSON object", i, c.Function.Name)
				}
				if c.ID == "" || c.Function.Name == "" {
					return "", nil, fmt.Errorf("message %d: a tool call has an id and a name", i)
				}
				blocks = append(blocks, map[string]any{"type": "tool_use", "id": c.ID, "name": c.Function.Name,
					"input": json.RawMessage(args)})
			}
			add("assistant", blocks)
		case "tool":
			if m.ToolCallID == "" {
				return "", nil, fmt.Errorf("message %d: a tool's result names the call it answers", i)
			}
			result := map[string]any{"type": "tool_result", "tool_use_id": m.ToolCallID}
			if m.Images() > 0 {
				blocks, err := anthropicParts(m.Content)
				if err != nil {
					return "", nil, fmt.Errorf("message %d: %w", i, err)
				}
				result["content"] = blocks
			} else if t := m.Text(); strings.TrimSpace(t) != "" {
				result["content"] = t
			}
			add("user", []map[string]any{result})
		default:
			return "", nil, fmt.Errorf("message %d: %q is not a role in a conversation", i, m.Role)
		}
	}
	if len(turns) == 0 {
		return "", nil, errors.New("the conversation has nothing to answer")
	}
	out := make([]map[string]any, len(turns))
	for i, t := range turns {
		out[i] = map[string]any{"role": t.role, "content": t.blocks}
	}
	return strings.Join(system, "\n\n"), out, nil
}

// anthropicParts is a message's content as blocks. Text that is only
// space is left out: the API refuses an empty text block.
func anthropicParts(parts []Part) ([]map[string]any, error) {
	var out []map[string]any
	for _, p := range parts {
		switch p.Type {
		case "text":
			if strings.TrimSpace(p.Text) != "" {
				out = append(out, map[string]any{"type": "text", "text": p.Text})
			}
		case "image_url":
			if p.ImageURL == nil || !reImageData.MatchString(p.ImageURL.URL) {
				return nil, errors.New("a picture is sent as a data: URL (PNG, JPEG, WebP or GIF)")
			}
			head, data, _ := strings.Cut(strings.TrimPrefix(p.ImageURL.URL, "data:"), ";base64,")
			out = append(out, map[string]any{"type": "image",
				"source": map[string]string{"type": "base64", "media_type": head, "data": data}})
		default:
			return nil, fmt.Errorf("%q is not a part this sends; text and image_url are", p.Type)
		}
	}
	return out, nil
}

// anthropicReply is the model's turn as the Messages API writes it.
type anthropicReply struct {
	Model       string           `json:"model"`
	Content     []anthropicBlock `json:"content"`
	StopReason  string           `json:"stop_reason"`
	StopDetails *anthropicStop   `json:"stop_details"`
	Usage       anthropicUsage   `json:"usage"`
}

type anthropicBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

type anthropicStop struct {
	Category string `json:"category"`
}

// anthropicUsage is what a call used. Tokens read from or written to the
// provider's cache are input too, and are counted as input.
type anthropicUsage struct {
	Input      int `json:"input_tokens"`
	Output     int `json:"output_tokens"`
	CacheWrite int `json:"cache_creation_input_tokens"`
	CacheRead  int `json:"cache_read_input_tokens"`
}

// chatReply is the reply as a ChatReply, or a Declined.
func (r anthropicReply) chatReply(req ChatRequest, model string) (ChatReply, error) {
	in := r.Usage.Input + r.Usage.CacheWrite + r.Usage.CacheRead
	usage := Usage{In: in, Out: r.Usage.Output, Reported: in > 0 || r.Usage.Output > 0}
	if r.Model != "" {
		model = r.Model
	}
	if r.StopReason == "refusal" {
		d := &Declined{Model: model}
		if r.StopDetails != nil {
			d.Category = r.StopDetails.Category
		}
		return ChatReply{Usage: usage}, d
	}
	msg := ChatMessage{Role: "assistant"}
	var text strings.Builder
	for _, b := range r.Content {
		switch b.Type {
		case "text":
			text.WriteString(b.Text)
		case "tool_use":
			args := bytes.TrimSpace(b.Input)
			if len(args) == 0 {
				args = []byte("{}")
			}
			msg.ToolCalls = append(msg.ToolCalls, ToolCall{ID: b.ID, Type: "function",
				Function: FunctionCall{Name: b.Name, Arguments: string(args)}})
		}
	}
	if text.Len() > 0 {
		msg.Content = []Part{{Type: "text", Text: text.String()}}
	}
	finish := "stop"
	switch r.StopReason {
	case "tool_use":
		finish = "tool_calls"
	case "max_tokens", "model_context_window_exceeded":
		finish = "length"
	}
	if !usage.Reported {
		usage = Usage{In: (req.TextLen() + 3) / 4, Out: (text.Len() + 3) / 4}
	}
	return ChatReply{Message: msg, Finish: finish, Usage: usage}, nil
}

// anthropicChat sends a conversation to the Messages API.
func (h *HTTPModel) anthropicChat(ctx context.Context, req ChatRequest) (ChatReply, error) {
	stream := anthropicMaxTokens(req.MaxTokens) > AnthropicStreamAbove
	body, err := anthropicBody(h.Model, req, h.Params, stream)
	if err != nil {
		return ChatReply{}, err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return ChatReply{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+"/messages", bytes.NewReader(b))
	if err != nil {
		return ChatReply{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	if err := h.prepare(hreq); err != nil {
		return ChatReply{}, err
	}
	// After the profile's headers: a profile that names no version still
	// speaks this one, and one that names betas keeps them.
	if hreq.Header.Get("anthropic-version") == "" {
		hreq.Header.Set("anthropic-version", AnthropicVersion)
	}
	if h.Params.Fallback {
		beta := anthropicFallbackBeta
		if v := hreq.Header.Get("anthropic-beta"); v != "" {
			beta = v + "," + beta
		}
		hreq.Header.Set("anthropic-beta", beta)
	}
	if stream {
		hreq.Header.Set("Accept", "text/event-stream")
	}
	resp, err := h.Client.Do(hreq)
	if err != nil {
		return ChatReply{}, fmt.Errorf("model request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, 4<<10))
		snippet := strings.TrimSpace(buf.String())
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return ChatReply{}, &StatusError{Code: resp.StatusCode, Body: snippet}
	}
	var r anthropicReply
	if stream {
		r, err = readAnthropicStream(io.LimitReader(resp.Body, anthropicMaxReply))
	} else {
		err = json.NewDecoder(io.LimitReader(resp.Body, anthropicMaxReply)).Decode(&r)
	}
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			return ChatReply{}, err
		}
		return ChatReply{}, fmt.Errorf("cannot read the model's reply: %w", err)
	}
	return r.chatReply(req, h.Model)
}

// anthropicMaxReply is the most of a reply that is read.
const anthropicMaxReply = 16 << 20

// anthropicMaxBlocks is the most content blocks a streamed reply may open.
const anthropicMaxBlocks = 1024

// readAnthropicStream reads a streamed reply whole: the server-sent events
// message_start, content_block_start, content_block_delta,
// content_block_stop, message_delta and message_stop, with ping between
// them and error in place of any. An error event is the provider's status,
// as a StatusError, so the gateway judges it as it would have judged the
// same error before the stream began.
func readAnthropicStream(r io.Reader) (anthropicReply, error) {
	type building struct {
		anthropicBlock
		text, input strings.Builder
	}
	var out anthropicReply
	var blocks []*building
	stopped := false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var data strings.Builder
	dispatch := func() error {
		if data.Len() == 0 {
			return nil
		}
		raw := []byte(data.String())
		data.Reset()
		var ev struct {
			Type    string `json:"type"`
			Index   int    `json:"index"`
			Message *struct {
				Model string         `json:"model"`
				Usage anthropicUsage `json:"usage"`
			} `json:"message"`
			ContentBlock *anthropicBlock `json:"content_block"`
			Delta        *struct {
				Type        string         `json:"type"`
				Text        string         `json:"text"`
				PartialJSON string         `json:"partial_json"`
				StopReason  string         `json:"stop_reason"`
				StopDetails *anthropicStop `json:"stop_details"`
			} `json:"delta"`
			Usage *struct {
				Input      *int `json:"input_tokens"`
				Output     *int `json:"output_tokens"`
				CacheWrite *int `json:"cache_creation_input_tokens"`
				CacheRead  *int `json:"cache_read_input_tokens"`
			} `json:"usage"`
			Error *struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return fmt.Errorf("an event is not JSON: %w", err)
		}
		block := func() (*building, error) {
			if ev.Index < 0 || ev.Index >= anthropicMaxBlocks {
				return nil, fmt.Errorf("a reply of more than %d blocks", anthropicMaxBlocks)
			}
			for len(blocks) <= ev.Index {
				blocks = append(blocks, &building{})
			}
			return blocks[ev.Index], nil
		}
		switch ev.Type {
		case "message_start":
			if ev.Message != nil {
				out.Model, out.Usage = ev.Message.Model, ev.Message.Usage
			}
		case "content_block_start":
			b, err := block()
			if err != nil {
				return err
			}
			if ev.ContentBlock != nil {
				b.anthropicBlock = *ev.ContentBlock
				b.text.WriteString(ev.ContentBlock.Text)
			}
		case "content_block_delta":
			b, err := block()
			if err != nil {
				return err
			}
			if ev.Delta != nil {
				switch ev.Delta.Type {
				case "text_delta":
					b.text.WriteString(ev.Delta.Text)
				case "input_json_delta":
					b.input.WriteString(ev.Delta.PartialJSON)
				}
			}
		case "message_delta":
			if ev.Delta != nil {
				out.StopReason = ev.Delta.StopReason
				if ev.Delta.StopDetails != nil {
					out.StopDetails = ev.Delta.StopDetails
				}
			}
			if u := ev.Usage; u != nil {
				for _, f := range []struct {
					from *int
					into *int
				}{{u.Input, &out.Usage.Input}, {u.Output, &out.Usage.Output},
					{u.CacheWrite, &out.Usage.CacheWrite}, {u.CacheRead, &out.Usage.CacheRead}} {
					if f.from != nil && *f.from >= 0 {
						*f.into = *f.from
					}
				}
			}
		case "message_stop":
			stopped = true
		case "error":
			se := &StatusError{Code: http.StatusInternalServerError, Body: "the stream failed"}
			if ev.Error != nil {
				se.Code = anthropicErrorStatus(ev.Error.Type)
				se.Body = clip300(ev.Error.Type + ": " + ev.Error.Message)
			}
			return se
		}
		return nil
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if err := dispatch(); err != nil {
				return out, err
			}
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	if err := dispatch(); err != nil {
		return out, err
	}
	if !stopped {
		return out, errors.New("the stream ended before the reply did")
	}
	for _, b := range blocks {
		blk := b.anthropicBlock
		blk.Text = b.text.String()
		if blk.Type == "tool_use" {
			in := strings.TrimSpace(b.input.String())
			if in == "" {
				in = "{}"
			}
			if !json.Valid([]byte(in)) {
				return out, fmt.Errorf("the arguments of the call to %s are not JSON", blk.Name)
			}
			blk.Input = json.RawMessage(in)
		}
		out.Content = append(out.Content, blk)
	}
	return out, nil
}

// anthropicErrorStatus is the HTTP status an error event stands for.
func anthropicErrorStatus(kind string) int {
	switch kind {
	case "invalid_request_error":
		return http.StatusBadRequest
	case "authentication_error":
		return http.StatusUnauthorized
	case "permission_error":
		return http.StatusForbidden
	case "not_found_error":
		return http.StatusNotFound
	case "request_too_large":
		return http.StatusRequestEntityTooLarge
	case "rate_limit_error":
		return http.StatusTooManyRequests
	case "overloaded_error":
		return 529
	}
	return http.StatusInternalServerError
}

func clip300(s string) string {
	if len(s) > 300 {
		return s[:300]
	}
	return s
}
