// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// A whole conversation, as OpenAI's chat completions take one.
//
// Complete takes a system prompt and a user message and returns text, which
// is all a model writing a page needs. An agent that looks at a screen and
// chooses a tool needs more: pictures in, tools offered, and the tool the
// model chose back. Chat carries that, in the shape nearly every model
// server speaks, so one client still covers hosted and local models.
//
// Pictures arrive only inside the request, as data: URLs. An image given as
// a web address is fetched by the provider, from wherever the address says,
// which is a way for whatever wrote the request to send anything anywhere
// and have a model provider deliver it; so it is refused.

// Part is one piece of a message's content: text, or a picture.
type Part struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

// ImageURL is a picture, as a data: URL.
type ImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

// ToolCall is a tool the model chose, with its arguments as JSON text.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

// FunctionCall is the named function and its arguments.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatTool is a tool offered to the model.
type ChatTool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction describes a tool: its name, what it is for, and its
// parameters as a JSON schema.
type ToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// ChatMessage is one turn of a conversation.
type ChatMessage struct {
	Role       string     `json:"role"`
	Content    []Part     `json:"-"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// Text is the message's text parts, joined.
func (m ChatMessage) Text() string {
	var b strings.Builder
	for _, p := range m.Content {
		if p.Type == "text" {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

// Images counts the pictures in the message.
func (m ChatMessage) Images() int {
	n := 0
	for _, p := range m.Content {
		if p.Type == "image_url" {
			n++
		}
	}
	return n
}

// MarshalJSON writes content as a string when it is all text, which every
// server reads, and as parts only when there is a picture.
func (m ChatMessage) MarshalJSON() ([]byte, error) {
	type plain ChatMessage
	out := struct {
		plain
		Content any `json:"content"`
	}{plain: plain(m)}
	switch {
	case m.Images() > 0:
		out.Content = m.Content
	case len(m.Content) == 0 && len(m.ToolCalls) > 0:
		out.Content = nil
	default:
		out.Content = m.Text()
	}
	return json.Marshal(out)
}

// UnmarshalJSON reads content given as a string, as parts, or as null.
func (m *ChatMessage) UnmarshalJSON(b []byte) error {
	type plain ChatMessage
	var in struct {
		plain
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	*m = ChatMessage(in.plain)
	m.Content = nil
	raw := bytes.TrimSpace(in.Content)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		m.Content = []Part{{Type: "text", Text: s}}
		return nil
	}
	var parts []Part
	if err := json.Unmarshal(raw, &parts); err != nil {
		return fmt.Errorf("a message's content is text or a list of parts: %w", err)
	}
	m.Content = parts
	return nil
}

// ChatRequest is a conversation and the tools offered in it.
type ChatRequest struct {
	Messages []ChatMessage
	Tools    []ChatTool
	// ToolChoice is "auto", "none" or "required"; empty leaves it to the
	// server.
	ToolChoice string
	MaxTokens  int
}

// ChatReply is the model's turn.
type ChatReply struct {
	Message ChatMessage
	// Finish is why it stopped: "stop", "tool_calls", "length".
	Finish string
	Usage  Usage
}

// Chatter is a model that takes a whole conversation.
type Chatter interface {
	Chat(ctx context.Context, req ChatRequest) (ChatReply, error)
}

// Limits on what one conversation may carry. A picture is at most a few
// megabytes once encoded, and a screen is about one; twenty is more than a
// computer-using agent keeps (the vendors advise the last three).
const (
	MaxChatImages     = 20
	MaxChatImageBytes = 8 << 20
	MaxChatMessages   = 400
	MaxChatTools      = 128
)

var reImageData = regexp.MustCompile(`^data:image/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$`)

// Check refuses a conversation this program will not send anywhere.
func (r ChatRequest) Check() error {
	if len(r.Messages) == 0 {
		return errors.New("a conversation needs at least one message")
	}
	if len(r.Messages) > MaxChatMessages {
		return fmt.Errorf("a conversation is at most %d messages", MaxChatMessages)
	}
	if len(r.Tools) > MaxChatTools {
		return fmt.Errorf("at most %d tools are offered at once", MaxChatTools)
	}
	switch r.ToolChoice {
	case "", "auto", "none", "required":
	default:
		return fmt.Errorf("tool_choice is auto, none or required, not %q", r.ToolChoice)
	}
	images := 0
	for _, m := range r.Messages {
		switch m.Role {
		case "system", "developer", "user", "assistant", "tool":
		default:
			return fmt.Errorf("%q is not a role in a conversation", m.Role)
		}
		for _, p := range m.Content {
			switch p.Type {
			case "text":
			case "image_url":
				images++
				if p.ImageURL == nil {
					return errors.New("a picture part carries no picture")
				}
				if len(p.ImageURL.URL) > MaxChatImageBytes {
					return fmt.Errorf("a picture is at most %d bytes encoded", MaxChatImageBytes)
				}
				if !reImageData.MatchString(p.ImageURL.URL) {
					return errors.New("a picture is sent as a data: URL (PNG, JPEG, WebP or GIF), " +
						"never as a web address: the provider would fetch it from wherever it points")
				}
			default:
				return fmt.Errorf("%q is not a part this sends; text and image_url are", p.Type)
			}
		}
	}
	if images > MaxChatImages {
		return fmt.Errorf("a conversation carries at most %d pictures; keep the last few", MaxChatImages)
	}
	for _, t := range r.Tools {
		if t.Type != "function" || t.Function.Name == "" {
			return errors.New("a tool is a function with a name")
		}
	}
	return nil
}

// Images counts the pictures in a conversation.
func (r ChatRequest) Images() int {
	n := 0
	for _, m := range r.Messages {
		n += m.Images()
	}
	return n
}

// TextLen is the length of everything in the conversation that is text,
// for budgets that count characters.
func (r ChatRequest) TextLen() int {
	n := 0
	for _, m := range r.Messages {
		n += len(m.Text())
		for _, c := range m.ToolCalls {
			n += len(c.Function.Arguments)
		}
	}
	return n
}

// Chat sends a conversation to the endpoint and reads the model's turn.
func (h *HTTPModel) Chat(ctx context.Context, req ChatRequest) (ChatReply, error) {
	if err := req.Check(); err != nil {
		return ChatReply{}, err
	}
	payload := map[string]any{
		"model":       h.Model,
		"messages":    req.Messages,
		"temperature": 0.2,
		"stream":      false,
	}
	if len(req.Tools) > 0 {
		payload["tools"] = req.Tools
		if req.ToolChoice != "" {
			payload["tool_choice"] = req.ToolChoice
		}
	}
	if req.MaxTokens > 0 {
		payload["max_tokens"] = req.MaxTokens
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ChatReply{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return ChatReply{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	if h.APIKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+h.APIKey)
	}
	resp, err := h.Client.Do(hreq)
	if err != nil {
		return ChatReply{}, fmt.Errorf("model request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(http.MaxBytesReader(nil, resp.Body, 4<<10))
		snippet := strings.TrimSpace(buf.String())
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return ChatReply{}, fmt.Errorf("model returned %d: %s", resp.StatusCode, snippet)
	}
	var out struct {
		Choices []struct {
			Message      ChatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 16<<20)).Decode(&out); err != nil {
		return ChatReply{}, fmt.Errorf("cannot read the model's reply: %w", err)
	}
	if len(out.Choices) == 0 {
		return ChatReply{}, errors.New("the model returned no choices")
	}
	c := out.Choices[0]
	c.Message.Role = "assistant"
	reply := ChatReply{Message: c.Message, Finish: c.FinishReason}
	reply.Usage = Usage{In: (req.TextLen() + 3) / 4, Out: (len(c.Message.Text()) + 3) / 4}
	if out.Usage != nil && (out.Usage.Prompt > 0 || out.Usage.Completion > 0) {
		reply.Usage = Usage{In: out.Usage.Prompt, Out: out.Usage.Completion, Reported: true}
	}
	return reply, nil
}
