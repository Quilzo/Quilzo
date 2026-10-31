// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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

	"github.com/quilzo/quilzo/internal/jsonschema"
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
	// Strict is the promise that a call's arguments fit the parameters,
	// structured output for a tool. It is checked on every call that
	// comes back (Honour), and sent only to a model declared to honour it,
	// since a server that cannot may refuse it or take it without a word.
	Strict bool `json:"strict,omitempty"`
}

// ChatMessage is one turn of a conversation.
type ChatMessage struct {
	Role       string     `json:"role"`
	Content    []Part     `json:"-"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
	// Refusal is a model declining to answer, which OpenAI's models say
	// apart from their text, most often when asked for an answer to a
	// schema. It is written back in the caller's shape as a refusal, and
	// sent on in a later turn as what the model said; so only the model's
	// own turn carries one (Check), and it counts as text against a budget.
	Refusal string `json:"-"`
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
	case m.Text() == "" && m.Refusal != "":
		out.Content = m.Refusal
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
		Refusal *string         `json:"refusal"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	*m = ChatMessage(in.plain)
	m.Content = nil
	if in.Refusal != nil {
		m.Refusal = *in.Refusal
	}
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
	// server. ToolChoiceName, with "required", is the one tool the model
	// must call, passed on as the named choice it is rather than widened
	// to any tool.
	ToolChoice     string
	ToolChoiceName string
	MaxTokens      int

	// What a caller asked of the answer beyond the conversation. Each is
	// sent to the model, held to on what comes back (Honour), or refused
	// where no model here could honour it; none is ever dropped, because
	// an answer that ignored one is an answer to a question nobody asked.

	// ResponseFormat, when set, is the shape the answer must take.
	ResponseFormat *ResponseFormat
	// Stop are sequences the answer ends before, at most MaxStop.
	Stop []string
	// Temperature and TopP are the caller's, sent in place of a route's.
	Temperature *float64
	TopP        *float64
	// ReasoningEffort is how hard a model that reasons is asked to think:
	// none, minimal, low, medium, high or xhigh. Empty leaves it to the
	// model.
	ReasoningEffort string
	// OneToolCall asks for at most one tool call in the turn.
	OneToolCall bool
}

// ResponseFormat is the shape a model's answer must take: a JSON object,
// or JSON that fits a schema.
type ResponseFormat struct {
	// Type is "json_object" or "json_schema".
	Type        string
	Name        string
	Description string
	Schema      json.RawMessage
	// Strict, with a schema, is the promise that the answer fits it, which
	// is checked on the answer (Honour) rather than taken on trust.
	Strict bool
}

// MaxStop is how many stop sequences a request may carry: what OpenAI's
// chat completions take, which is the shape every route is sent.
const MaxStop = 4

var reFormatName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (f ResponseFormat) check() error {
	switch f.Type {
	case "json_object":
		if len(f.Schema) > 0 {
			return errors.New("an answer as a JSON object takes no schema; json_schema does")
		}
	case "json_schema":
		var s map[string]any
		if json.Unmarshal(f.Schema, &s) != nil {
			return errors.New("an answer to a schema needs the schema, as a JSON object")
		}
		if f.Name != "" && !reFormatName.MatchString(f.Name) {
			return fmt.Errorf("a schema's name is letters, digits, _ and -, at most 64, not %q", f.Name)
		}
	default:
		return fmt.Errorf("an answer's format is json_object or json_schema, not %q", f.Type)
	}
	return nil
}

// wire is the format as chat completions take it.
func (f ResponseFormat) wire() map[string]any {
	if f.Type != "json_schema" {
		return map[string]any{"type": f.Type}
	}
	// OpenAI requires a name, which Anthropic's shape does not have.
	name := f.Name
	if name == "" {
		name = "answer"
	}
	s := map[string]any{"name": name, "schema": f.Schema, "strict": f.Strict}
	if f.Description != "" {
		s["description"] = f.Description
	}
	return map[string]any{"type": "json_schema", "json_schema": s}
}

// ErrCannotHonour is a request asking for something no model here is
// declared able to do: an answer to a schema, say, where no route says it
// takes one. The caller can change the request; nothing is sent.
var ErrCannotHonour = errors.New("no model here can honour what the request asks for")

// ErrNotHonoured is a model's answer that is not what its request asked
// for. The model answered, so it is not resting; the answer goes back as
// this error rather than as an answer the caller would take for the one
// it asked for.
var ErrNotHonoured = errors.New("the model's answer is not what the request asked for")

// Honour holds a model's turn to what its request asked of it.
//
// A stop sequence the model wrote past is cut at, as the provider does
// when it honours one: the text ends there, and so does the turn, so a
// tool call after it goes too, unless the request required a call, when
// the call is the turn and the text only what came before it. Anything
// else asked for and not given is ErrNotHonoured: a tool the request
// required, or named, that the model did not call; a call where the
// request allowed none, or more than one where it asked for one; a call
// to a strict tool whose arguments do not fit its parameters; text that
// is not JSON where JSON was asked for, or JSON that does not fit a schema
// it was promised to fit. A schema is held to as far as internal/jsonschema
// reads one, which is every keyword OpenAI's and Anthropic's structured
// output take.
//
// It is checked here rather than trusted to have been sent, because not
// every model honours what it is sent: a route that refuses a forced tool
// is sent "auto" (Params.AutoToolChoice), and some servers take a forced
// choice or a format and silently do as they please. A turn cut short by
// its limit is not held to what it did not finish, a format, a call or a
// call's arguments, since its finish says so; nor is a refusal, which is
// an answer in every shape.
func (r ChatRequest) Honour(reply ChatReply) (ChatReply, error) {
	if len(r.Stop) > 0 {
		reply = cutAtStop(reply, r.Stop, r.ToolChoice == "required")
	}
	m := reply.Message
	if m.Refusal != "" {
		return reply, nil
	}
	calls := m.ToolCalls
	cut := reply.Finish == "length"
	switch {
	case r.ToolChoice == "none" && len(calls) > 0:
		return reply, fmt.Errorf("%w: it called %s, and the request allowed no tool", ErrNotHonoured, calls[0].Function.Name)
	case r.ToolChoice == "required" && len(calls) == 0 && !cut:
		return reply, fmt.Errorf("%w: the request required a tool call, and the model answered without one", ErrNotHonoured)
	case r.OneToolCall && len(calls) > 1:
		return reply, fmt.Errorf("%w: it made %d tool calls, and the request asked for one at most", ErrNotHonoured, len(calls))
	}
	for _, c := range calls {
		if r.ToolChoiceName != "" && c.Function.Name != r.ToolChoiceName {
			return reply, fmt.Errorf("%w: it called %s, and the request named %s", ErrNotHonoured, c.Function.Name, r.ToolChoiceName)
		}
		if !cut {
			if err := r.strictCall(c); err != nil {
				return reply, err
			}
		}
	}
	f := r.ResponseFormat
	if f == nil || len(calls) > 0 || cut {
		return reply, nil
	}
	var v any
	if err := json.Unmarshal([]byte(m.Text()), &v); err != nil {
		return reply, fmt.Errorf("%w: the answer is not JSON (%v)", ErrNotHonoured, err)
	}
	if _, object := v.(map[string]any); f.Type == "json_object" && !object {
		return reply, fmt.Errorf("%w: the answer is JSON, and not an object", ErrNotHonoured)
	}
	if f.Type == "json_schema" && f.Strict {
		if err := jsonschema.CheckAnswer(f.Schema, v, "answer"); err != nil {
			return reply, fmt.Errorf("%w: the answer does not fit its schema: %v", ErrNotHonoured, err)
		}
	}
	return reply, nil
}

// strictCall holds a call to a strict tool to the tool's parameters.
func (r ChatRequest) strictCall(c ToolCall) error {
	for _, t := range r.Tools {
		if t.Function.Name != c.Function.Name || !t.Function.Strict {
			continue
		}
		var args any
		if err := json.Unmarshal([]byte(c.Function.Arguments), &args); err != nil {
			return fmt.Errorf("%w: its call to %s carries arguments that are not JSON (%v)", ErrNotHonoured, c.Function.Name, err)
		}
		if err := jsonschema.CheckAnswer(t.Function.Parameters, args, "arguments"); err != nil {
			return fmt.Errorf("%w: its call to %s does not fit the tool's parameters: %v", ErrNotHonoured, c.Function.Name, err)
		}
	}
	return nil
}

// cutAtStop ends a turn's text before the first stop sequence in it, and
// the turn with it, keeping its calls only when a call was required.
func cutAtStop(reply ChatReply, stop []string, keepCalls bool) ChatReply {
	text := reply.Message.Text()
	at := -1
	for _, s := range stop {
		if i := strings.Index(text, s); i >= 0 && (at < 0 || i < at) {
			at = i
		}
	}
	if at < 0 {
		return reply
	}
	reply.Message.Content = []Part{{Type: "text", Text: text[:at]}}
	if keepCalls && len(reply.Message.ToolCalls) > 0 {
		return reply
	}
	reply.Message.ToolCalls = nil
	reply.Finish = "stop"
	return reply
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
	if r.ToolChoiceName != "" {
		named := false
		for _, t := range r.Tools {
			named = named || t.Function.Name == r.ToolChoiceName
		}
		if r.ToolChoice != "required" || !named {
			return fmt.Errorf("the tool a request names as its choice, %q, is one of the tools it offers", r.ToolChoiceName)
		}
	}
	if r.ToolChoice == "required" && len(r.Tools) == 0 {
		return errors.New("a request that requires a tool call offers a tool to call")
	}
	if f := r.ResponseFormat; f != nil {
		if err := f.check(); err != nil {
			return err
		}
	}
	if len(r.Stop) > MaxStop {
		return fmt.Errorf("a request carries at most %d stop sequences", MaxStop)
	}
	for _, s := range r.Stop {
		if s == "" {
			return errors.New("a stop sequence is not empty")
		}
	}
	// Written so that NaN, which compares false with everything, is refused
	// too: it could not be sent as JSON.
	if r.Temperature != nil && !(*r.Temperature >= 0 && *r.Temperature <= 2) {
		return errors.New("temperature is between 0 and 2")
	}
	if r.TopP != nil && !(*r.TopP > 0 && *r.TopP <= 1) {
		return errors.New("top_p is more than 0 and at most 1")
	}
	switch r.ReasoningEffort {
	case "", "none", "minimal", "low", "medium", "high", "xhigh":
	default:
		return fmt.Errorf("a reasoning effort is none, minimal, low, medium, high or xhigh, not %q", r.ReasoningEffort)
	}
	images := 0
	for _, m := range r.Messages {
		switch m.Role {
		case "system", "developer", "user", "assistant", "tool":
		default:
			return fmt.Errorf("%q is not a role in a conversation", m.Role)
		}
		// A refusal is sent on as what the model said, so on anyone else's
		// turn it would be words put in the model's mouth.
		if m.Refusal != "" && m.Role != "assistant" {
			return fmt.Errorf("only the model's own turn carries a refusal, not a %s message", m.Role)
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
		n += len(m.Text()) + len(m.Refusal)
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
		"model":    h.Model,
		"messages": req.Messages,
		"stream":   false,
	}
	if len(req.Tools) > 0 {
		payload["tools"] = req.Tools
		switch {
		case req.ToolChoice == "required" && h.Params.AutoToolChoice:
			payload["tool_choice"] = "auto"
		case req.ToolChoiceName != "":
			payload["tool_choice"] = map[string]any{"type": "function",
				"function": map[string]string{"name": req.ToolChoiceName}}
		case req.ToolChoice != "":
			payload["tool_choice"] = req.ToolChoice
		}
	}
	h.Params.apply(payload, req.MaxTokens)
	// What the caller asked for is sent as it asked: its temperature in
	// place of the route's, which is only what the route sends when nobody
	// says otherwise. A model that refuses one answers 400, which goes back
	// to the caller as its own to fix.
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		payload["top_p"] = *req.TopP
	}
	if len(req.Stop) > 0 {
		payload["stop"] = req.Stop
	}
	if req.ReasoningEffort != "" {
		payload["reasoning_effort"] = req.ReasoningEffort
	}
	if req.OneToolCall && len(req.Tools) > 0 {
		payload["parallel_tool_calls"] = false
	}
	if req.ResponseFormat != nil {
		payload["response_format"] = req.ResponseFormat.wire()
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
		return ChatReply{}, &StatusError{Code: resp.StatusCode, Body: snippet}
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
