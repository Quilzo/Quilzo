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
// picture it never saw. The same goes for every field at a request's top
// level (see fields): an agent that asked for JSON to a schema and got
// prose, because the field was passed over, is worse off than one told no.
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
	"reflect"
	"slices"
	"sort"
	"strconv"
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

// fields is what one shape may carry at its top level. Every field is one
// of three things: read into the conversation; quiet, accepted and not
// passed on, because it cannot change the answer; or unasked, accepted
// only at null or at the value that asks for nothing (one answer, no log
// probabilities) and refused at any other, because nothing here could
// honour it. A field none of them names is refused by name. A shape's
// providers add fields every few months, and one passed over could be a
// format, a seed or a number of answers the caller is counting on.
type fields struct {
	what        string
	read, quiet []string
	unasked     []unasked
}

// unasked is a field refused unless it is null or one of nothing, with
// why.
type unasked struct {
	name    string
	nothing []any
	why     string
}

// body reads a request, refusing a field its shape does not take.
func (f fields) body(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxRequest))
	if err != nil {
		return nil, fmt.Errorf("the request could not be read: %w", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, fmt.Errorf("the request is not %s: %w", f.what, err)
	}
	known := map[string]bool{}
	for _, k := range append(append([]string{}, f.read...), f.quiet...) {
		known[k] = true
	}
	for _, u := range f.unasked {
		known[u.name] = true
	}
	var odd []string
	for k := range top {
		if !known[k] {
			odd = append(odd, k)
		}
	}
	if err := strange("", odd); err != nil {
		return nil, err
	}
	for _, u := range f.unasked {
		if asks(top[u.name], u.nothing...) {
			return nil, fmt.Errorf("%s: %s", u.name, u.why)
		}
	}
	return b, nil
}

// strange refuses fields this does not read, naming them.
func strange(within string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	for i, n := range names {
		if len(n) > 64 {
			n = n[:64] + "…"
		}
		names[i] = strconv.Quote(within + n)
	}
	noun := "a field"
	if len(names) > 1 {
		noun = "fields"
	}
	return fmt.Errorf("%s: not %s this reads, so refused rather than passed over, "+
		"since what is passed over could change the answer", strings.Join(names, ", "), noun)
}

// only refuses a key of an object that keys does not name. It is used on
// the objects that shape an answer (a format, a reasoning effort), where a
// key passed over changes it as much as one at the top does.
func only(raw json.RawMessage, what string, keys ...string) error {
	if absent(raw) {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%s is an object", what)
	}
	var odd []string
	for k := range m {
		if !slices.Contains(keys, k) {
			odd = append(odd, k)
		}
	}
	return strange(what+".", odd)
}

func absent(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null"
}

// asks reports whether a field was given as anything but null or one of
// the values that ask for nothing.
func asks(raw json.RawMessage, nothing ...any) bool {
	if absent(raw) {
		return false
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return true
	}
	for _, n := range nothing {
		if reflect.DeepEqual(v, n) {
			return false
		}
	}
	return true
}

// Fields refused unless they ask for nothing, and the words for why.
var (
	// The answer may come from any route, so from another model: the same
	// seed gives another answer there, and log probabilities and token ids
	// are one model's own.
	seedField = unasked{"seed", nil,
		"nothing here can promise the same answer twice: another route, another model, answers the same seed differently"}
	logprobsField = unasked{"logprobs", []any{false},
		"an answer carries no log probabilities here, since the route that answers may be another model"}
	topLogprobsField = unasked{"top_logprobs", []any{0.0},
		"an answer carries no log probabilities here, since the route that answers may be another model"}
	logitBiasField = unasked{"logit_bias", []any{map[string]any{}},
		"token ids are one model's own, and the route that answers may be another"}
	// A route may take these and silently do nothing with them, as
	// Anthropic's OpenAI-compatible endpoint does, and no route says which
	// it honours, so they are not sent at all.
	noPenalty = "penalties are not passed on: a route may take one and silently do nothing with it"
	verbosity = "how much the model says is not passed on: a route may take it and silently do nothing with it"
)

// formatIn is an answer's format as a shape writes it: its type, and with
// a schema, the schema and what goes with it.
type formatIn struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Strict      *bool           `json:"strict"`
}

// format is the format as a request carries it, nil for text. strict is
// what the shape promises when the request does not say.
func (f formatIn) format(what string, strict bool) (*assist.ResponseFormat, error) {
	if f.Strict != nil {
		strict = *f.Strict
	}
	switch f.Type {
	case "text":
		return nil, nil
	case "json_object", "json_schema":
		return &assist.ResponseFormat{Type: f.Type, Name: f.Name, Description: f.Description, Schema: f.Schema,
			Strict: strict && f.Type == "json_schema"}, nil
	}
	return nil, fmt.Errorf("%s is text, json_object or json_schema, not %q", what, f.Type)
}

// readFormat reads an answer's format with its schema beside its type, as
// the Responses API and Anthropic write it.
func readFormat(raw json.RawMessage, what string, strict bool, keys ...string) (*assist.ResponseFormat, error) {
	if absent(raw) {
		return nil, nil
	}
	if err := only(raw, what, keys...); err != nil {
		return nil, err
	}
	var f formatIn
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return f.format(what, strict)
}

// OpenAI's chat completions.

var openaiFields = fields{what: "a chat completion",
	read: []string{"model", "messages", "tools", "tool_choice", "max_tokens", "max_completion_tokens", "stream",
		"response_format", "stop", "temperature", "top_p", "reasoning_effort", "parallel_tool_calls"},
	// None of these changes the answer: how a stream is written (usage is
	// always in it); the caller's own labels for its records and its users,
	// which no provider is told (who asked is the door's to know, from the
	// token); whether the provider keeps the answer, when nothing here
	// keeps it either way; the tier and cache a provider serves it from;
	// and a predicted answer, which only makes the real one sooner.
	quiet: []string{"stream_options", "metadata", "user", "safety_identifier", "store", "service_tier",
		"prompt_cache_key", "prompt_cache_retention", "prediction"},
	unasked: []unasked{
		{"n", []any{1.0}, "one answer is written, so n is 1"},
		seedField, logprobsField, topLogprobsField, logitBiasField,
		{"frequency_penalty", []any{0.0}, noPenalty},
		{"presence_penalty", []any{0.0}, noPenalty},
		{"verbosity", []any{"medium"}, verbosity},
		{"modalities", []any{[]any{"text"}}, "the answer is text"},
		{"audio", nil, "the answer is text"},
		{"functions", nil, "send tools, which replaced functions"},
		{"function_call", nil, "send tool_choice, which replaced function_call"},
		{"web_search_options", nil, "a search the provider runs itself, and nothing here runs it"},
	}}

type openaiRequest struct {
	Model               string               `json:"model"`
	Messages            []assist.ChatMessage `json:"messages"`
	Tools               []assist.ChatTool    `json:"tools"`
	ToolChoice          json.RawMessage      `json:"tool_choice"`
	MaxTokens           int                  `json:"max_tokens"`
	MaxCompletionTokens int                  `json:"max_completion_tokens"`
	Stream              bool                 `json:"stream"`
	ResponseFormat      json.RawMessage      `json:"response_format"`
	Stop                json.RawMessage      `json:"stop"`
	Temperature         *float64             `json:"temperature"`
	TopP                *float64             `json:"top_p"`
	ReasoningEffort     *string              `json:"reasoning_effort"`
	ParallelToolCalls   *bool                `json:"parallel_tool_calls"`
}

// openaiFormat reads response_format as chat completions write it, the
// schema in an object of its own.
func openaiFormat(raw json.RawMessage) (*assist.ResponseFormat, error) {
	if absent(raw) {
		return nil, nil
	}
	if err := only(raw, "response_format", "type", "json_schema"); err != nil {
		return nil, err
	}
	var outer struct {
		Type       string          `json:"type"`
		JSONSchema json.RawMessage `json:"json_schema"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil {
		return nil, fmt.Errorf("response_format: %w", err)
	}
	f := formatIn{Type: outer.Type}
	switch {
	case outer.Type == "json_schema" && absent(outer.JSONSchema):
		return nil, errors.New("response_format json_schema carries the schema in json_schema")
	case outer.Type == "json_schema":
		if err := only(outer.JSONSchema, "response_format.json_schema", "name", "description", "schema", "strict"); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(outer.JSONSchema, &f); err != nil {
			return nil, fmt.Errorf("response_format.json_schema: %w", err)
		}
		f.Type = "json_schema"
	case !absent(outer.JSONSchema):
		return nil, errors.New("response_format carries json_schema only with the type json_schema")
	}
	return f.format("response_format", false)
}

// stops reads stop sequences given as one string or a list of them.
func stops(raw json.RawMessage) ([]string, error) {
	if absent(raw) {
		return nil, nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return nil, errors.New("stop is a string or a list of them")
	}
	return many, nil
}

// readToolChoice reads a tool choice as OpenAI's chat completions and
// Responses APIs write it: a word, or an object naming one function, in
// either API's shape. A named choice stays named: widening it to "any
// tool" would let the model call a tool the caller did not ask for. Any
// other object, a list of allowed tools or a tool the provider runs, is
// refused, for the same reason: read as "any tool", it would force a call
// where the caller may have allowed none.
func readToolChoice(raw json.RawMessage) (choice, name string, err error) {
	if absent(raw) {
		return "", "", nil
	}
	if json.Unmarshal(raw, &choice) == nil {
		return choice, "", nil
	}
	var named struct {
		Type     string `json:"type"`
		Name     string `json:"name"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &named) != nil {
		return "", "", errors.New("tool_choice is a word, or an object naming one function")
	}
	if named.Type != "function" {
		return "", "", fmt.Errorf("tool_choice is a word, or an object naming one function, not one of type %q", named.Type)
	}
	name = named.Function.Name
	if name == "" {
		name = named.Name
	}
	if name == "" {
		return "", "", errors.New("tool_choice names its function")
	}
	return "required", name, nil
}

// ReadOpenAI reads a chat completion request.
func ReadOpenAI(r io.Reader) (Request, error) {
	b, err := openaiFields.body(r)
	if err != nil {
		return Request{}, err
	}
	var in openaiRequest
	if err := json.Unmarshal(b, &in); err != nil {
		return Request{}, fmt.Errorf("the request is not a chat completion: %w", err)
	}
	out := Request{Model: in.Model, Stream: in.Stream, Chat: assist.ChatRequest{
		Messages: in.Messages, Tools: in.Tools, MaxTokens: in.MaxTokens,
		Temperature: in.Temperature, TopP: in.TopP,
		OneToolCall: in.ParallelToolCalls != nil && !*in.ParallelToolCalls}}
	if out.Chat.MaxTokens == 0 {
		out.Chat.MaxTokens = in.MaxCompletionTokens
	}
	if in.ReasoningEffort != nil {
		out.Chat.ReasoningEffort = *in.ReasoningEffort
	}
	if out.Chat.ToolChoice, out.Chat.ToolChoiceName, err = readToolChoice(in.ToolChoice); err != nil {
		return Request{}, err
	}
	if out.Chat.ResponseFormat, err = openaiFormat(in.ResponseFormat); err != nil {
		return Request{}, err
	}
	if out.Chat.Stop, err = stops(in.Stop); err != nil {
		return Request{}, err
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
	if r := reply.Message.Refusal; r != "" {
		message["refusal"] = r
		if text == "" {
			message["content"] = nil
		}
	}
	if stream {
		// A stream's tool calls carry their position.
		delta := map[string]any{"role": "assistant", "content": message["content"]}
		if r, ok := message["refusal"]; ok {
			delta["refusal"] = r
		}
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

var anthropicFields = fields{what: "a messages request",
	read: []string{"model", "system", "messages", "tools", "tool_choice", "max_tokens", "stream",
		"stop_sequences", "temperature", "top_p", "thinking", "output_config", "output_format"},
	// Neither changes the answer: metadata is the caller's label for its
	// user, which no provider is told, and the tier is the route's.
	quiet: []string{"metadata", "service_tier"},
	unasked: []unasked{
		{"top_k", nil, "a route is sent an OpenAI-compatible request, which has no top_k"},
	}}

type anthropicRequest struct {
	Model      string             `json:"model"`
	System     json.RawMessage    `json:"system"`
	Messages   []anthropicMessage `json:"messages"`
	Tools      []anthropicTool    `json:"tools"`
	ToolChoice *struct {
		Type                   string `json:"type"`
		Name                   string `json:"name"`
		DisableParallelToolUse bool   `json:"disable_parallel_tool_use"`
	} `json:"tool_choice"`
	MaxTokens     int             `json:"max_tokens"`
	Stream        bool            `json:"stream"`
	StopSequences []string        `json:"stop_sequences"`
	Temperature   *float64        `json:"temperature"`
	TopP          *float64        `json:"top_p"`
	Thinking      json.RawMessage `json:"thinking"`
	OutputConfig  json.RawMessage `json:"output_config"`
	// OutputFormat is where structured output was asked for while it was
	// in beta, and where clients written then still ask for it.
	OutputFormat json.RawMessage `json:"output_format"`
}

// anthropicEffort is how hard a request asks the model to think, as an
// OpenAI-compatible route takes it: output_config's effort, or else its
// thinking budget. A budget counts tokens, which such a route does not
// take, so it is sent as the nearest effort: under 4,096 tokens low,
// under 16,384 medium, and more high. Adaptive thinking leaves it to the
// model, as a route does when it is sent none.
func anthropicEffort(thinking json.RawMessage, effort string) (string, error) {
	if err := only(thinking, "thinking", "type", "budget_tokens"); err != nil {
		return "", err
	}
	var t struct {
		Type   string `json:"type"`
		Budget int    `json:"budget_tokens"`
	}
	if !absent(thinking) {
		if err := json.Unmarshal(thinking, &t); err != nil {
			return "", fmt.Errorf("thinking: %w", err)
		}
	}
	budgeted := ""
	switch t.Type {
	case "", "disabled", "adaptive":
	case "enabled":
		switch {
		case t.Budget < 4096:
			budgeted = "low"
		case t.Budget < 16384:
			budgeted = "medium"
		default:
			budgeted = "high"
		}
	default:
		return "", fmt.Errorf("thinking is enabled, adaptive or disabled, not %q", t.Type)
	}
	switch effort {
	case "":
		return budgeted, nil
	case "low", "medium", "high":
		return effort, nil
	case "max":
		return "xhigh", nil
	}
	return "", fmt.Errorf("output_config.effort is low, medium, high or max, not %q", effort)
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
	b, err := anthropicFields.body(r)
	if err != nil {
		return Request{}, err
	}
	var in anthropicRequest
	if err := json.Unmarshal(b, &in); err != nil {
		return Request{}, fmt.Errorf("the request is not a messages request: %w", err)
	}
	out := Request{Model: in.Model, Stream: in.Stream, Chat: assist.ChatRequest{MaxTokens: in.MaxTokens,
		Stop: in.StopSequences, Temperature: in.Temperature, TopP: in.TopP}}
	if err := only(in.OutputConfig, "output_config", "format", "effort"); err != nil {
		return Request{}, err
	}
	var config struct {
		Format json.RawMessage `json:"format"`
		Effort string          `json:"effort"`
	}
	if !absent(in.OutputConfig) {
		if err := json.Unmarshal(in.OutputConfig, &config); err != nil {
			return Request{}, fmt.Errorf("output_config: %w", err)
		}
	}
	if out.Chat.ReasoningEffort, err = anthropicEffort(in.Thinking, config.Effort); err != nil {
		return Request{}, err
	}
	if !absent(config.Format) && !absent(in.OutputFormat) {
		return Request{}, errors.New("an answer's format is given once: output_config.format, or output_format")
	}
	format, what := config.Format, "output_config.format"
	if absent(format) {
		format, what = in.OutputFormat, "output_format"
	}
	// Anthropic's structured output always fits its schema: the model is
	// held to it as it writes, so the answer here is held to it too.
	if out.Chat.ResponseFormat, err = readFormat(format, what, true, "type", "schema"); err != nil {
		return Request{}, err
	}
	if f := out.Chat.ResponseFormat; f != nil && f.Type != "json_schema" {
		return Request{}, fmt.Errorf("%s is json_schema", what)
	}
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
		case "any":
			out.Chat.ToolChoice = "required"
		case "tool":
			out.Chat.ToolChoice, out.Chat.ToolChoiceName = "required", c.Name
		default:
			return Request{}, fmt.Errorf("tool_choice is auto, any, tool or none, not %q", c.Type)
		}
		out.Chat.OneToolCall = c.DisableParallelToolUse
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
	// A refusal is said in words, with the stop reason Anthropic's own
	// models give one.
	if r := reply.Message.Refusal; r != "" {
		content = append(content, map[string]any{"type": "text", "text": r})
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
	case reply.Message.Refusal != "":
		stop = "refusal"
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

var responsesFields = fields{what: "a responses request",
	read: []string{"model", "instructions", "input", "tools", "tool_choice", "max_output_tokens", "stream",
		"previous_response_id", "conversation", "temperature", "top_p", "text", "reasoning",
		"parallel_tool_calls", "include"},
	// As for chat completions (see openaiFields), and: truncation, which
	// only says what the provider does with a conversation too long for
	// its model, where here it is refused rather than shortened; and
	// max_tool_calls, which bounds the tools the provider runs itself,
	// and here it runs none.
	quiet: []string{"stream_options", "metadata", "user", "safety_identifier", "store", "service_tier",
		"prompt_cache_key", "prompt_cache_retention", "truncation", "max_tool_calls"},
	unasked: []unasked{
		topLogprobsField,
		{"background", []any{false}, "nothing runs in the background here: the answer comes back with the request"},
		{"prompt", nil, "a prompt kept at OpenAI is not here to read: send its instructions"},
	}}

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
	Temperature        *float64        `json:"temperature"`
	TopP               *float64        `json:"top_p"`
	Text               json.RawMessage `json:"text"`
	Reasoning          json.RawMessage `json:"reasoning"`
	ParallelToolCalls  *bool           `json:"parallel_tool_calls"`
	Include            []string        `json:"include"`
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
	b, err := responsesFields.body(r)
	if err != nil {
		return Request{}, err
	}
	var in responsesRequest
	if err := json.Unmarshal(b, &in); err != nil {
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
	if out.Chat.ToolChoice, out.Chat.ToolChoiceName, err = readToolChoice(in.ToolChoice); err != nil {
		return Request{}, err
	}
	out.Chat.Temperature, out.Chat.TopP = in.Temperature, in.TopP
	out.Chat.OneToolCall = in.ParallelToolCalls != nil && !*in.ParallelToolCalls
	if err := only(in.Text, "text", "format", "verbosity"); err != nil {
		return Request{}, err
	}
	var text struct {
		Format    json.RawMessage `json:"format"`
		Verbosity json.RawMessage `json:"verbosity"`
	}
	if !absent(in.Text) {
		if err := json.Unmarshal(in.Text, &text); err != nil {
			return Request{}, fmt.Errorf("text: %w", err)
		}
	}
	if asks(text.Verbosity, "medium") {
		return Request{}, errors.New("text.verbosity: " + verbosity)
	}
	if out.Chat.ResponseFormat, err = readFormat(text.Format, "text.format", false,
		"type", "name", "description", "schema", "strict"); err != nil {
		return Request{}, err
	}
	// A summary of the model's reasoning is not an answer, and is not
	// always given even by OpenAI, so asking for one is not refused; the
	// effort is passed on.
	if err := only(in.Reasoning, "reasoning", "effort", "summary", "generate_summary"); err != nil {
		return Request{}, err
	}
	var reasoning struct {
		Effort *string `json:"effort"`
	}
	if !absent(in.Reasoning) {
		if err := json.Unmarshal(in.Reasoning, &reasoning); err != nil {
			return Request{}, fmt.Errorf("reasoning: %w", err)
		}
	}
	if reasoning.Effort != nil {
		out.Chat.ReasoningEffort = *reasoning.Effort
	}
	// What include asks for is more about an item this never writes (the
	// model's reasoning, a tool the provider runs), so there is nothing to
	// add, except log probabilities, which a message would carry.
	for _, what := range in.Include {
		if what == "message.output_text.logprobs" {
			return Request{}, errors.New("include: " + logprobsField.why)
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
	text, refusal := reply.Message.Text(), reply.Message.Refusal
	if text != "" || refusal != "" || len(reply.Message.ToolCalls) == 0 {
		var parts []any
		if text != "" || refusal == "" {
			parts = append(parts, map[string]any{"type": "output_text", "text": text, "annotations": []any{}})
		}
		if refusal != "" {
			parts = append(parts, map[string]any{"type": "refusal", "refusal": refusal})
		}
		output = append(output, map[string]any{"type": "message", "id": fmt.Sprintf("msg_%d", now.UnixNano()),
			"status": "completed", "role": "assistant", "content": parts})
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
			opening := map[string]any{"type": "message", "id": itemID, "status": "in_progress", "role": "assistant", "content": []any{}}
			event("response.output_item.added", map[string]any{"output_index": i, "item": opening})
			for j, p := range item["content"].([]any) {
				part := p.(map[string]any)
				at := map[string]any{"item_id": itemID, "output_index": i, "content_index": j}
				with := func(k string, v any) map[string]any {
					m := map[string]any{k: v}
					for k, v := range at {
						m[k] = v
					}
					return m
				}
				if part["type"] == "refusal" {
					event("response.content_part.added", with("part", map[string]any{"type": "refusal", "refusal": ""}))
					event("response.refusal.delta", with("delta", part["refusal"]))
					event("response.refusal.done", with("refusal", part["refusal"]))
				} else {
					empty := map[string]any{"type": "output_text", "text": "", "annotations": []any{}}
					event("response.content_part.added", with("part", empty))
					delta := with("delta", part["text"])
					delta["logprobs"] = []any{}
					event("response.output_text.delta", delta)
					done := with("text", part["text"])
					done["logprobs"] = []any{}
					event("response.output_text.done", done)
				}
				event("response.content_part.done", with("part", part))
			}
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
