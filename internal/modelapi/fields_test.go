// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package modelapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assist"
)

// The three shapes, each a function of the fields to add to a request
// that is otherwise fine.
var shapes = map[string]struct {
	read func(io.Reader) (Request, error)
	base string
}{
	"chat completions": {ReadOpenAI, `"model":"m","messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]`},
	"responses": {ReadResponses, `"model":"m","input":"hi",
		"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]`},
	"messages": {ReadAnthropic, `"model":"m","max_tokens":10,"messages":[{"role":"user","content":"hi"}],
		"tools":[{"name":"lookup","input_schema":{"type":"object"}}]`},
}

func ask(t *testing.T, shape, more string) (Request, error) {
	t.Helper()
	s := shapes[shape]
	body := "{" + s.base
	if more != "" {
		body += "," + more
	}
	return s.read(strings.NewReader(body + "}"))
}

// A field none of the shapes' tables names is refused, by its name, in
// every shape: passed over, it could have been a format or a seed the
// caller is counting on.
func TestAFieldNothingReadsIsRefusedByName(t *testing.T) {
	for shape := range shapes {
		if _, err := ask(t, shape, ""); err != nil {
			t.Fatalf("%s: the plain request was refused: %v", shape, err)
		}
		for more, names := range map[string][]string{
			`"frobnicate":true`:                 {`"frobnicate"`},
			`"Temperature":0.2`:                 {`"Temperature"`},
			`"guided_json":{},"repetition":1.1`: {`"guided_json"`, `"repetition"`},
		} {
			_, err := ask(t, shape, more)
			if err == nil {
				t.Errorf("%s: %s was accepted", shape, more)
				continue
			}
			for _, n := range names {
				if !strings.Contains(err.Error(), n) {
					t.Errorf("%s: the refusal of %s does not name %s: %v", shape, more, n, err)
				}
			}
		}
	}
}

// Fields that do not change the answer are accepted, and the request
// read as it would be without them.
func TestFieldsThatDoNotChangeTheAnswerAreAccepted(t *testing.T) {
	for shape, more := range map[string][]string{
		"chat completions": {`"stream_options":{"include_usage":true}`, `"metadata":{"run":"7"}`, `"user":"u-1"`,
			`"safety_identifier":"h"`, `"store":true`, `"service_tier":"auto"`, `"prompt_cache_key":"k"`,
			`"prompt_cache_retention":"24h"`, `"prediction":{"type":"content","content":"x"}`,
			`"n":1`, `"seed":null`, `"logprobs":false`, `"top_logprobs":0`, `"logit_bias":{}`,
			`"frequency_penalty":0`, `"presence_penalty":0.0`, `"verbosity":"medium"`, `"modalities":["text"]`,
			`"response_format":{"type":"text"}`},
		"responses": {`"store":false`, `"metadata":{}`, `"user":"u-1"`, `"truncation":"auto"`, `"max_tool_calls":3`,
			`"service_tier":"default"`, `"prompt_cache_key":"k"`, `"background":false`, `"top_logprobs":0`,
			`"include":["reasoning.encrypted_content"]`, `"reasoning":{"summary":"auto"}`,
			`"text":{"format":{"type":"text"},"verbosity":"medium"}`, `"stream_options":{"include_obfuscation":false}`},
		"messages": {`"metadata":{"user_id":"u-1"}`, `"service_tier":"auto"`, `"top_k":null`,
			`"thinking":{"type":"disabled"}`, `"thinking":{"type":"adaptive"}`},
	} {
		for _, m := range more {
			r, err := ask(t, shape, m)
			if err != nil {
				t.Errorf("%s: %s was refused: %v", shape, m, err)
				continue
			}
			c := r.Chat
			if c.ResponseFormat != nil || c.Stop != nil || c.Temperature != nil || c.ReasoningEffort != "" || c.OneToolCall {
				t.Errorf("%s: %s asked something of the answer: %+v", shape, m, c)
			}
		}
	}
}

// Fields nothing here can honour are refused, saying why, unless they ask
// for nothing.
func TestFieldsNothingHereCanHonourAreRefused(t *testing.T) {
	for shape, more := range map[string][]string{
		"chat completions": {`"n":2`, `"seed":42`, `"logprobs":true`, `"top_logprobs":3`, `"logit_bias":{"50256":-100}`,
			`"frequency_penalty":0.5`, `"presence_penalty":-1`, `"verbosity":"low"`, `"modalities":["text","audio"]`,
			`"audio":{"voice":"alloy"}`, `"functions":[{"name":"f"}]`, `"function_call":"auto"`,
			`"web_search_options":{}`, `"response_format":{"type":"yaml"}`,
			`"response_format":{"type":"json_schema"}`, `"response_format":{"type":"json_object","json_schema":{}}`,
			`"response_format":{"type":"json_schema","json_schema":{"schema":{},"cache":true}}`,
			`"stop":["a","b","c","d","e"]`, `"stop":7`, `"temperature":2.5`, `"top_p":0`, `"reasoning_effort":"extreme"`,
			`"tool_choice":"required","tools":[]`,
			`"tool_choice":{"type":"allowed_tools","allowed_tools":{"mode":"auto","tools":[]}}`,
			`"tool_choice":{"type":"function","function":{}}`, `"tool_choice":{"function":{"name":"lookup"}}`, `"tool_choice":7`},
		"responses": {`"background":true`, `"prompt":{"id":"pmpt_1"}`, `"top_logprobs":2`,
			`"include":["message.output_text.logprobs"]`, `"text":{"verbosity":"low"}`, `"text":{"tone":"dry"}`,
			`"text":{"format":{"type":"json_schema","schema":{},"cache":1}}`, `"reasoning":{"effort":"high","depth":3}`,
			`"stop":["END"]`, `"seed":1`, `"n":1`, `"temperature":-1`, `"tool_choice":{"type":"file_search"}`,
			`"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"function","name":"lookup"}]}`},
		"messages": {`"top_k":40`, `"output_config":{"format":{"type":"json_schema","schema":{}},"tone":"dry"}`,
			`"output_config":{"effort":"most"}`, `"thinking":{"type":"enabled","budget_tokens":2048,"style":"x"}`,
			`"thinking":{"type":"sometimes"}`, `"output_format":{"type":"json_object"}`,
			`"output_format":{"type":"json_schema","schema":{}},"output_config":{"format":{"type":"json_schema","schema":{}}}`,
			`"mcp_servers":[]`, `"container":"c1"`, `"stop_sequences":[""]`},
	} {
		for _, m := range more {
			if _, err := ask(t, shape, m); err == nil {
				t.Errorf("%s: %s was accepted", shape, m)
			}
		}
	}
	if _, err := ask(t, "chat completions", `"seed":42`); err == nil || !strings.Contains(err.Error(), "seed: nothing here can promise") {
		t.Errorf("a refused seed does not say why: %v", err)
	}
}

const schema = `{"type":"object","properties":{"city":{"type":"string"}},"required":["city"],"additionalProperties":false}`

// What changes the answer is carried into the conversation, from each
// shape's own way of writing it.
func TestWhatChangesTheAnswerIsCarriedFromEveryShape(t *testing.T) {
	format := func(shape, more string) *assist.ResponseFormat {
		t.Helper()
		r, err := ask(t, shape, more)
		if err != nil {
			t.Fatalf("%s: %s: %v", shape, more, err)
		}
		if r.Chat.ResponseFormat == nil {
			t.Fatalf("%s: %s: no format", shape, more)
		}
		return r.Chat.ResponseFormat
	}
	for _, c := range []struct {
		shape, more, name string
		strict            bool
	}{
		{"chat completions", `"response_format":{"type":"json_schema","json_schema":{"name":"weather","strict":true,"schema":` + schema + `}}`, "weather", true},
		{"chat completions", `"response_format":{"type":"json_schema","json_schema":{"name":"weather","schema":` + schema + `}}`, "weather", false},
		{"responses", `"text":{"format":{"type":"json_schema","name":"weather","strict":true,"schema":` + schema + `}}`, "weather", true},
		{"responses", `"text":{"format":{"type":"json_schema","name":"weather","schema":` + schema + `}}`, "weather", false},
		// Anthropic's structured output always fits its schema.
		{"messages", `"output_config":{"format":{"type":"json_schema","schema":` + schema + `}}`, "", true},
		{"messages", `"output_format":{"type":"json_schema","schema":` + schema + `}`, "", true},
	} {
		f := format(c.shape, c.more)
		if f.Type != "json_schema" || f.Name != c.name || f.Strict != c.strict || !json.Valid(f.Schema) ||
			!strings.Contains(string(f.Schema), `"city"`) {
			t.Errorf("%s: %s read as %+v", c.shape, c.more, f)
		}
	}
	for shape, more := range map[string]string{
		"chat completions": `"response_format":{"type":"json_object"}`,
		"responses":        `"text":{"format":{"type":"json_object"}}`,
	} {
		if f := format(shape, more); f.Type != "json_object" || f.Strict {
			t.Errorf("%s: %+v", shape, f)
		}
	}

	f := func(v float64) *float64 { return &v }
	for _, c := range []struct {
		shape, more string
		want        assist.ChatRequest
	}{
		{"chat completions", `"stop":"END"`, assist.ChatRequest{Stop: []string{"END"}}},
		{"chat completions", `"stop":["END","\n\n"]`, assist.ChatRequest{Stop: []string{"END", "\n\n"}}},
		{"messages", `"stop_sequences":["END","Human:"]`, assist.ChatRequest{Stop: []string{"END", "Human:"}}},
		{"chat completions", `"temperature":0.2,"top_p":0.9`, assist.ChatRequest{Temperature: f(0.2), TopP: f(0.9)}},
		{"responses", `"temperature":0,"top_p":1`, assist.ChatRequest{Temperature: f(0), TopP: f(1)}},
		{"messages", `"temperature":0.5,"top_p":0.8`, assist.ChatRequest{Temperature: f(0.5), TopP: f(0.8)}},
		{"chat completions", `"reasoning_effort":"high"`, assist.ChatRequest{ReasoningEffort: "high"}},
		{"responses", `"reasoning":{"effort":"low","summary":"detailed"}`, assist.ChatRequest{ReasoningEffort: "low"}},
		{"messages", `"output_config":{"effort":"medium"}`, assist.ChatRequest{ReasoningEffort: "medium"}},
		{"messages", `"output_config":{"effort":"max"}`, assist.ChatRequest{ReasoningEffort: "xhigh"}},
		{"messages", `"thinking":{"type":"enabled","budget_tokens":1024}`, assist.ChatRequest{ReasoningEffort: "low"}},
		{"messages", `"thinking":{"type":"enabled","budget_tokens":10000}`, assist.ChatRequest{ReasoningEffort: "medium"}},
		{"messages", `"thinking":{"type":"enabled","budget_tokens":31999}`, assist.ChatRequest{ReasoningEffort: "high"}},
		{"messages", `"thinking":{"type":"enabled","budget_tokens":31999},"output_config":{"effort":"low"}`,
			assist.ChatRequest{ReasoningEffort: "low"}},
		{"chat completions", `"parallel_tool_calls":false`, assist.ChatRequest{OneToolCall: true}},
		{"responses", `"parallel_tool_calls":false`, assist.ChatRequest{OneToolCall: true}},
		{"messages", `"tool_choice":{"type":"auto","disable_parallel_tool_use":true}`, assist.ChatRequest{OneToolCall: true}},
		{"chat completions", `"parallel_tool_calls":true`, assist.ChatRequest{}},
	} {
		r, err := ask(t, c.shape, c.more)
		if err != nil {
			t.Errorf("%s: %s: %v", c.shape, c.more, err)
			continue
		}
		got, want := r.Chat, c.want
		same := strings.Join(got.Stop, "|") == strings.Join(want.Stop, "|") && got.ReasoningEffort == want.ReasoningEffort &&
			got.OneToolCall == want.OneToolCall && equalPtr(got.Temperature, want.Temperature) && equalPtr(got.TopP, want.TopP)
		if !same {
			t.Errorf("%s: %s read as stop %q, effort %q, one call %v, temperature %v, top_p %v",
				c.shape, c.more, got.Stop, got.ReasoningEffort, got.OneToolCall, got.Temperature, got.TopP)
		}
	}
}

func equalPtr(a, b *float64) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// A model declining to answer is written back as each shape says so.
func TestARefusalIsWrittenInEveryShape(t *testing.T) {
	reply := assist.ChatReply{Message: assist.ChatMessage{Role: "assistant", Refusal: "I cannot help with that."}}

	w := httptest.NewRecorder()
	WriteOpenAI(w, "quilzo", Request{}, reply)
	var cc struct {
		Choices []struct {
			Message map[string]any `json:"message"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cc); err != nil || cc.Choices[0].Message["refusal"] != "I cannot help with that." ||
		cc.Choices[0].Message["content"] != nil {
		t.Errorf("chat completions: %s", w.Body)
	}
	w = httptest.NewRecorder()
	WriteOpenAI(w, "quilzo", Request{Stream: true}, reply)
	if !strings.Contains(w.Body.String(), `"refusal":"I cannot help with that."`) {
		t.Errorf("chat completions stream: %s", w.Body)
	}

	w = httptest.NewRecorder()
	WriteAnthropic(w, "quilzo", Request{}, reply)
	var msg struct {
		Content    []struct{ Type, Text string }
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil || msg.StopReason != "refusal" || len(msg.Content) != 1 ||
		msg.Content[0].Text != "I cannot help with that." {
		t.Errorf("messages: %s", w.Body)
	}

	w = httptest.NewRecorder()
	WriteResponses(w, "quilzo", Request{}, reply)
	var resp struct {
		Output []struct {
			Content []map[string]any
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Output) != 1 || len(resp.Output[0].Content) != 1 ||
		resp.Output[0].Content[0]["type"] != "refusal" || resp.Output[0].Content[0]["refusal"] != "I cannot help with that." {
		t.Errorf("responses: %s", w.Body)
	}
	w = httptest.NewRecorder()
	WriteResponses(w, "quilzo", Request{Stream: true}, reply)
	for _, e := range []string{"response.content_part.added", "response.refusal.delta", "response.refusal.done", "response.completed"} {
		if !strings.Contains(w.Body.String(), "event: "+e+"\n") {
			t.Errorf("the responses stream has no %s:\n%s", e, w.Body)
		}
	}
	if strings.Contains(w.Body.String(), "response.output_text.delta") {
		t.Errorf("a refusal was streamed as text:\n%s", w.Body)
	}
}

// A tool's strict, structured output for its arguments, is read in every
// shape, as each shape defaults it; and a key in a tool or a tool choice
// that nothing reads is refused by name, as one at the top is.
func TestAToolIsReadWholeOrRefused(t *testing.T) {
	for _, c := range []struct {
		shape, tools string
		strict       bool
	}{
		{"chat completions", `"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"},"strict":true}}]`, true},
		{"chat completions", `"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]`, false},
		{"responses", `"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}]`, true},
		{"responses", `"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"},"strict":false}]`, false},
		{"messages", `"tools":[{"name":"lookup","input_schema":{"type":"object"},"strict":true}]`, true},
		{"messages", `"tools":[{"name":"lookup","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}]`, false},
	} {
		s := shapes[c.shape]
		base := s.base[:strings.Index(s.base, `"tools"`)]
		r, err := s.read(strings.NewReader("{" + base + c.tools + "}"))
		if err != nil {
			t.Errorf("%s: %s: %v", c.shape, c.tools, err)
			continue
		}
		if f := r.Chat.Tools[0].Function; f.Name != "lookup" || f.Strict != c.strict {
			t.Errorf("%s: %s read as %+v", c.shape, c.tools, f)
		}
	}
	for shape, more := range map[string][]string{
		"chat completions": {
			`"tools":[{"type":"function","function":{"name":"lookup","examples":[]}}]`,
			`"tools":[{"type":"function","function":{"name":"lookup"},"cache":true}]`,
			`"tool_choice":{"type":"function","function":{"name":"lookup","only":true}}`,
			`"tool_choice":{"type":"function","name":"lookup","mode":"any"}`,
		},
		"responses": {
			`"tools":[{"type":"function","name":"lookup","parameters":{},"defer_loading":true}]`,
			`"tool_choice":{"type":"function","name":"lookup","mode":"any"}`,
		},
		"messages": {
			`"tools":[{"name":"lookup","input_schema":{},"input_examples":[{}]}]`,
			`"tool_choice":{"type":"auto","weird":1}`,
		},
	} {
		for _, m := range more {
			s := shapes[shape]
			body := "{" + s.base + "," + m + "}"
			if strings.HasPrefix(m, `"tools"`) {
				body = "{" + s.base[:strings.Index(s.base, `"tools"`)] + m + "}"
			}
			_, err := s.read(strings.NewReader(body))
			if err == nil || !strings.Contains(err.Error(), "not a field this reads") {
				t.Errorf("%s: %s came back as %v", shape, m, err)
			}
		}
	}
}

// A refusal names a few of the fields it refuses and counts the rest, so
// a body of a million strange keys is not answered with all of them.
func TestARefusalNamesAFewFieldsAndCountsTheRest(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"model":"m","messages":[{"role":"user","content":"hi"}]`)
	for i := 0; i < 100000; i++ {
		fmt.Fprintf(&b, `,"k%06d":1`, i)
	}
	b.WriteString("}")
	_, err := ReadOpenAI(strings.NewReader(b.String()))
	if err == nil || len(err.Error()) > 300 || !strings.Contains(err.Error(), `"k000000", "k000001", "k000002", "k000003", "k000004" and 99995 more`) {
		t.Errorf("%.400v", err)
	}
	_, err = ReadOpenAI(strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}],"odd":1}`))
	if err == nil || !strings.Contains(err.Error(), `"odd": not a field this reads`) {
		t.Errorf("one field: %v", err)
	}
}

// A response says back what its request asked for and was held to, not
// what a request that asked for nothing would have been given.
func TestAResponseSaysWhatWasAskedOfIt(t *testing.T) {
	req, err := ReadResponses(strings.NewReader(`{"model":"m","input":"weather?","temperature":0.2,"top_p":0.9,
		"parallel_tool_calls":false,"reasoning":{"effort":"low"},
		"tools":[{"type":"function","name":"lookup","description":"Look it up","parameters":{"type":"object"}}],
		"tool_choice":{"type":"function","name":"lookup"},
		"text":{"format":{"type":"json_schema","name":"weather","strict":true,"schema":` + schema + `}}}`))
	if err != nil {
		t.Fatal(err)
	}
	reply := assist.ChatReply{Message: assist.ChatMessage{Role: "assistant",
		Content: []assist.Part{{Type: "text", Text: `{"city":"Paris"}`}}}}
	for _, stream := range []bool{false, true} {
		req.Stream = stream
		w := httptest.NewRecorder()
		WriteResponses(w, "quilzo", req, reply)
		body := w.Body.String()
		if stream {
			at := strings.Index(body, "event: response.completed\ndata: ")
			body = strings.TrimSpace(body[at+len("event: response.completed\ndata: "):])
			var event struct{ Response json.RawMessage }
			_ = json.Unmarshal([]byte(body), &event)
			body = string(event.Response)
		}
		var resp struct {
			Text struct {
				Format struct {
					Type, Name string
					Strict     bool
					Schema     json.RawMessage
				}
			}
			ParallelToolCalls bool                        `json:"parallel_tool_calls"`
			ToolChoice        struct{ Type, Name string } `json:"tool_choice"`
			Tools             []struct {
				Name   string
				Strict bool
			}
			Temperature *float64
			TopP        *float64 `json:"top_p"`
			Reasoning   struct{ Effort string }
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatalf("stream %v: %v: %s", stream, err, body)
		}
		f := resp.Text.Format
		if f.Type != "json_schema" || f.Name != "weather" || !f.Strict || !strings.Contains(string(f.Schema), `"city"`) ||
			resp.ParallelToolCalls || resp.ToolChoice.Name != "lookup" || len(resp.Tools) != 1 || !resp.Tools[0].Strict ||
			resp.Temperature == nil || *resp.Temperature != 0.2 || resp.TopP == nil || *resp.TopP != 0.9 || resp.Reasoning.Effort != "low" {
			t.Errorf("stream %v: the response says %s", stream, body)
		}
	}

	w := httptest.NewRecorder()
	WriteResponses(w, "quilzo", Request{}, reply)
	var plain map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &plain)
	if b, _ := json.Marshal(plain["text"]); string(b) != `{"format":{"type":"text"}}` || plain["parallel_tool_calls"] != true ||
		plain["tool_choice"] != "auto" || plain["temperature"] != nil {
		t.Errorf("a request that asked for nothing: %s", w.Body)
	}
}
