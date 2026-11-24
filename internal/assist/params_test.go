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

// sent is a provider that keeps the last request it was sent and answers
// with status, or 200.
func sent(t *testing.T, status int) (*HTTPModel, *map[string]any) {
	t.Helper()
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = nil
		_ = json.Unmarshal(b, &got)
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
			io.WriteString(w, `{"error":{"message":"temperature is not supported by this model"}}`)
			return
		}
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]}`)
	}))
	t.Cleanup(srv.Close)
	return &HTTPModel{BaseURL: srv.URL, Model: "m", Client: srv.Client()}, &got
}

func clickRequest() ChatRequest {
	return ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: []Part{{Type: "text", Text: "submit"}}}},
		Tools: []ChatTool{
			{Type: "function", Function: ToolFunction{Name: "click", Parameters: json.RawMessage(`{"type":"object"}`)}},
			{Type: "function", Function: ToolFunction{Name: "type", Parameters: json.RawMessage(`{"type":"object"}`)}},
		},
		MaxTokens: 100,
	}
}

// A route that asks for nothing sends nothing beyond the conversation and
// the caller's own limit, so a model that refuses a temperature is not
// sent one.
func TestNothingIsSentThatARouteDidNotAskFor(t *testing.T) {
	h, got := sent(t, 0)
	if _, err := h.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"temperature", "top_p", "top_k", "max_tokens", "max_completion_tokens"} {
		if _, ok := (*got)[k]; ok {
			t.Errorf("a completion sent %s that nobody asked for: %v", k, *got)
		}
	}
	if _, err := h.Chat(context.Background(), clickRequest()); err != nil {
		t.Fatal(err)
	}
	if _, ok := (*got)["temperature"]; ok {
		t.Errorf("a conversation sent a temperature: %v", *got)
	}
	if (*got)["max_tokens"] != float64(100) {
		t.Errorf("the caller's own limit was not sent: %v", *got)
	}
}

// What a route does ask for is sent, under the name its model reads.
func TestARoutesFieldsAreSentAsItNamesThem(t *testing.T) {
	h, got := sent(t, 0)
	temp, top := 0.3, 0.9
	h.Params = Params{MaxTokensField: "max_completion_tokens", Temperature: &temp, TopP: &top}
	if _, err := h.Chat(context.Background(), clickRequest()); err != nil {
		t.Fatal(err)
	}
	if (*got)["max_completion_tokens"] != float64(100) || (*got)["max_tokens"] != nil {
		t.Errorf("the limit went out as %v", *got)
	}
	if (*got)["temperature"] != 0.3 || (*got)["top_p"] != 0.9 {
		t.Errorf("the route's sampling went out as %v", *got)
	}
	// Zero is a value a route may ask for, not the same as asking nothing.
	zero := 0.0
	h.Params = Params{Temperature: &zero}
	if _, err := h.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if v, ok := (*got)["temperature"]; !ok || v != 0.0 {
		t.Errorf("a temperature of zero was not sent: %v", *got)
	}
}

// A forced choice of one tool reaches the model as that tool, not widened
// to any tool; a route whose model refuses forced choices sends auto.
func TestANamedToolChoiceIsPassedOnAsItWasMade(t *testing.T) {
	h, got := sent(t, 0)
	req := clickRequest()
	req.ToolChoice, req.ToolChoiceName = "required", "click"
	if _, err := h.Chat(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal((*got)["tool_choice"])
	if string(b) != `{"function":{"name":"click"},"type":"function"}` {
		t.Errorf("a named choice went out as %s", b)
	}
	h.Params = Params{AutoToolChoice: true}
	if _, err := h.Chat(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if (*got)["tool_choice"] != "auto" {
		t.Errorf("a route that refuses forced choices was sent %v", (*got)["tool_choice"])
	}
	req.ToolChoiceName = ""
	if _, err := h.Chat(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if (*got)["tool_choice"] != "auto" {
		t.Errorf("required went to a route that refuses forced choices as %v", (*got)["tool_choice"])
	}
	for _, bad := range []struct{ choice, name string }{{"required", "scroll"}, {"auto", "click"}, {"", "click"}} {
		r := clickRequest()
		r.ToolChoice, r.ToolChoiceName = bad.choice, bad.name
		if r.Check() == nil {
			t.Errorf("a choice of %q with %q was accepted", bad.name, bad.choice)
		}
	}
}

// A provider's refusal keeps its status, so the gateway can tell a request
// every route would refuse from a route that is down.
func TestARefusalKeepsItsStatus(t *testing.T) {
	h, _ := sent(t, http.StatusBadRequest)
	_, err := h.Complete(context.Background(), "s", "u")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusBadRequest {
		t.Fatalf("err = %v", err)
	}
	if _, err := h.Chat(context.Background(), clickRequest()); !errors.As(err, &se) || se.Code != http.StatusBadRequest {
		t.Fatalf("chat err = %v", err)
	}
}

// What a provider said when it refused is cut where a character starts, on
// every way a request is made. It is shown to whoever runs the gateway, and
// a provider elsewhere explains in its own language.
func TestAProvidersLongRefusalIsCutBetweenCharacters(t *testing.T) {
	kept := strings.Repeat("a", 299)
	refuse := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, kept+"中文")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { refuse(w) }))
	t.Cleanup(srv.Close)
	words := &HTTPModel{BaseURL: srv.URL, Model: "m", Client: srv.Client()}
	anthropic, _ := anthropicAt(t, func(w http.ResponseWriter, _ map[string]any) { refuse(w) })
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"complete":  func() error { _, err := words.Complete(ctx, "s", "u"); return err },
		"chat":      func() error { _, err := words.Chat(ctx, clickRequest()); return err },
		"paint":     func() error { _, err := painterAt(t, srv.URL).Paint(ctx, "a lighthouse", ""); return err },
		"anthropic": func() error { _, err := anthropic.Complete(ctx, "s", "u"); return err },
	} {
		var se *StatusError
		if err := call(); !errors.As(err, &se) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if se.Body != kept {
			t.Errorf("%s: %d bytes, ending %q", name, len(se.Body), se.Body[len(se.Body)-3:])
		}
	}
}

// The same, on the ways a request is made for something other than words:
// an embedding, speech, a transcript, a film.
func TestAProvidersLongRefusalOfMediaIsCutBetweenCharacters(t *testing.T) {
	kept := strings.Repeat("a", 299)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, kept+"中文")
	}))
	t.Cleanup(srv.Close)
	h := &HTTPModel{BaseURL: srv.URL, Model: "m", Client: srv.Client()}
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"embed":      func() error { _, _, err := h.Embed(ctx, []string{"a question"}); return err },
		"speak":      func() error { _, _, err := h.Speak(ctx, "hello", "alloy"); return err },
		"transcribe": func() error { _, _, err := h.Transcribe(ctx, []byte("RIFF"), "a.wav", "en"); return err },
		"film": func() error {
			veo := *h
			veo.Wire = WireVeo
			_, _, err := veo.Film(ctx, "a lighthouse", "16:9")
			return err
		},
	} {
		var se *StatusError
		if err := call(); !errors.As(err, &se) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if se.Body != kept {
			t.Errorf("%s: %d bytes, ending %q", name, len(se.Body), se.Body[len(se.Body)-3:])
		}
	}
}
