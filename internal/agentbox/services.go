// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentbox

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/mcp"
)

// The services handed into a box, on this side of it.

// RunServer is the agent interface for one run: each call one step of
// the run through the bridge, which holds only the manifest's capabilities
// and tools. catalog is the store's operations, as its own interface
// describes them.
func RunServer(b *Bridge, m agent.Manifest, catalog []mcp.Operation, version string) *mcp.Server {
	s := mcp.NewServer("quilzo-run", version)
	// The run is the authority: every call is one of its steps, and the
	// session refuses what the manifest does not hold.
	s.Authorise = func(mcp.Operation) error { return nil }
	byName := map[string]mcp.Operation{}
	for _, op := range catalog {
		byName[op.Name] = op
	}
	step := func(a agent.Action) mcp.Handler {
		return func(args map[string]any) (any, error) {
			a.Input = args
			r, err := b.Call(context.Background(), a)
			switch {
			case err != nil:
				return nil, &mcp.Refusal{Reason: err.Error()}
			case r.Refused:
				return nil, &mcp.Refusal{Reason: strings.TrimPrefix(r.Body, "refused: ")}
			case r.Failed:
				return nil, errors.New(strings.TrimPrefix(r.Body, "failed: "))
			}
			return r.Body, nil
		}
	}
	// Every operation the store offers, not only the ones the manifest
	// holds: asking for one it does not hold is then a step the run
	// refuses and records, as it is for a model, and the watch that counts
	// an agent reaching for what it was never given sees a program do it.
	held := map[string]bool{}
	for _, c := range m.Capabilities {
		held[c] = true
		if _, ok := byName[c]; !ok {
			byName[c] = mcp.Operation{Name: c, Summary: c}
		}
	}
	for name, op := range byName {
		if !held[name] {
			op.Summary += " (this agent does not hold it; asking is refused and recorded)"
		}
		// Remembering changes what later runs recall: a write, through
		// quilzo_write, though it changes no content.
		op.Writes, op.NeedsRole = agent.IsWrite(name) || name == "remember", ""
		s.Register(op, step(agent.Action{Op: name}))
	}
	for _, t := range m.Tools {
		s.Register(mcp.Operation{Name: "tool:" + t.Name, Summary: t.Purpose, Writes: true,
			Keywords: []string{"tool", t.Name}}, step(agent.Action{Tool: t.Name}))
	}
	return s
}

// Bearer checks the run's credential on a request to a service in the box.
func Bearer(r *http.Request, secret string) bool {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && secret != "" && subtle.ConstantTimeCompare([]byte(got), []byte(secret)) == 1
}

// Models is the model endpoint in a box: the shape of OpenAI's chat
// completions, answered by the model gateway, so a program built for any
// provider works and no provider's key is ever inside. What it spends is
// charged to the run.
type Models struct {
	Secret string
	// Complete answers a conversation flattened to a system prompt and the
	// rest, with the tokens the provider reported.
	Complete func(ctx context.Context, system, user string) (text string, in, out int, err error)
	// Name is the model the box is told it is talking to.
	Name string
}

type chatMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// text is a message's content: a string, or the parts a newer client
// sends, of which the text ones are kept.
func (m chatMessage) text() string {
	var s string
	if json.Unmarshal(m.Content, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(m.Content, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			if p.Type == "text" {
				b.WriteString(p.Text)
			}
		}
		return b.String()
	}
	return ""
}

func (h *Models) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !Bearer(r, h.Secret) {
		writeError(w, http.StatusUnauthorized, "the run's credential is needed (Authorization: Bearer)")
		return
	}
	name := h.Name
	if name == "" {
		name = "quilzo"
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list",
			"data": []any{map[string]any{"id": name, "object": "model", "owned_by": "quilzo"}}})
		return
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
	default:
		writeError(w, http.StatusNotFound, "this endpoint answers POST /v1/chat/completions and GET /v1/models")
		return
	}
	var req chatRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "the request is not a chat completion: "+err.Error())
		return
	}
	var system, rest strings.Builder
	for _, m := range req.Messages {
		t := m.text()
		if m.Role == "system" || m.Role == "developer" {
			system.WriteString(t + "\n")
			continue
		}
		fmt.Fprintf(&rest, "%s: %s\n", m.Role, t)
	}
	if rest.Len() == 0 {
		writeError(w, http.StatusBadRequest, "a conversation needs at least one message that is not a system prompt")
		return
	}
	text, in, out, err := h.Complete(r.Context(), system.String(), rest.String())
	if err != nil {
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	id := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
	usage := map[string]int{"prompt_tokens": in, "completion_tokens": out, "total_tokens": in + out}
	if req.Stream {
		// The whole answer in one chunk: honest about having it all at once,
		// and enough for every client that asked for a stream.
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := map[string]any{"id": id, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": name,
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "content": text}, "finish_reason": "stop"}},
			"usage":   usage}
		b, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", b)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "object": "chat.completion", "created": time.Now().Unix(),
		"model": name, "usage": usage,
		"choices": []any{map[string]any{"index": 0, "finish_reason": "stop",
			"message": map[string]any{"role": "assistant", "content": text}}}})
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": msg, "type": "quilzo"}})
}
