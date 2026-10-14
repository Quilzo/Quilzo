// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentbox

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/modelapi"
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
	// Chat answers a whole conversation: pictures, the tools offered and the
	// tool the model chose. A program that looks at a screen, or an agent
	// framework that calls tools, needs it; a conversation that is only text
	// still goes through Complete. Nil refuses pictures and tools, saying
	// so, rather than dropping them and answering something else.
	Chat func(ctx context.Context, req assist.ChatRequest) (assist.ChatReply, error)
	// Name is the model the box is told it is talking to.
	Name string
}

// whole reports whether a conversation needs to go as it is: it carries a
// picture, offers a tool, or continues one.
func whole(r assist.ChatRequest) bool {
	if len(r.Tools) > 0 {
		return true
	}
	for _, m := range r.Messages {
		if m.Images() > 0 || len(m.ToolCalls) > 0 || m.Role == "tool" {
			return true
		}
	}
	return false
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
		modelapi.WriteModels(w, []string{name})
		return
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
	default:
		writeError(w, http.StatusNotFound, "this endpoint answers POST /v1/chat/completions and GET /v1/models")
		return
	}
	req, err := modelapi.ReadOpenAI(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var reply assist.ChatReply
	if whole(req.Chat) {
		if h.Chat == nil {
			writeError(w, http.StatusBadRequest, "this run's model takes text only: pictures and tools are not passed on")
			return
		}
		if reply, err = h.Chat(r.Context(), req.Chat); err != nil {
			writeError(w, http.StatusTooManyRequests, err.Error())
			return
		}
	} else {
		var system, rest strings.Builder
		for _, m := range req.Chat.Messages {
			t := m.Text()
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
		reply = assist.ChatReply{Message: assist.ChatMessage{Role: "assistant",
			Content: []assist.Part{{Type: "text", Text: text}}}, Usage: assist.Usage{In: in, Out: out}}
	}
	modelapi.WriteOpenAI(w, name, reply, req.Stream)
}

func writeError(w http.ResponseWriter, code int, msg string) { modelapi.OpenAIError(w, code, msg) }
