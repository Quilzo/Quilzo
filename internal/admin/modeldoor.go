// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/modelapi"
)

// The model door: the model gateway, served to agents built anywhere.
//
// An agent made with any framework talks to its model in one of three
// shapes: OpenAI's chat completions or responses, or Anthropic's messages.
// At /v1 the admin answers all three through the model gateway, so the provider's key
// stays here, and every call is charged to the person whose Quilzo token
// it carries, against their budget, through the privacy guard, on the
// ledger and in the audit log. An agent is pointed here by changing its
// base address and its key, and nothing else.
//
// Naming one of this store's agents as the model, agent/NAME, brings what
// that agent remembers about the person into the conversation and lets
// the model remember more, under the agent's declaration.
//
// Off until an administrator turns it on (models.remote). The admin's own
// session never works here: only a token presented with the request.

// ModelDoor is what the admin needs to serve it.
type ModelDoor struct {
	// Enabled says whether the door answers at all.
	Enabled func() bool
	// Models are the names a caller may give as the model.
	Models func(c *mcp.Caller) []string
	// Chat answers a conversation for a caller. shape is "openai",
	// "responses" or "anthropic", for the record; model is the name the
	// caller gave.
	Chat func(r *http.Request, c *mcp.Caller, shape, model string, req assist.ChatRequest) (assist.ChatReply, error)
}

// ModelRefusal is a call the door refuses, with the status it is answered
// with.
type ModelRefusal struct {
	Code int
	Why  string
}

func (e *ModelRefusal) Error() string { return e.Why }

// doorStatus is the status an error is answered with.
func doorStatus(err error) int {
	var refused *ModelRefusal
	switch {
	case errors.As(err, &refused):
		return refused.Code
	case errors.Is(err, gateway.ErrBudget):
		return http.StatusTooManyRequests
	case errors.Is(err, gateway.ErrNoRoute):
		return http.StatusServiceUnavailable
	case errors.Is(err, gateway.ErrPictureNotAllowed):
		return http.StatusBadRequest
	}
	return http.StatusBadGateway
}

// doorToken is the token a request carries: as OpenAI's clients send a
// key, or as Anthropic's do.
func doorToken(r *http.Request) string {
	if t, _ := authzToken(r); t != "" {
		return t
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

func (s *Server) handleModelDoor(w http.ResponseWriter, r *http.Request) {
	d := s.ModelDoor
	if d == nil || d.Enabled == nil || !d.Enabled() {
		http.NotFound(w, r)
		return
	}
	anthropic := r.URL.Path == "/v1/messages" || (r.URL.Path == "/v1/models" && r.Header.Get("Anthropic-Version") != "")
	fail := modelapi.OpenAIError
	if anthropic {
		fail = modelapi.AnthropicError
	}
	if s.shieldedOff(w, "models") {
		return
	}
	token := doorToken(r)
	if token == "" {
		tokenChallenge(w, "", nil)
		fail(w, http.StatusUnauthorized, "a Quilzo token is needed, as the API key: Authorization: Bearer, or x-api-key")
		return
	}
	c, err := s.interfaceCaller(r, token, "")
	if err != nil {
		tokenChallenge(w, "", err)
		fail(w, http.StatusUnauthorized, err.Error())
		return
	}
	switch {
	case r.URL.Path == "/v1/models" && r.Method == http.MethodGet:
		var names []string
		if d.Models != nil {
			names = d.Models(c)
		}
		if anthropic {
			modelapi.WriteAnthropicModels(w, names)
		} else {
			modelapi.WriteModels(w, names)
		}
		return
	case r.URL.Path == "/v1/models", r.Method != http.MethodPost:
		w.Header().Set("Allow", http.MethodPost)
		fail(w, http.StatusMethodNotAllowed, "a conversation is sent with POST")
		return
	}
	read, write, shape := modelapi.ReadOpenAI, modelapi.WriteOpenAI, "openai"
	switch {
	case anthropic:
		read, write, shape = modelapi.ReadAnthropic, modelapi.WriteAnthropic, "anthropic"
	case r.URL.Path == "/v1/responses":
		read, write, shape = modelapi.ReadResponses, modelapi.WriteResponses, "responses"
	}
	req, err := read(r.Body)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if d.Chat == nil {
		fail(w, http.StatusServiceUnavailable, "this build was started without the model gateway")
		return
	}
	reply, err := d.Chat(r, c, shape, req.Model, req.Chat)
	if err != nil {
		fail(w, doorStatus(err), err.Error())
		return
	}
	name := req.Model
	if name == "" {
		name = "quilzo"
	}
	write(w, name, reply, req.Stream)
}
