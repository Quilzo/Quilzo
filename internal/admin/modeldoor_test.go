// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/gateway"
	"github.com/quilzo/quilzo/internal/mcp"
)

type doorRig struct {
	srv   *Server
	token string
	on    bool
	asked []string
	fail  error
}

func newDoorRig(t *testing.T) *doorRig {
	t.Helper()
	srv, token := emptyStore(t)
	r := &doorRig{srv: srv, token: token, on: true}
	srv.ModelDoor = &ModelDoor{
		Enabled: func() bool { return r.on },
		Models:  func(*mcp.Caller) []string { return []string{"quilzo", "agent/concierge"} },
		Chat: func(_ *http.Request, c *mcp.Caller, shape, model string, req assist.ChatRequest) (assist.ChatReply, error) {
			r.asked = append(r.asked, fmt.Sprintf("%s %s %s %s", c.Principal, shape, model, req.Messages[len(req.Messages)-1].Text()))
			if r.fail != nil {
				return assist.ChatReply{}, r.fail
			}
			return assist.ChatReply{Message: assist.ChatMessage{Role: "assistant",
				Content: []assist.Part{{Type: "text", Text: "hello " + c.Principal}}}, Usage: assist.Usage{In: 5, Out: 2}}, nil
		},
	}
	return r
}

func (r *doorRig) send(t *testing.T, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	method := "POST"
	if body == "" {
		method = "GET"
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(w, req)
	return w
}

const (
	openaiBody    = `{"model":"agent/concierge","messages":[{"role":"user","content":"hi"}]}`
	anthropicBody = `{"model":"quilzo","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`
)

// An agent built for either provider reaches the gateway with its Quilzo
// token as its key, and is answered in its own shape.
func TestTheModelDoorAnswersEachShapeWithAToken(t *testing.T) {
	r := newDoorRig(t)
	w := r.send(t, "/v1/chat/completions", openaiBody, map[string]string{"Authorization": "Bearer " + r.token})
	var cc struct {
		Choices []struct{ Message struct{ Content string } }
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &cc) != nil || cc.Choices[0].Message.Content != "hello editor" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = r.send(t, "/v1/messages", anthropicBody, map[string]string{"X-Api-Key": r.token, "Anthropic-Version": "2023-06-01"})
	var msg struct {
		Type    string
		Content []struct{ Text string }
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &msg) != nil || msg.Type != "message" || msg.Content[0].Text != "hello editor" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if strings.Join(r.asked, "|") != "editor openai agent/concierge hi|editor anthropic quilzo hi" {
		t.Errorf("asked %v", r.asked)
	}
	w = r.send(t, "/v1/models", "", map[string]string{"Authorization": "Bearer " + r.token})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"agent/concierge"`) {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

// Nothing but a token presented with the request opens it: not the
// admin's own session, not a token an app was given for /mcp, and nothing
// at all while it is off.
func TestTheModelDoorTakesOnlyATokenPresentedForIt(t *testing.T) {
	r := newDoorRig(t)
	w := r.send(t, "/v1/chat/completions", openaiBody, map[string]string{"Cookie": "quilzo_token=" + r.token})
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"error"`) {
		t.Errorf("the admin's session opened it: %d %s", w.Code, w.Body)
	}
	w = r.send(t, "/v1/messages", anthropicBody, nil)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "authentication_error") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	app, _, err := r.srv.Tokens.IssueForGrant("editor", auth.RoleAdmin, auth.Scope{}, "https://app.example.com/c.json",
		"gr_1", "https://admin.example.org/mcp", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if w := r.send(t, "/v1/chat/completions", openaiBody, map[string]string{"Authorization": "Bearer " + app}); w.Code != http.StatusUnauthorized {
		t.Errorf("a token for /mcp opened it: %d %s", w.Code, w.Body)
	}
	if len(r.asked) != 0 {
		t.Errorf("asked %v", r.asked)
	}
	r.on = false
	if w := r.send(t, "/v1/chat/completions", openaiBody, map[string]string{"Authorization": "Bearer " + r.token}); w.Code != http.StatusNotFound {
		t.Errorf("answered while off: %d", w.Code)
	}
}

// A refusal is answered with what each client reads as one.
func TestTheModelDoorSaysWhyInEachShape(t *testing.T) {
	r := newDoorRig(t)
	auth := map[string]string{"Authorization": "Bearer " + r.token}
	r.fail = fmt.Errorf("today's: %w", gateway.ErrBudget)
	if w := r.send(t, "/v1/messages", anthropicBody, auth); w.Code != http.StatusTooManyRequests ||
		!strings.Contains(w.Body.String(), "rate_limit_error") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	r.fail = &ModelRefusal{Code: http.StatusForbidden, Why: "takes a token that may draft"}
	if w := r.send(t, "/v1/chat/completions", openaiBody, auth); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "may draft") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	if w := r.send(t, "/v1/chat/completions", `{"messages":[]}`, auth); w.Code != http.StatusBadRequest {
		t.Errorf("an empty conversation: %d %s", w.Code, w.Body)
	}
}

// A field the door does not read is refused in the caller's own shape,
// by its name, before any model is asked: passed over, it could have been
// a format or a seed the caller is counting on.
func TestTheModelDoorRefusesAFieldItDoesNotRead(t *testing.T) {
	r := newDoorRig(t)
	auth := map[string]string{"Authorization": "Bearer " + r.token}
	for _, c := range []struct{ path, body, shape string }{
		{"/v1/chat/completions", `{"model":"quilzo","messages":[{"role":"user","content":"hi"}],"guided_json":{}}`, `"error":{`},
		{"/v1/responses", `{"model":"quilzo","input":"hi","guided_json":{}}`, `"error":{`},
		{"/v1/messages", `{"model":"quilzo","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"guided_json":{}}`,
			`"type":"invalid_request_error"`},
	} {
		w := r.send(t, c.path, c.body, auth)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), c.shape) ||
			!strings.Contains(w.Body.String(), `guided_json`) {
			t.Errorf("%s: %d %s", c.path, w.Code, w.Body)
		}
	}
	if len(r.asked) != 0 {
		t.Errorf("a refused request was asked of the model: %v", r.asked)
	}
	r.fail = fmt.Errorf("%w: hosted: it is not declared to honour a response format", assist.ErrCannotHonour)
	if w := r.send(t, "/v1/messages", anthropicBody, auth); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "invalid_request_error") {
		t.Errorf("a request nothing can honour: %d %s", w.Code, w.Body)
	}
}
