// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package a2a

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Tasks: other agents handing work to this one, over A2A 1.0.
//
// A2A 1.0 settled the verbs (SendMessage, GetTask, ListTasks, CancelTask,
// with streaming, subscriptions and push notifications beside them) and a
// JSON-RPC binding. This is that binding's server side for the verbs a
// governed agent can honour: a message is a goal for one of this store's
// agents, the run is the task, and the task is what the run became. What
// the run may do is still its manifest, narrowed by whoever's credential
// sent the message; nothing about arriving over A2A widens it.
//
// Streaming, subscriptions and push notifications are answered as
// unsupported, truthfully: the card says so too.

// TaskVersion is the A2A revision these tasks speak.
const TaskVersion = "1.0"

// Task states, as A2A 1.0 writes them.
const (
	StateSubmitted = "TASK_STATE_SUBMITTED"
	StateWorking   = "TASK_STATE_WORKING"
	StateCompleted = "TASK_STATE_COMPLETED"
	StateFailed    = "TASK_STATE_FAILED"
	StateCanceled  = "TASK_STATE_CANCELED"
	StateRejected  = "TASK_STATE_REJECTED"
)

// Roles.
const (
	RoleUser  = "ROLE_USER"
	RoleAgent = "ROLE_AGENT"
)

// Errors, as the JSON-RPC binding numbers them.
const (
	CodeTaskNotFound          = -32001
	CodeTaskNotCancelable     = -32002
	CodePushNotSupported      = -32003
	CodeUnsupportedOperation  = -32004
	CodeContentTypeNotAllowed = -32005
	CodeExtendedCardNone      = -32007
	CodeVersionNotSupported   = -32009
	codeParse                 = -32700
	codeInvalidRequest        = -32600
	codeMethodNotFound        = -32601
	codeInvalidParams         = -32602
	codeInternal              = -32603
)

// Part is one piece of a message; only text is taken here.
type Part struct {
	Text      string         `json:"text,omitempty"`
	Data      any            `json:"data,omitempty"`
	URL       string         `json:"url,omitempty"`
	Raw       string         `json:"raw,omitempty"`
	MediaType string         `json:"mediaType,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Message is one turn.
type Message struct {
	MessageID string         `json:"messageId"`
	ContextID string         `json:"contextId,omitempty"`
	TaskID    string         `json:"taskId,omitempty"`
	Role      string         `json:"role"`
	Parts     []Part         `json:"parts"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// TaskStatus is where a task is.
type TaskStatus struct {
	State     string   `json:"state"`
	Message   *Message `json:"message,omitempty"`
	Timestamp string   `json:"timestamp,omitempty"`
}

// Artifact is what a task produced.
type Artifact struct {
	ArtifactID string `json:"artifactId"`
	Name       string `json:"name,omitempty"`
	Parts      []Part `json:"parts"`
}

// Task is a unit of work and what became of it.
type Task struct {
	ID        string         `json:"id"`
	ContextID string         `json:"contextId"`
	Status    TaskStatus     `json:"status"`
	Artifacts []Artifact     `json:"artifacts,omitempty"`
	History   []Message      `json:"history,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Error is an A2A error, with its JSON-RPC code.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// Errorf is an error with a code.
func Errorf(code int, msg string) *Error { return &Error{Code: code, Message: msg} }

// Host is what answering tasks needs from the program.
type Host struct {
	// Agents are the agents a message may name.
	Agents func() []string
	// Send runs agent with the text as its goal, for whoever sent it, and
	// returns the task as it stands when the run ended or stopped for a
	// person.
	Send func(r *http.Request, agent, text string) (Task, error)
	// Get is one task, List the sender's latest, Cancel ends one that is
	// waiting for a person.
	Get    func(r *http.Request, id string) (Task, error)
	List   func(r *http.Request, limit int) ([]Task, error)
	Cancel func(r *http.Request, id string) (Task, error)
}

// MaxRequest bounds a request; MaxText a message's text.
const (
	MaxRequest = 256 << 10
	MaxText    = 8000
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Serve answers one JSON-RPC request. The caller has been authenticated.
func (h Host) Serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST a JSON-RPC request", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequest+1))
	if err != nil || len(body) > MaxRequest {
		reply(w, nil, nil, Errorf(codeInvalidRequest, "a request is at most 256 kilobytes"))
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		reply(w, nil, nil, Errorf(codeParse, "that is not JSON-RPC"))
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" || len(req.ID) == 0 {
		reply(w, req.ID, nil, Errorf(codeInvalidRequest, "a JSON-RPC 2.0 request with an id and a method"))
		return
	}
	// A request without the header is 0.3's, which this does not speak.
	if v := strings.TrimSpace(r.Header.Get("A2A-Version")); v != TaskVersion {
		reply(w, req.ID, nil, Errorf(CodeVersionNotSupported, "this server speaks A2A "+TaskVersion+"; send A2A-Version: "+TaskVersion))
		return
	}
	res, rerr := h.call(r, req)
	reply(w, req.ID, res, rerr)
}

func (h Host) call(r *http.Request, req rpcRequest) (any, *Error) {
	switch req.Method {
	case "SendMessage":
		var p struct {
			Message       Message `json:"message"`
			Configuration *struct {
				AcceptedOutputModes []string `json:"acceptedOutputModes"`
			} `json:"configuration"`
			Metadata map[string]any `json:"metadata"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, Errorf(codeInvalidParams, "SendMessage takes a message")
		}
		if p.Message.Role != RoleUser || p.Message.MessageID == "" {
			return nil, Errorf(codeInvalidParams, "a message is the user's, with a messageId")
		}
		if p.Message.TaskID != "" {
			return nil, Errorf(CodeUnsupportedOperation, "a task here is one run; it is not continued by another message")
		}
		if c := p.Configuration; c != nil && len(c.AcceptedOutputModes) > 0 && !accepts(c.AcceptedOutputModes, "text/plain") {
			return nil, Errorf(CodeContentTypeNotAllowed, "these agents answer in text/plain")
		}
		var text []string
		for _, part := range p.Message.Parts {
			if part.Data != nil || part.URL != "" || part.Raw != "" {
				return nil, Errorf(CodeContentTypeNotAllowed, "these agents take text, not files or data")
			}
			text = append(text, part.Text)
		}
		goal := strings.TrimSpace(strings.Join(text, "\n"))
		switch {
		case goal == "":
			return nil, Errorf(codeInvalidParams, "the message says nothing")
		case len(goal) > MaxText:
			return nil, Errorf(codeInvalidParams, "a message is at most 8,000 characters")
		}
		agent, err := h.pick(p.Message.Metadata, p.Metadata)
		if err != nil {
			return nil, err
		}
		t, serr := h.Send(r, agent, goal)
		if serr != nil {
			return nil, asError(serr)
		}
		return map[string]any{"task": t}, nil
	case "GetTask":
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.ID == "" {
			return nil, Errorf(codeInvalidParams, "GetTask takes an id")
		}
		t, err := h.Get(r, p.ID)
		if err != nil {
			return nil, asError(err)
		}
		return t, nil
	case "ListTasks":
		var p struct {
			PageSize int `json:"pageSize"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.PageSize <= 0 || p.PageSize > 50 {
			p.PageSize = 50
		}
		ts, err := h.List(r, p.PageSize)
		if err != nil {
			return nil, asError(err)
		}
		if ts == nil {
			ts = []Task{}
		}
		return map[string]any{"tasks": ts, "nextPageToken": "", "pageSize": p.PageSize, "totalSize": len(ts)}, nil
	case "CancelTask":
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.ID == "" {
			return nil, Errorf(codeInvalidParams, "CancelTask takes an id")
		}
		t, err := h.Cancel(r, p.ID)
		if err != nil {
			return nil, asError(err)
		}
		return t, nil
	case "SendStreamingMessage", "SubscribeToTask":
		return nil, Errorf(CodeUnsupportedOperation, "this server does not stream; send SendMessage and ask GetTask")
	case "CreateTaskPushNotificationConfig", "GetTaskPushNotificationConfig",
		"ListTaskPushNotificationConfigs", "DeleteTaskPushNotificationConfig":
		return nil, Errorf(CodePushNotSupported, "this server does not send push notifications")
	case "GetExtendedAgentCard":
		return nil, Errorf(CodeExtendedCardNone, "the public card is the whole card")
	}
	return nil, Errorf(codeMethodNotFound, "no method "+clampName(req.Method))
}

// pick is the agent a message is for: named in its metadata as "agent",
// or the one agent there is.
func (h Host) pick(metas ...map[string]any) (string, *Error) {
	agents := h.Agents()
	for _, m := range metas {
		if name, ok := m["agent"].(string); ok && name != "" {
			for _, a := range agents {
				if a == name {
					return a, nil
				}
			}
			return "", Errorf(codeInvalidParams, "no agent here is called "+clampName(name))
		}
	}
	if len(agents) == 1 {
		return agents[0], nil
	}
	if len(agents) == 0 {
		return "", Errorf(CodeUnsupportedOperation, "no agent here takes tasks")
	}
	return "", Errorf(codeInvalidParams, "name the agent in the message's metadata as \"agent\": one of "+strings.Join(agents, ", "))
}

func accepts(modes []string, want string) bool {
	for _, m := range modes {
		if m == want || m == "text/*" || m == "*/*" {
			return true
		}
	}
	return false
}

func asError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Errorf(codeInternal, err.Error())
}

func clampName(s string) string {
	if len(s) > 60 {
		return s[:60]
	}
	return s
}

func reply(w http.ResponseWriter, id json.RawMessage, result any, err *Error) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Result: result, Error: err})
}
