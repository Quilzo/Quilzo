// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

// The agent interface over HTTP: MCP's Streamable HTTP transport, revision
// 2026-07-28, with the earlier revisions still answered.
//
// # What 2026-07-28 changed, and why it suits this
//
// The revision made MCP stateless. There is no initialize handshake and no
// session: every request carries its protocol version and the client's
// capabilities in _meta, and the HTTP request repeats the method and the
// tool's name in headers (Mcp-Method, Mcp-Name) so a gateway can decide
// without reading the body. This server was already stateless in the way
// that matters (each call is authorised on its own, from the credential
// that came with it), so nothing has to be remembered between requests and
// any process can answer any request.
//
// # The headers are checked against the body
//
// A header that says tools/call while the body says something else is the
// classic way two components disagree about one request: the gateway allows
// what the header names and the server runs what the body says. So a
// 2026-07-28 request whose headers and body differ is refused with
// HeaderMismatch before anything runs, as the revision requires.
//
// # Earlier clients
//
// A client of 2025-03-26 to 2025-11-25 opens with initialize. It is answered
// without a session (sessions were always optional for a server), and its
// later requests are served the same way. Nothing a later revision removed
// is offered: no GET stream, no resumable events.
//
// # Credentials
//
// Every request carries a bearer token in the Authorization header and
// nowhere else; a token in the query string is refused, because URLs end up
// in logs. Who the token belongs to, and what it may do, is the host's to
// decide (Authenticate); this transport only refuses to run anything without
// it, and turns "the token's scope is too small" into the 403 the client
// knows how to answer by asking the person for more.

// Modern is the stateless revision.
const Modern = "2026-07-28"

// Legacy are the handshake revisions still answered.
var Legacy = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// Supported is every revision this server speaks, newest first.
func Supported() []string { return append([]string{Modern}, Legacy...) }

// Codes the 2026-07-28 revision reserves.
const (
	CodeHeaderMismatch     = -32020
	CodeMissingCapability  = -32021
	CodeUnsupportedVersion = -32022
)

const (
	metaVersion = "io.modelcontextprotocol/protocolVersion"
	metaServer  = "io.modelcontextprotocol/serverInfo"
)

// MaxBody bounds one request. The operations take a page or a record at
// most; a body larger than this is not a request this server has.
const MaxBody = 4 << 20

// Caller is who a request comes from, as the host established it.
type Caller struct {
	// Principal is the person or service the token acts for.
	Principal string
	// Client is the app holding the token, when it was given through OAuth.
	Client string
	// Data is anything else the host needs when it builds the server.
	Data any
}

// ScopeError is an operation the credential's scope does not reach, though
// the person behind it might: the client should ask them for Scope.
type ScopeError struct {
	Scope  string
	Reason string
}

func (e *ScopeError) Error() string { return e.Reason }

// ErrNoCredential is a request that presented no token.
var ErrNoCredential = errors.New("no bearer token")

// Endpoint serves the agent interface over HTTP.
type Endpoint struct {
	// Metadata is the URL of this resource's OAuth protected resource
	// metadata (RFC 9728), named in every 401 so a client can find where to
	// sign in. Empty when nothing is set up for that: the 401 then says only
	// that a bearer token is needed.
	Metadata string
	// DefaultScope is the scope named in a 401.
	DefaultScope string
	// Authenticate resolves the bearer token. An error is a 401.
	Authenticate func(r *http.Request, token string) (*Caller, error)
	// Build makes the server that answers one caller.
	Build func(r *http.Request, c *Caller) (*Server, error)
	// SameOrigin reports whether a browser Origin header may call this. A
	// request with no Origin is not from a page and is not affected.
	SameOrigin func(origin string) bool
	// Called is told about each tools/call, for the audit log: the tool, the
	// operation, and the error the caller was given, or nil.
	Called func(r *http.Request, c *Caller, tool, operation string, err *Error)
}

// ServeHTTP answers one request.
func (e *Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")

	if origin := r.Header.Get("Origin"); origin != "" && (e.SameOrigin == nil || !e.SameOrigin(origin)) {
		// DNS rebinding and pages elsewhere driving a person's browser at
		// this endpoint. Required by the transport.
		writeRPC(w, http.StatusForbidden, Response{JSONRPC: "2.0",
			Error: &Error{Code: CodeInvalidRequest, Message: "requests from another site's pages are refused"}})
		return
	}
	if r.Method != http.MethodPost {
		h.Set("Allow", "POST")
		http.Error(w, "the agent interface takes POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Has("access_token") {
		writeRPC(w, http.StatusBadRequest, Response{JSONRPC: "2.0",
			Error: &Error{Code: CodeInvalidRequest, Message: "a token goes in the Authorization header, never in the address"}})
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		writeRPC(w, http.StatusUnsupportedMediaType, Response{JSONRPC: "2.0",
			Error: &Error{Code: CodeInvalidRequest, Message: "the body is JSON-RPC, sent as application/json"}})
		return
	}

	// Authentication before the body is read: an anonymous caller costs a
	// header comparison, not a parse.
	token, ok := bearer(r)
	if !ok {
		e.challenge(w, "", "")
		return
	}
	if e.Authenticate == nil || e.Build == nil {
		writeRPC(w, http.StatusInternalServerError, Response{JSONRPC: "2.0",
			Error: &Error{Code: CodeInternal, Message: "this endpoint is not wired to anything that can authorise a caller"}})
		return
	}
	caller, err := e.Authenticate(r, token)
	if err != nil {
		e.challenge(w, "invalid_token", err.Error())
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		writeRPC(w, http.StatusRequestEntityTooLarge, Response{JSONRPC: "2.0",
			Error: &Error{Code: CodeInvalidRequest, Message: fmt.Sprintf("a request is at most %d bytes", MaxBody)}})
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		// Batches were removed in 2025-06-18, and a batch is several
		// requests sharing one set of headers that can match only one.
		writeRPC(w, http.StatusBadRequest, Response{JSONRPC: "2.0",
			Error: &Error{Code: CodeInvalidRequest, Message: "one JSON-RPC message per request; batches are not accepted"}})
		return
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeRPC(w, http.StatusBadRequest, Response{JSONRPC: "2.0",
			Error: &Error{Code: CodeParse, Message: "the body is not one JSON-RPC message"}})
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeRPC(w, http.StatusBadRequest, Response{JSONRPC: "2.0", ID: req.ID,
			Error: &Error{Code: CodeInvalidRequest, Message: "not a JSON-RPC 2.0 request"}})
		return
	}
	if len(req.ID) > 0 && !validID(req.ID) {
		writeRPC(w, http.StatusBadRequest, Response{JSONRPC: "2.0",
			Error: &Error{Code: CodeInvalidRequest, Message: "a request id is a string or a number"}})
		return
	}

	version, verr := e.version(r, req)
	if verr != nil {
		writeRPC(w, http.StatusBadRequest, Response{JSONRPC: "2.0", ID: req.ID, Error: verr})
		return
	}
	modern := version == Modern

	if len(req.ID) == 0 {
		// A notification. The only ones a client sends are the legacy
		// handshake's and cancellation, and neither needs anything done.
		w.WriteHeader(http.StatusAccepted)
		return
	}

	srv, err := e.Build(r, caller)
	if err != nil {
		writeRPC(w, http.StatusInternalServerError, Response{JSONRPC: "2.0", ID: req.ID,
			Error: &Error{Code: CodeInternal, Message: err.Error()}})
		return
	}

	switch req.Method {
	case "initialize":
		if modern {
			e.notFound(w, req, modern)
			return
		}
		writeRPC(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID, Result: srv.initialize(legacyVersion(req))})
		return
	case "ping":
		if modern {
			e.notFound(w, req, modern)
			return
		}
		writeRPC(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})
		return
	case "server/discover":
		writeRPC(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID, Result: srv.discover()})
		return
	case "tools/list":
		res := map[string]any{"tools": srv.tools()}
		if modern {
			res = srv.complete(res)
			res["ttlMs"] = 3600000
			// Private: what a caller may do depends on who they are, so a
			// shared cache must not hand one caller's list to another.
			res["cacheScope"] = "private"
		}
		writeRPC(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID, Result: res})
		return
	case "tools/call":
		tool, op := callNames(req.Params)
		result, rerr := srv.call(req.Params)
		if e.Called != nil {
			e.Called(r, caller, tool, op, rerr)
		}
		if rerr != nil {
			var se *ScopeError
			if errors.As(rerr.cause, &se) {
				e.insufficient(w, se, req.ID)
				return
			}
			rerr.cause = nil
			writeRPC(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID, Error: rerr})
			return
		}
		if m, ok := result.(map[string]any); ok && modern {
			result = srv.complete(m)
		}
		writeRPC(w, http.StatusOK, Response{JSONRPC: "2.0", ID: req.ID, Result: result})
		return
	}
	e.notFound(w, req, modern)
}

// version decides which revision a request speaks, and checks a modern
// request's headers against its body.
func (e *Endpoint) version(r *http.Request, req Request) (string, *Error) {
	header := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	meta := metaOf(req.Params)
	var bodyVersion string
	if v, ok := meta[metaVersion]; ok {
		s, isString := v.(string)
		if !isString {
			return "", &Error{Code: CodeHeaderMismatch, Message: "the protocol version in _meta is not a string"}
		}
		bodyVersion = s
	}
	switch {
	case header == "" && req.Method == "initialize":
		// The legacy opening, before a client has a version to state.
		return legacyVersion(req), nil
	case header == "" && bodyVersion == "":
		// What 2025-03-26 clients sent: no header at all.
		return "2025-03-26", nil
	case header == "":
		return "", &Error{Code: CodeHeaderMismatch, Message: "the MCP-Protocol-Version header is missing"}
	}
	if header == Modern {
		if bodyVersion != header {
			return "", &Error{Code: CodeHeaderMismatch, Message: fmt.Sprintf(
				"MCP-Protocol-Version says %s and the body's _meta says %q", header, bodyVersion)}
		}
		if got := r.Header.Get("Mcp-Method"); got != req.Method {
			return "", &Error{Code: CodeHeaderMismatch, Message: fmt.Sprintf(
				"Mcp-Method says %q and the body says %q", got, req.Method)}
		}
		if field := nameField(req.Method); field != "" {
			want := stringParam(req.Params, field)
			raw := r.Header.Get("Mcp-Name")
			got, err := decodeHeaderValue(raw)
			if raw == "" || err != nil || got != want {
				return "", &Error{Code: CodeHeaderMismatch, Message: fmt.Sprintf(
					"Mcp-Name does not match the body's %s", field)}
			}
		}
		return Modern, nil
	}
	for _, v := range Legacy {
		if header == v {
			if bodyVersion != "" && bodyVersion != header {
				return "", &Error{Code: CodeHeaderMismatch, Message: "the header and the body name different versions"}
			}
			return v, nil
		}
	}
	return "", &Error{Code: CodeUnsupportedVersion, Message: "Unsupported protocol version",
		Data: map[string]any{"supported": Supported(), "requested": header}}
}

// legacyVersion is the revision a legacy client asked for in initialize, or
// the newest legacy one when it asked for something else.
func legacyVersion(req Request) string {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(req.Params, &p)
	for _, v := range Legacy {
		if p.ProtocolVersion == v {
			return v
		}
	}
	return Legacy[0]
}

func nameField(method string) string {
	switch method {
	case "tools/call", "prompts/get":
		return "name"
	case "resources/read":
		return "uri"
	}
	return ""
}

// decodeHeaderValue undoes the transport's Base64 sentinel, =?base64?...?=,
// used for values that are not plain ASCII.
func decodeHeaderValue(v string) (string, error) {
	if strings.HasPrefix(v, "=?base64?") && strings.HasSuffix(v, "?=") && len(v) >= len("=?base64??=") {
		b, err := base64.StdEncoding.DecodeString(v[len("=?base64?") : len(v)-2])
		if err != nil || !utf8.Valid(b) {
			return "", errors.New("not base64 UTF-8")
		}
		return string(b), nil
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 && c != '\t' || c == 0x7f || c >= 0x80 {
			return "", errors.New("not a header value")
		}
	}
	return v, nil
}

func metaOf(params json.RawMessage) map[string]any {
	var p struct {
		Meta map[string]any `json:"_meta"`
	}
	_ = json.Unmarshal(params, &p)
	return p.Meta
}

func stringParam(params json.RawMessage, field string) string {
	var p map[string]json.RawMessage
	if json.Unmarshal(params, &p) != nil {
		return ""
	}
	var s string
	_ = json.Unmarshal(p[field], &s)
	return s
}

func callNames(params json.RawMessage) (tool, op string) {
	var p callParams
	_ = json.Unmarshal(params, &p)
	op, _ = p.Arguments["operation"].(string)
	return p.Name, op
}

func validID(id json.RawMessage) bool {
	var v any
	if json.Unmarshal(id, &v) != nil {
		return false
	}
	switch v.(type) {
	case string, float64:
		return true
	}
	return false
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Values("Authorization")
	if len(h) != 1 {
		return "", false
	}
	scheme, token, ok := strings.Cut(strings.TrimSpace(h[0]), " ")
	token = strings.TrimSpace(token)
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}

// challenge is the 401 every client knows how to answer: it names where
// to find the authorization server.
func (e *Endpoint) challenge(w http.ResponseWriter, code, why string) {
	params := []string{}
	if e.Metadata != "" {
		params = append(params, fmt.Sprintf("resource_metadata=%q", e.Metadata))
	}
	if e.DefaultScope != "" {
		params = append(params, fmt.Sprintf("scope=%q", e.DefaultScope))
	}
	if code != "" {
		params = append(params, fmt.Sprintf("error=%q", code))
	}
	v := "Bearer"
	if len(params) > 0 {
		v += " " + strings.Join(params, ", ")
	}
	w.Header().Set("WWW-Authenticate", v)
	msg := "a bearer token is needed"
	if why != "" {
		msg = "the token was refused: " + why
	}
	writeRPC(w, http.StatusUnauthorized, Response{JSONRPC: "2.0",
		Error: &Error{Code: CodeInvalidRequest, Message: msg}})
}

// insufficient is the 403 that asks the client to come back with more scope.
func (e *Endpoint) insufficient(w http.ResponseWriter, se *ScopeError, id json.RawMessage) {
	params := []string{`error="insufficient_scope"`, fmt.Sprintf("scope=%q", se.Scope)}
	if e.Metadata != "" {
		params = append(params, fmt.Sprintf("resource_metadata=%q", e.Metadata))
	}
	params = append(params, fmt.Sprintf("error_description=%q", strings.ReplaceAll(se.Reason, `"`, "'")))
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))
	// With the request's id, so a client waiting for the answer to this
	// request gets one; without it, it waits until it gives up.
	writeRPC(w, http.StatusForbidden, Response{JSONRPC: "2.0", ID: id,
		Error: &Error{Code: CodeRefused, Message: se.Reason}})
}

// notFound is an unknown method: a 404 in 2026-07-28, which is how a client
// tells it from a legacy server; a plain JSON-RPC error before that, where a
// 404 meant "your session is gone" and would send a client round in circles.
func (e *Endpoint) notFound(w http.ResponseWriter, req Request, modern bool) {
	status := http.StatusOK
	if modern {
		status = http.StatusNotFound
	}
	writeRPC(w, status, Response{JSONRPC: "2.0", ID: req.ID,
		Error: &Error{Code: CodeMethodNotFound, Message: fmt.Sprintf("no method %q", req.Method)}})
}

func writeRPC(w http.ResponseWriter, status int, resp Response) {
	b, err := json.Marshal(resp)
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"the answer could not be encoded"}}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
