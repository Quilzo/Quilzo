// Package mcp exposes scrivet to agents over the Model Context Protocol.
//
// # Why now, and not before
//
// Earlier research on this project concluded that MCP is worth its cost for
// remote, authenticated access and not for local, deterministic work — a CLI
// wins the second case outright, and scrivet was local. Hosting changes which
// case this is, so the conclusion changes with it.
//
// # Four tools, not fifteen
//
// The measured problem with MCP is that servers preload every tool definition
// into the context window, which put naive servers at roughly 35x the tokens of
// an equivalent CLI call with reliability falling as the tool count grew. The
// 2026 fixes all say the same thing: stop preloading. Anthropic's Tool Search
// cut usage about 85%, its code-execution pattern went 150,000 tokens to 2,000,
// and Cloudflare's Code Mode reports 99.9%.
//
// So this exposes four tools rather than one per CLI command, and one of them
// describes the rest on demand. An agent that only wants to read a page pays for
// four short definitions instead of fifteen long ones, and learns the detail of
// exactly the operation it needs.
//
// # The gates apply here too
//
// This is the third interface onto the same content, and the previous two each
// shipped with a control present in one and missing from the other. A gate that
// exists on the command line and not in the API is a gate with a hole in
// whichever one people automate against — which, for an agent, is this one.
//
// So publishing through MCP runs the same accessibility and provenance checks,
// and refuses for the same reasons. Content written through MCP is marked as
// AI-generated without being asked, because an agent calling a write tool is a
// model writing content whatever the wrapper is called.
//
// # Authentication
//
// The 2026-07-28 specification makes an MCP server an OAuth resource server, and
// names the pitfall plainly: a server that checks a token's signature and expiry
// but not its audience will accept a token minted for something else entirely.
//
// scrivet's tokens are opaque and issued by this server, so they are
// audience-bound by construction — there is no other issuer whose token could
// validate here, and the class of confusion the specification warns about cannot
// arise. That is a smaller claim than OAuth 2.1 conformance, and it is the true
// one: a multi-tenant deployment behind a shared identity provider needs RFC
// 9728 discovery and RFC 8707 resource binding, and that is a seam rather than
// something pretended at.
package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Protocol is the revision this speaks.
const Protocol = "2025-06-18"

// Request is a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSON-RPC error codes, plus the one that matters for an agent: a refusal is not
// a malfunction, and an agent that cannot tell them apart will retry a decision.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
	CodeRefused        = -32001
)

// Tool is an MCP tool definition.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Operation is something the server can do, described only when asked.
//
// This is the progressive disclosure: operations are data rather than tools, so
// none of their descriptions enter a context window until an agent searches for
// one.
type Operation struct {
	Name      string
	Summary   string
	Detail    string
	Args      map[string]string
	Writes    bool
	NeedsRole string
	Keywords  []string
}

// Handler performs an operation. Returning an error whose message begins with a
// refusal is surfaced to the agent as a refusal rather than a failure.
type Handler func(args map[string]any) (any, error)

// Refusal is a decision, not a malfunction.
//
// The distinction is the same one the CLI makes with exit code 3: an agent that
// reads "denied by policy" as "the server broke" will retry, and retrying a
// refusal is how an agent turns one blocked action into a hundred.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return r.Reason }

// Server routes MCP traffic.
type Server struct {
	Name       string
	Version    string
	operations map[string]Operation
	handlers   map[string]Handler
}

func NewServer(name, version string) *Server {
	return &Server{
		Name: name, Version: version,
		operations: map[string]Operation{},
		handlers:   map[string]Handler{},
	}
}

// Register adds an operation and its handler.
func (s *Server) Register(op Operation, h Handler) {
	s.operations[op.Name] = op
	s.handlers[op.Name] = h
}

// tools returns the four that are always present.
//
// Deliberately short descriptions. These are the only definitions that enter a
// context window unasked, so every word in them is paid for on each session.
func (s *Server) tools() []Tool {
	return []Tool{
		{
			Name: "scrivet_find",
			Description: "Find the scrivet operation for a task. Call this first; " +
				"it returns the exact arguments for the operation you need.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "what you are trying to do, in a few words",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "scrivet_read",
			Description: "Read content or state. Use scrivet_find to learn the operations.",
			InputSchema: opSchema("a read operation name from scrivet_find"),
		},
		{
			Name: "scrivet_write",
			Description: "Change a draft. Never publishes. Content written here is " +
				"recorded as AI-generated.",
			InputSchema: opSchema("a write operation name from scrivet_find"),
		},
		{
			Name: "scrivet_check",
			Description: "Run the checks that gate publishing: accessibility and " +
				"content provenance.",
			InputSchema: opSchema("a check operation name from scrivet_find"),
		},
	}
}

func opSchema(desc string) map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"operation": map[string]any{"type": "string", "description": desc},
			"arguments": map[string]any{
				"type":        "object",
				"description": "arguments for the operation, as scrivet_find described them",
			},
		},
		"required": []string{"operation"},
	}
}

// find matches operations against a query.
//
// A plain keyword score rather than an embedding. The corpus is a dozen
// operations written by one person; a retrieval model here would add a
// dependency, a failure mode and a warm-up cost to a lookup that a substring
// match answers correctly.
func (s *Server) find(query string) []Operation {
	q := strings.ToLower(strings.TrimSpace(query))
	words := strings.Fields(q)

	type scored struct {
		op    Operation
		score int
	}
	var out []scored
	for _, op := range s.operations {
		score := 0
		hay := strings.ToLower(op.Name + " " + op.Summary + " " + strings.Join(op.Keywords, " "))
		for _, w := range words {
			if strings.Contains(hay, w) {
				score += 2
			}
			if strings.Contains(strings.ToLower(op.Name), w) {
				score += 3
			}
		}
		if score > 0 {
			out = append(out, scored{op, score})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].op.Name < out[j].op.Name
	})

	ops := make([]Operation, 0, len(out))
	for _, s := range out {
		ops = append(ops, s.op)
	}
	// Nothing matched: return everything rather than nothing. An agent that
	// searched badly should see the menu, not a dead end it will guess around.
	if len(ops) == 0 {
		for _, op := range s.operations {
			ops = append(ops, op)
		}
		sort.Slice(ops, func(i, j int) bool { return ops[i].Name < ops[j].Name })
	}
	return ops
}

// Handle processes one request.
func (s *Server) Handle(req Request) *Response {
	resp := &Response{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": Protocol,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
			"instructions": "Call scrivet_find first to discover operations. " +
				"Writes go to a draft and never publish. Content you write is " +
				"recorded as AI-generated, which the EU AI Act requires.",
		}

	case "notifications/initialized", "ping":
		resp.Result = map[string]any{}

	case "tools/list":
		resp.Result = map[string]any{"tools": s.tools()}

	case "tools/call":
		resp.Result, resp.Error = s.call(req.Params)

	default:
		resp.Error = &Error{Code: CodeMethodNotFound,
			Message: fmt.Sprintf("no method %q", req.Method)}
	}
	return resp
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func (s *Server) call(raw json.RawMessage) (any, *Error) {
	var p callParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &Error{Code: CodeInvalidParams, Message: err.Error()}
	}

	if p.Name == "scrivet_find" {
		query, _ := p.Arguments["query"].(string)
		return textResult(s.describe(s.find(query))), nil
	}

	kind := map[string]string{
		"scrivet_read": "read", "scrivet_write": "write", "scrivet_check": "check",
	}[p.Name]
	if kind == "" {
		return nil, &Error{Code: CodeMethodNotFound,
			Message: fmt.Sprintf("no tool %q; the tools are scrivet_find, "+
				"scrivet_read, scrivet_write and scrivet_check", p.Name)}
	}

	opName, _ := p.Arguments["operation"].(string)
	if opName == "" {
		return nil, &Error{Code: CodeInvalidParams,
			Message: "no operation given; call scrivet_find to get one"}
	}
	op, ok := s.operations[opName]
	if !ok {
		return nil, &Error{Code: CodeInvalidParams,
			Message: fmt.Sprintf("no operation %q; call scrivet_find", opName)}
	}

	// A read tool must not be able to reach a write operation. Without this the
	// four-tool split would be a labelling convention rather than a boundary,
	// and a client permitted only to read could write by naming the operation.
	if op.Writes && kind == "read" {
		return nil, &Error{Code: CodeInvalidParams,
			Message: fmt.Sprintf("%q changes content; call it through scrivet_write", opName)}
	}
	if !op.Writes && kind == "write" {
		return nil, &Error{Code: CodeInvalidParams,
			Message: fmt.Sprintf("%q does not change anything; use scrivet_read", opName)}
	}

	args, _ := p.Arguments["arguments"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}

	result, err := s.handlers[opName](args)
	if err != nil {
		var ref *Refusal
		if asRefusal(err, &ref) {
			// A refusal carries its own code so an agent does not retry a
			// decision. Retrying a refusal turns one blocked action into many.
			return nil, &Error{Code: CodeRefused, Message: ref.Reason,
				Data: map[string]any{"refused": true, "retryable": false}}
		}
		return nil, &Error{Code: CodeInternal, Message: err.Error()}
	}
	return textResult(fmt.Sprintf("%v", result)), nil
}

func asRefusal(err error, out **Refusal) bool {
	if r, ok := err.(*Refusal); ok {
		*out = r
		return true
	}
	return false
}

// describe renders operations for an agent that asked for them.
func (s *Server) describe(ops []Operation) string {
	var b strings.Builder
	if len(ops) == 0 {
		return "no operations available"
	}
	for _, op := range ops {
		tool := "scrivet_read"
		if op.Writes {
			tool = "scrivet_write"
		}
		if strings.HasPrefix(op.Name, "check") {
			tool = "scrivet_check"
		}
		fmt.Fprintf(&b, "%s — %s\n", op.Name, op.Summary)
		fmt.Fprintf(&b, "  call: %s{operation:%q, arguments:{...}}\n", tool, op.Name)
		if len(op.Args) > 0 {
			keys := make([]string, 0, len(op.Args))
			for k := range op.Args {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "    %s: %s\n", k, op.Args[k])
			}
		}
		if op.NeedsRole != "" {
			fmt.Fprintf(&b, "    needs role: %s\n", op.NeedsRole)
		}
		if op.Detail != "" {
			fmt.Fprintf(&b, "  %s\n", op.Detail)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func textResult(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}
}

// Operations lists what is registered, for tests and for `scrivet mcp --list`.
func (s *Server) Operations() []Operation {
	out := make([]Operation, 0, len(s.operations))
	for _, op := range s.operations {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
