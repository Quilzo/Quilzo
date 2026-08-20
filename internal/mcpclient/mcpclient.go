// Package mcpclient calls tools on somebody else's MCP server.
//
// # What this is for, and what internal/mcp is
//
// internal/mcp is the server: it exposes this store's operations to a model
// somebody else is running. This is the other direction — reaching an MCP
// server run by a service the operator has declared, so an agent can look
// something up or file something in a system this program does not implement.
//
// # Why a client at all, given the rule about dependencies
//
// The protocol is JSON-RPC over HTTP. That is encoding/json and an io.Reader,
// so there is no SDK to vendor and no exception being made. Writing a client
// per service does not scale past a handful and is how a CMS acquires forty
// half-maintained integrations; one client that speaks the protocol covers the
// roughly 18,850 servers in the registry as of July 2026.
//
// # Everything here is refusal, because the ecosystem is what it is
//
// Of the remote servers surveyed in July 2026, 17.2% were dead. The live risk
// has a name — tool poisoning: a server that adds or redefines a tool after
// the day somebody decided to trust it. A client that calls whatever is
// advertised has handed its capability list to a third party's next release.
//
// So the allow-list is the product. An Integration names the tools it may call
// and this refuses every other name, including one the server offers, including
// one that appeared since. The server is asked what it has; it is never asked
// what may be called.
//
// # The address checks are internal/fetch's, not reimplemented here
//
// Every request goes through fetch.Client.Post: the hostname is resolved and
// the address judged before the socket connects, so DNS rebinding cannot walk
// this into the metadata endpoint or onto the loopback interface. Two answers
// to that question would be worse than one, and the one that rots is always
// the copy.
package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/fetch"
)

// MaxResult bounds what one tool call returns.
//
// A response is going into a model's context and onto somebody's bill. A
// server that answers with a megabyte is a server this stops reading.
const MaxResult = 32 << 10

// Client calls tools on the integrations an install has enabled.
type Client struct {
	// Fetch performs the request, with the address checks. Nil means a default
	// client, which still has them.
	Fetch *fetch.Client

	// Secrets resolves a credential name to its value. Nil means no
	// integration that names one can be called — which is the right failure
	// for a store with no vault configured, because the alternative is calling
	// somebody's API anonymously and reporting their 401 as a tool failure.
	Secrets func(name string) (string, error)

	id atomic.Int64
}

// rpc is a JSON-RPC 2.0 request.
type rpc struct {
	Version string `json:"jsonrpc"`
	ID      int64  `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// reply is what comes back.
type reply struct {
	Version string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tool is one tool as the far side describes it.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Allowed is whether this install may call it. Reported rather than
	// filtered out, so `quilzo integrations tools` shows an operator what a
	// server offers and which of it they have agreed to — the difference is
	// the thing worth looking at.
	Allowed bool `json:"allowed"`
}

// Call runs one tool on one integration.
//
// The integration is resolved from the tool name by the caller, so this is
// handed both: what it may not do is pick an integration from something a
// model said.
func (c *Client) Call(ctx context.Context, in agent.Integration, tool string,
	args map[string]any) (string, error) {

	if err := c.permits(in, tool); err != nil {
		return "", err
	}
	raw, err := c.send(ctx, in, "tools/call", map[string]any{
		"name": tool, "arguments": args,
	})
	if err != nil {
		return "", err
	}
	return renderContent(raw), nil
}

// Tools asks a server what it offers, and marks what this install may call.
//
// Deliberately does not filter. An operator comparing what a server advertises
// against what they agreed to is exactly how tool poisoning is noticed, and a
// list that quietly hides the new tool is a list that hides the problem.
func (c *Client) Tools(ctx context.Context, in agent.Integration) ([]Tool, error) {
	raw, err := c.send(ctx, in, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s answered tools/list with something this "+
			"cannot read: %w", in.Name, err)
	}
	return markAllowed(out.Tools, in.Uses), nil
}

// markAllowed says which of a server's tools this install agreed to.
//
// Marks, never filters. An operator comparing what a server advertises against
// what they agreed to is exactly how tool poisoning is noticed, and a list that
// quietly drops the tool that appeared last week is a list that hides it.
func markAllowed(tools []Tool, uses []string) []Tool {
	agreed := make(map[string]bool, len(uses))
	for _, u := range uses {
		agreed[u] = true
	}
	for i := range tools {
		tools[i].Allowed = agreed[tools[i].Name]
	}
	return tools
}

// permits is the allow-list, and it is the whole control.
func (c *Client) permits(in agent.Integration, tool string) error {
	if !in.Enabled {
		return fmt.Errorf(
			"%s is declared and not enabled, so nothing may call it", in.Name)
	}
	if in.Kind != agent.IntegrationMCP {
		return fmt.Errorf("%s is a %s integration, not an MCP server",
			in.Name, in.Kind)
	}
	for _, u := range in.Uses {
		if u == tool {
			return nil
		}
	}
	// Named plainly, including the list. The operator reading this is deciding
	// whether to add the tool, and "not permitted" without the agreed set
	// makes that a trip to a config file.
	return fmt.Errorf(
		"%s may not call %q on %s. This install agreed to %s, and a tool the "+
			"server offers is not thereby a tool this may call — that is the "+
			"whole point of naming them",
		in.Name, clamp(tool, 60), in.Endpoint, strings.Join(in.Uses, ", "))
}

// send performs one JSON-RPC call.
func (c *Client) send(ctx context.Context, in agent.Integration, method string,
	params any) (json.RawMessage, error) {

	body, err := json.Marshal(rpc{
		Version: "2.0", ID: c.id.Add(1), Method: method, Params: params,
	})
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}
	if in.Secret != "" {
		if c.Secrets == nil {
			return nil, fmt.Errorf(
				"%s authenticates with the secret %q and this process has no "+
					"vault to read it from. Calling anonymously would report "+
					"their 401 as a tool that does not work",
				in.Name, in.Secret)
		}
		v, serr := c.Secrets(in.Secret)
		if serr != nil {
			return nil, fmt.Errorf("%s: reading the secret %q: %w",
				in.Name, in.Secret, serr)
		}
		headers["Authorization"] = "Bearer " + v
	}

	client := c.Fetch
	if client == nil {
		client = fetch.New()
	}
	// https, always. An MCP call carries a credential and whatever the tool
	// was given; over plain HTTP both are on the wire. The endpoint is a
	// hostname by declaration — Integration.Validate refuses a URL — so the
	// scheme is this package's to choose and there is one right answer.
	url := "https://" + in.Endpoint
	res, err := client.PostWithHeaders(ctx, url, body, headers)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", in.Name, err)
	}
	if res.Status != 0 && (res.Status < 200 || res.Status > 299) {
		return nil, fmt.Errorf("%s answered %d", in.Name, res.Status)
	}
	if int64(len(res.Body)) > MaxResult {
		return nil, fmt.Errorf(
			"%s answered %d bytes and the limit is %d; a tool result goes "+
				"into a model's context and onto somebody's bill",
			in.Name, len(res.Body), MaxResult)
	}

	var r reply
	if err := json.Unmarshal(res.Body, &r); err != nil {
		return nil, fmt.Errorf(
			"%s did not answer with JSON-RPC this can read: %w", in.Name, err)
	}
	if r.Error != nil {
		return nil, fmt.Errorf("%s refused: %s (code %d)",
			in.Name, clamp(r.Error.Message, 300), r.Error.Code)
	}
	if len(r.Result) == 0 {
		return nil, fmt.Errorf("%s answered with no result", in.Name)
	}
	return r.Result, nil
}

// renderContent turns an MCP tool result into text for a model.
//
// The protocol returns a content array of typed parts. Only text parts are
// read: an image or a blob coming back from a tool is not something this can
// put in front of a model, and rendering it as its own JSON would be handing
// the model a base64 payload and calling it an answer.
func renderContent(raw json.RawMessage) string {
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Content) == 0 {
		// Not every server returns the content shape. Handing back the raw
		// result is more useful than an error, and it is still bounded.
		return clamp(string(raw), MaxResult)
	}
	var b strings.Builder
	if out.IsError {
		b.WriteString("the tool reported an error:\n")
	}
	for _, part := range out.Content {
		if part.Type != "text" || part.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(part.Text)
	}
	if b.Len() == 0 {
		return "the tool returned nothing this can read as text"
	}
	return clamp(b.String(), MaxResult)
}

func clamp(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
