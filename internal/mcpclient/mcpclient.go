// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

	// Changed is told when a pinned tool's definition is not the one a
	// person approved, so the shield can hear about it.
	Changed func(in agent.Integration, tool, pinned, now string)

	// Now is a clock for the definitions' cache.
	Now func() time.Time

	// Do performs one POST; nil is Fetch's, with every address check. A
	// test hands the server in directly.
	Do func(ctx context.Context, url string, body []byte, headers map[string]string) (*fetch.Result, error)

	id atomic.Int64

	mu       sync.Mutex
	sessions map[string]*session
	defs     map[string]cachedDefs
}

// session is a legacy server's: the revision agreed in its handshake, and
// the session it assigned, if it assigned one.
type session struct{ version, id string }

type cachedDefs struct {
	tools []Tool
	until time.Time
}

// The revisions this speaks: the stateless one first, and the handshake
// revisions for a server that has not moved yet.
const (
	Modern = "2026-07-28"
	Legacy = "2025-11-25"
)

var legacyAccepted = map[string]bool{"2025-11-25": true, "2025-06-18": true, "2025-03-26": true}

// definitionsFor is how long a server's tool definitions are kept.
const definitionsFor = 5 * time.Minute

// rpc is a JSON-RPC 2.0 request.
type rpc struct {
	Version string `json:"jsonrpc"`
	ID      int64  `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// reply is what comes back.
type reply struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Tool is one tool as the far side describes it.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	// Allowed is whether this install may call it. Reported rather than
	// filtered out, so `quilzo integrations tools` shows an operator what a
	// server offers and which of it they have agreed to — the difference is
	// the thing worth looking at.
	Allowed bool `json:"allowed"`
	// Definition is the SHA-256 of the definition as given, which is what a
	// pin records; Pinned is the pin, when there is one.
	Definition string `json:"definition"`
	Pinned     string `json:"pinned,omitempty"`
}

// Matches reports whether a pinned tool is still the tool that was pinned.
func (t Tool) Matches() bool { return t.Pinned != "" && t.Pinned == t.Definition }

// Args are the names a tool takes, from its input schema: names only, and
// only ones that look like names. What the server says each one means is
// never shown to a model; a description is text the far side wrote.
func (t Tool) Args() []string {
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	_ = json.Unmarshal(t.InputSchema, &schema)
	var out []string
	for k := range schema.Properties {
		if reArg.MatchString(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

var reArg = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

// definitionOf is the SHA-256 of a tool's definition, over its name,
// description and input schema re-encoded with sorted keys, so the same
// definition sent with its keys in another order is the same definition.
func definitionOf(t Tool) string {
	var schema any
	if len(t.InputSchema) > 0 {
		_ = json.Unmarshal(t.InputSchema, &schema)
	}
	b, _ := json.Marshal(struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		InputSchema any    `json:"inputSchema"`
	}{t.Name, t.Description, schema})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
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
	if pin := in.Pins[tool]; pin != "" {
		if err := c.checkPin(ctx, in, tool, pin); err != nil {
			return "", err
		}
	}
	raw, err := c.send(ctx, in, "tools/call", map[string]any{
		"name": tool, "arguments": args,
	})
	if err != nil {
		return "", err
	}
	return renderContent(raw), nil
}

// checkPin refuses a tool whose definition is not the one approved.
func (c *Client) checkPin(ctx context.Context, in agent.Integration, tool, pin string) error {
	tools, err := c.Definitions(ctx, in)
	if err != nil {
		return err
	}
	for _, t := range tools {
		if t.Name != tool {
			continue
		}
		if t.Definition == pin {
			return nil
		}
		if c.Changed != nil {
			c.Changed(in, tool, pin, t.Definition)
		}
		return fmt.Errorf("%s has changed what %q is since a person approved it "+
			"(approved %s, now %s). Nothing is called until somebody looks: "+
			"quilzo integrations tools %s, then quilzo integrations pin %s",
			in.Name, tool, pin[:12], t.Definition[:12], in.Name, in.Name)
	}
	return fmt.Errorf("%s no longer offers %q, which was approved", in.Name, tool)
}

// Definitions are a server's tools with their definitions' digests and
// this install's pins, kept for a few minutes.
func (c *Client) Definitions(ctx context.Context, in agent.Integration) ([]Tool, error) {
	key := in.Name + "|" + in.Endpoint
	c.mu.Lock()
	if d, ok := c.defs[key]; ok && c.now().Before(d.until) {
		c.mu.Unlock()
		return d.tools, nil
	}
	c.mu.Unlock()
	tools, err := c.Tools(ctx, in)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.defs == nil {
		c.defs = map[string]cachedDefs{}
	}
	c.defs[key] = cachedDefs{tools: tools, until: c.now().Add(definitionsFor)}
	c.mu.Unlock()
	return tools, nil
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
	if len(out.Tools) > 1000 {
		return nil, fmt.Errorf("%s offers %d tools; that is not a server anybody reviewed", in.Name, len(out.Tools))
	}
	for i := range out.Tools {
		out.Tools[i].Definition = definitionOf(out.Tools[i])
		out.Tools[i].Pinned = in.Pins[out.Tools[i].Name]
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

// send performs one JSON-RPC call: as 2026-07-28 first, statelessly; and,
// when the server answers like one that predates it, through the handshake
// the earlier revisions use, remembered for that server afterwards.
func (c *Client) send(ctx context.Context, in agent.Integration, method string,
	params map[string]any) (json.RawMessage, error) {

	key := in.Name + "|" + in.Endpoint
	c.mu.Lock()
	sess := c.sessions[key]
	c.mu.Unlock()
	if sess == nil {
		raw, res, err := c.exchange(ctx, in, method, params, Modern, "")
		if err == nil {
			return raw, nil
		}
		if !legacyServer(res) {
			return nil, err
		}
		if sess, err = c.handshake(ctx, in); err != nil {
			return nil, err
		}
		c.remember(key, sess)
	}
	raw, res, err := c.exchange(ctx, in, method, params, sess.version, sess.id)
	if err != nil && res != nil && res.Status == 404 && sess.id != "" {
		// The server ended the session; a legacy client starts another.
		if sess, err = c.handshake(ctx, in); err != nil {
			return nil, err
		}
		c.remember(key, sess)
		raw, _, err = c.exchange(ctx, in, method, params, sess.version, sess.id)
	}
	return raw, err
}

func (c *Client) remember(key string, s *session) {
	c.mu.Lock()
	if c.sessions == nil {
		c.sessions = map[string]*session{}
	}
	c.sessions[key] = s
	c.mu.Unlock()
}

// legacyServer reads a refused modern request the way the revision says
// to: a 400, 404 or 405 whose body is not one of the modern errors comes
// from a server that wants a handshake first.
func legacyServer(res *fetch.Result) bool {
	if res == nil {
		return false
	}
	switch res.Status {
	case 400, 404, 405:
	default:
		return false
	}
	var r reply
	if json.Unmarshal(res.Body, &r) == nil && r.Error != nil {
		switch r.Error.Code {
		case -32022:
			// A modern server that does not take this revision: the
			// handshake revisions, if it names one of them.
			var d struct {
				Supported []string `json:"supported"`
			}
			_ = json.Unmarshal(r.Error.Data, &d)
			for _, v := range d.Supported {
				if legacyAccepted[v] {
					return true
				}
			}
			return false
		case -32020, -32021:
			return false
		case -32601:
			return res.Status != 404
		}
	}
	return true
}

// handshake opens a legacy session: initialize, then initialized.
func (c *Client) handshake(ctx context.Context, in agent.Integration) (*session, error) {
	raw, res, err := c.post(ctx, in, rpc{Version: "2.0", ID: c.id.Add(1), Method: "initialize",
		Params: map[string]any{"protocolVersion": Legacy, "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "quilzo", "version": "1"}}}, "", "", "initialize", "")
	if err != nil {
		return nil, err
	}
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(raw, &init); err != nil || !legacyAccepted[init.ProtocolVersion] {
		return nil, fmt.Errorf("%s offered protocol %q, which this does not speak", in.Name, clamp(init.ProtocolVersion, 40))
	}
	s := &session{version: init.ProtocolVersion}
	if res != nil && res.Header != nil {
		id := res.Header.Get("Mcp-Session-Id")
		if len(id) > 256 || !visibleASCII(id) {
			return nil, fmt.Errorf("%s assigned a session id this cannot send back", in.Name)
		}
		s.id = id
	}
	// The notification is answered 202 with nothing; an error here means a
	// server that will refuse what follows anyway, so it is not fatal.
	_, _, _ = c.post(ctx, in, rpc{Version: "2.0", Method: "notifications/initialized"}, s.version, s.id, "notifications/initialized", "")
	return s, nil
}

func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// exchange sends one request in a revision, and reads its answer.
func (c *Client) exchange(ctx context.Context, in agent.Integration, method string,
	params map[string]any, version, sessionID string) (json.RawMessage, *fetch.Result, error) {

	p := make(map[string]any, len(params)+1)
	for k, v := range params {
		p[k] = v
	}
	if version == Modern {
		p["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    Modern,
			"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "quilzo", "version": "1"},
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		}
	}
	name := ""
	if method == "tools/call" {
		name, _ = params["name"].(string)
	}
	return c.post(ctx, in, rpc{Version: "2.0", ID: c.id.Add(1), Method: method, Params: p},
		version, sessionID, method, name)
}

// post sends one message and reads one answer.
func (c *Client) post(ctx context.Context, in agent.Integration, msg rpc, version, sessionID, method, name string) (json.RawMessage, *fetch.Result, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, nil, err
	}
	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	}
	if version != "" {
		headers["MCP-Protocol-Version"] = version
		headers["Mcp-Method"] = method
		if name != "" {
			headers["Mcp-Name"] = headerValue(name)
		}
	}
	if sessionID != "" {
		headers["Mcp-Session-Id"] = sessionID
	}
	if in.Secret != "" {
		if c.Secrets == nil {
			return nil, nil, fmt.Errorf(
				"%s authenticates with the secret %q and this process has no "+
					"vault to read it from. Calling anonymously would report "+
					"their 401 as a tool that does not work",
				in.Name, in.Secret)
		}
		v, serr := c.Secrets(in.Secret)
		if serr != nil {
			return nil, nil, fmt.Errorf("%s: reading the secret %q: %w",
				in.Name, in.Secret, serr)
		}
		headers["Authorization"] = "Bearer " + v
	}

	do := c.Do
	if do == nil {
		client := c.Fetch
		if client == nil {
			// Read no more than a result may be: a server answering with
			// more is refused below, and is not first held in memory. And
			// counted as what it is, a call to a declared tool server.
			client = fetch.New()
			client.Purpose = "integrations"
			client.UserAgent = "quilzo/1 (+mcp client)"
			client.Limits = fetch.Limits{MaxBytes: MaxResult, Timeout: 30 * time.Second, MaxRedirects: -1}
		}
		do = func(ctx context.Context, url string, body []byte, headers map[string]string) (*fetch.Result, error) {
			return client.Do(ctx, "POST", url, body, headers)
		}
	}
	// https, always. An MCP call carries a credential and whatever the tool
	// was given; over plain HTTP both are on the wire. The endpoint is a
	// hostname by declaration — Integration.Validate refuses a URL — so the
	// scheme is this package's to choose and there is one right answer.
	url := "https://" + in.Endpoint
	res, err := do(ctx, url, body, headers)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", in.Name, err)
	}
	if msg.ID == 0 {
		// A notification: no answer to read.
		return nil, res, nil
	}
	if res.Status < 200 || res.Status > 299 {
		return nil, res, fmt.Errorf("%s answered %d", in.Name, res.Status)
	}
	if res.Truncated || int64(len(res.Body)) > MaxResult {
		return nil, res, fmt.Errorf(
			"%s answered more than %d bytes; a tool result goes "+
				"into a model's context and onto somebody's bill",
			in.Name, MaxResult)
	}
	data := res.Body
	if strings.HasPrefix(strings.ToLower(res.ContentType), "text/event-stream") {
		if data, err = answerInStream(res.Body, msg.ID); err != nil {
			return nil, res, fmt.Errorf("%s: %w", in.Name, err)
		}
	}
	var r reply
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, res, fmt.Errorf(
			"%s did not answer with JSON-RPC this can read: %w", in.Name, err)
	}
	if string(r.ID) != strconv.FormatInt(msg.ID, 10) {
		return nil, res, fmt.Errorf("%s answered another request than the one asked", in.Name)
	}
	if r.Error != nil {
		return nil, res, fmt.Errorf("%s refused: %s (code %d)",
			in.Name, clamp(r.Error.Message, 300), r.Error.Code)
	}
	if len(r.Result) == 0 {
		return nil, res, fmt.Errorf("%s answered with no result", in.Name)
	}
	return r.Result, res, nil
}

// answerInStream finds the response to request id in a server-sent event
// stream: the notifications before it are skipped, and nothing after it
// is read.
func answerInStream(stream []byte, id int64) ([]byte, error) {
	want := strconv.FormatInt(id, 10)
	var data strings.Builder
	flush := func() []byte {
		defer data.Reset()
		if data.Len() == 0 {
			return nil
		}
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		b := []byte(data.String())
		if json.Unmarshal(b, &probe) == nil && probe.Method == "" && string(probe.ID) == want {
			return b
		}
		return nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(stream), "\r\n", "\n"), "\n") {
		switch {
		case line == "":
			if b := flush(); b != nil {
				return b, nil
			}
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if b := flush(); b != nil {
		return b, nil
	}
	return nil, errors.New("the stream ended without an answer to the request")
}

// headerValue is a value for Mcp-Name: as it is when it is plain visible
// ASCII, and in the revision's Base64 form otherwise.
func headerValue(v string) string {
	plain := v != "" && strings.TrimSpace(v) == v && !(strings.HasPrefix(v, "=?base64?") && strings.HasSuffix(v, "?="))
	for i := 0; i < len(v) && plain; i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			plain = false
		}
	}
	if plain {
		return v
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(v)) + "?="
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
