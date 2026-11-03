// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/fetch"
)

// Another vendor's agent, over the Agent2Agent protocol (JSON-RPC binding).
//
// Its agent card, at /.well-known/agent-card.json on the declared host (or
// the integration's path), says what it can do: each skill is a tool here,
// pinned, allowed and approved as an MCP server's tools are, and described
// to the model by the card's own words, which are the far side's and are
// treated as such. A call sends one message, as text, with the skill named;
// the answer is a message, or a task, which is asked after until it
// finishes or a minute and a half passes. The card's service address must
// be on the declared host: a card cannot send this installation's
// credential somewhere else.
//
// A card that offers an A2A 1.0 JSON-RPC interface (supportedInterfaces) is
// spoken to there, in 1.0: SendMessage and GetTask, with A2A-Version sent.
// Any other is spoken to at its url, in 0.3: message/send and tasks/get.
// Only 0.3 was spoken once, and Quilzo's own task server speaks 1.0 alone,
// so one install's agent asking another's always failed.

// A2AWait is how long a task the far agent took on is waited for.
var A2AWait = 90 * time.Second

// a2aPoll is how often an unfinished task is asked after.
var a2aPoll = 2 * time.Second

type a2aCard struct {
	Name                string `json:"name"`
	URL                 string `json:"url"`
	SupportedInterfaces []struct {
		URL             string `json:"url"`
		ProtocolBinding string `json:"protocolBinding"`
		ProtocolVersion string `json:"protocolVersion"`
	} `json:"supportedInterfaces"`
	Skills []struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Examples    []string `json:"examples"`
	} `json:"skills"`
}

// a2aService is where, and in which revision, a far agent is spoken to.
type a2aService struct {
	URL     string
	Version string // "1.0" or "0.3"
}

// a2aDo is the transport for one request to another agent: the checked
// client, within the declared reach, with the declared credential.
func (c *Client) a2aDo(ctx context.Context, in agent.Integration, method, u, version string, body []byte) (*fetch.Result, error) {
	headers := map[string]string{"Accept": "application/json"}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	if version == "1.0" {
		headers["A2A-Version"] = version
	}
	if in.Connection != "" {
		tok, err := c.connected(ctx, in)
		if err != nil {
			return nil, err
		}
		headers["Authorization"] = "Bearer " + tok
	}
	if in.Secret != "" {
		if c.Secrets == nil {
			return nil, fmt.Errorf("%s authenticates with the secret %q and this process has no vault to read it from",
				in.Name, in.Secret)
		}
		v, err := c.Secrets(in.Secret)
		if err != nil {
			return nil, fmt.Errorf("%s: reading the secret %q: %w", in.Name, in.Secret, err)
		}
		headers["Authorization"] = "Bearer " + v
	}
	do := c.DoMethod
	if do == nil {
		client := c.Fetch
		if client == nil {
			client = fetch.New()
			client.Purpose = "integrations"
			client.UserAgent = "quilzo/1 (+a2a client)"
			client.Limits = fetch.Limits{MaxBytes: MaxResult, Timeout: 30 * time.Second, MaxRedirects: -1}
		}
		ranges, err := in.Ranges()
		if err != nil {
			return nil, err
		}
		if len(ranges) > 0 {
			own := *client
			own.Reach = fetch.Within(ranges)
			client = &own
		}
		do = client.Do
	}
	res, err := do(ctx, method, u, body, headers)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", in.Name, err)
	}
	if res.Status < 200 || res.Status > 299 {
		return nil, fmt.Errorf("%s answered %d", in.Name, res.Status)
	}
	return res, nil
}

// card reads the far agent's card and where it is spoken to.
func (c *Client) a2aCardOf(ctx context.Context, in agent.Integration) (a2aCard, a2aService, error) {
	path := in.Path
	if path == "" || path == "/" {
		path = "/.well-known/agent-card.json"
	}
	u := (&url.URL{Scheme: "https", Host: in.Endpoint, Path: path}).String()
	if in.Port != 0 && in.Port != 443 {
		u = (&url.URL{Scheme: "https", Host: fmt.Sprintf("%s:%d", in.Endpoint, in.Port), Path: path}).String()
	}
	res, err := c.a2aDo(ctx, in, "GET", u, "", nil)
	if err != nil {
		return a2aCard{}, a2aService{}, err
	}
	var card a2aCard
	if err := json.Unmarshal(res.Body, &card); err != nil {
		return a2aCard{}, a2aService{}, fmt.Errorf("%s's agent card is not one this can read", in.Name)
	}
	if len(card.Skills) > 200 {
		return a2aCard{}, a2aService{}, fmt.Errorf("%s offers %d skills; that is not an agent anybody reviewed", in.Name, len(card.Skills))
	}
	onHost := func(raw string) (string, bool) {
		svc, err := url.Parse(raw)
		if err != nil || svc.Scheme != "https" || !strings.EqualFold(svc.Hostname(), in.Endpoint) {
			return "", false
		}
		return svc.String(), true
	}
	// A 1.0 interface on another host is passed over as the 0.3 url would
	// be: nothing, and no credential, is sent off the declared host.
	for _, i := range card.SupportedInterfaces {
		if strings.EqualFold(i.ProtocolBinding, "JSONRPC") && strings.HasPrefix(i.ProtocolVersion, "1.") {
			if svc, ok := onHost(i.URL); ok {
				return card, a2aService{URL: svc, Version: "1.0"}, nil
			}
		}
	}
	svc, ok := onHost(card.URL)
	if !ok {
		return a2aCard{}, a2aService{}, fmt.Errorf("%s's card sends its messages to %q, which is not https on %s: nothing is sent there",
			in.Name, clamp(card.URL, 120), in.Endpoint)
	}
	return card, a2aService{URL: svc, Version: "0.3"}, nil
}

var a2aInput = json.RawMessage(`{"type":"object","properties":{"text":{"type":"string","description":"what to ask the other agent, in words"}},"required":["text"]}`)

// a2aTools are the far agent's skills, as tools.
func (c *Client) a2aTools(ctx context.Context, in agent.Integration) ([]Tool, error) {
	card, _, err := c.a2aCardOf(ctx, in)
	if err != nil {
		return nil, err
	}
	out := make([]Tool, 0, len(card.Skills))
	for _, s := range card.Skills {
		if strings.TrimSpace(s.ID) == "" {
			continue
		}
		desc := clamp(strings.TrimSpace(s.Name+": "+s.Description), 1000)
		if len(s.Examples) > 0 {
			desc += " For example: " + clamp(strings.Join(s.Examples[:min(3, len(s.Examples))], "; "), 300)
		}
		t := Tool{Name: clamp(s.ID, 64), Description: desc, InputSchema: a2aInput}
		t.Definition = definitionOf(t)
		t.Pinned = in.Pins[t.Name]
		out = append(out, t)
	}
	return markAllowed(out, in.Uses), nil
}

// a2aPart is a part as either revision writes it: 0.3 names its kind, 1.0
// is known by the member it carries.
type a2aPart struct {
	Kind string          `json:"kind"`
	Text string          `json:"text,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type a2aResult struct {
	Kind   string    `json:"kind"`
	ID     string    `json:"id"`
	Parts  []a2aPart `json:"parts"`
	Status struct {
		State   string `json:"state"`
		Message *struct {
			Parts []a2aPart `json:"parts"`
		} `json:"message"`
	} `json:"status"`
	Artifacts []struct {
		Parts []a2aPart `json:"parts"`
	} `json:"artifacts"`
}

// a2aCall asks the far agent for one skill and returns what it answered.
func (c *Client) a2aCall(ctx context.Context, in agent.Integration, skill string, args map[string]any) (string, error) {
	text, _ := args["text"].(string)
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("%s: say what to ask, as text", in.Name)
	}
	_, svc, err := c.a2aCardOf(ctx, in)
	if err != nil {
		return "", err
	}
	var idb [16]byte
	_, _ = rand.Read(idb[:])
	msgID := hex.EncodeToString(idb[:])
	// Named by its step when it is one, so a far side that keeps message
	// ids does not act twice on a repeat.
	if key, ok := IdempotencyKeyOf(ctx); ok {
		msgID = key
	}
	send, get := "message/send", "tasks/get"
	params := map[string]any{
		"message": map[string]any{"kind": "message", "role": "user", "messageId": msgID,
			"parts": []any{map[string]any{"kind": "text", "text": clamp(text, 20000)}}},
		"metadata": map[string]any{"skill": skill},
	}
	if svc.Version == "1.0" {
		send, get = "SendMessage", "GetTask"
		params["message"] = map[string]any{"role": "ROLE_USER", "messageId": msgID,
			"parts": []any{map[string]any{"text": clamp(text, 20000)}}}
	}
	res, err := c.a2aRPC(ctx, in, svc, send, params)
	if err != nil {
		return "", err
	}
	deadline := time.Now().Add(A2AWait)
	for res.Kind == "task" && (res.Status.State == "submitted" || res.Status.State == "working") {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("%s took on the task (%s) and had not finished it after %s", in.Name, clamp(res.ID, 64), A2AWait)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(a2aPoll):
		}
		if res, err = c.a2aRPC(ctx, in, svc, get, map[string]any{"id": res.ID}); err != nil {
			return "", err
		}
	}
	var parts []a2aPart
	switch {
	case res.Kind == "message":
		parts = res.Parts
	case res.Status.State == "completed":
		for _, a := range res.Artifacts {
			parts = append(parts, a.Parts...)
		}
		if len(parts) == 0 && res.Status.Message != nil {
			parts = res.Status.Message.Parts
		}
	case res.Status.State == "input-required" || res.Status.State == "auth-required":
		said := ""
		if res.Status.Message != nil {
			said = partsText(res.Status.Message.Parts)
		}
		return "", fmt.Errorf("%s needs more before it can go on (%s): %s", in.Name, res.Status.State, clamp(said, 500))
	default:
		said := ""
		if res.Status.Message != nil {
			said = partsText(res.Status.Message.Parts)
		}
		return "", fmt.Errorf("%s did not do it (%s): %s", in.Name, clamp(res.Status.State, 30), clamp(said, 500))
	}
	out := partsText(parts)
	if out == "" {
		out = "it answered with nothing to read"
	}
	if len(out) > MaxResult {
		out = out[:MaxResult]
	}
	return out, nil
}

func partsText(parts []a2aPart) string {
	var b strings.Builder
	for _, p := range parts {
		switch {
		case p.Kind == "text" || p.Kind == "" && p.Text != "":
			b.WriteString(p.Text)
			b.WriteString("\n")
		case p.Kind == "data" || p.Kind == "" && len(p.Data) > 0:
			b.Write(p.Data)
			b.WriteString("\n")
		}
	}
	return strings.TrimSpace(b.String())
}

// a2aResult1 reads what A2A 1.0 answers in 0.3's shape, which the rest of
// a call reads: SendMessage's task or message, or GetTask's task, with the
// state as 0.3 writes it (TASK_STATE_INPUT_REQUIRED is input-required).
func a2aResult1(raw json.RawMessage) (a2aResult, error) {
	var sent struct {
		Task    *a2aResult `json:"task"`
		Message *struct {
			Parts []a2aPart `json:"parts"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &sent); err != nil {
		return a2aResult{}, err
	}
	var out a2aResult
	switch {
	case sent.Message != nil:
		return a2aResult{Kind: "message", Parts: sent.Message.Parts}, nil
	case sent.Task != nil:
		out = *sent.Task
	default:
		if err := json.Unmarshal(raw, &out); err != nil {
			return a2aResult{}, err
		}
	}
	out.Kind = "task"
	out.Status.State = strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(out.Status.State, "TASK_STATE_")), "_", "-")
	return out, nil
}

// a2aRPC makes one JSON-RPC call to the far agent.
func (c *Client) a2aRPC(ctx context.Context, in agent.Integration, svc a2aService, method string, params any) (a2aResult, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id.Add(1), "method": method, "params": params})
	res, err := c.a2aDo(ctx, in, "POST", svc.URL, svc.Version, body)
	if err != nil {
		return a2aResult{}, err
	}
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(res.Body, &out); err != nil {
		return a2aResult{}, fmt.Errorf("%s answered %s with something this cannot read", in.Name, method)
	}
	if out.Error != nil {
		return a2aResult{}, fmt.Errorf("%s refused %s: %s", in.Name, method, clamp(out.Error.Message, 300))
	}
	if len(out.Result) == 0 || string(out.Result) == "null" {
		return a2aResult{}, fmt.Errorf("%s answered %s with nothing", in.Name, method)
	}
	var result a2aResult
	if svc.Version == "1.0" {
		result, err = a2aResult1(out.Result)
	} else {
		err = json.Unmarshal(out.Result, &result)
	}
	if err != nil {
		return a2aResult{}, fmt.Errorf("%s answered %s with something this cannot read", in.Name, method)
	}
	return result, nil
}
