// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/jsonschema"
)

// REST APIs as tools.
//
// A REST integration's operations are declared, usually imported from an
// OpenAPI description, and each is a tool by its name: the same allow-list,
// the same pins, the same gateway and the same approvals as an MCP server's
// tools, so an agent, the gateway and a person at the command line call one
// exactly as they call the other.
//
// Its definitions come from the declaration, not from the far side, so the
// server cannot redefine a tool after it was trusted; a person editing the
// declaration can, and a pinned operation whose declaration changed is
// refused until somebody pins it again.
//
// A call is built only from what the operation declares: its path with each
// placeholder escaped, its declared query parameters, and a JSON body when it
// takes one, checked against the body's declared schema (internal/jsonschema).
// An argument the operation does not declare is refused rather than passed
// on, so a model cannot add a parameter, or a body field, the person never
// read.
// The request goes over https, to the declared host and nowhere else, with
// no redirects followed, the integration's credential added here, and the
// answer cut off at MaxResult.

// restTools are a REST integration's operations as tools.
func restTools(in agent.Integration) []Tool {
	var out []Tool
	for _, o := range in.Operations {
		t := Tool{Name: o.Name, Description: o.Method + " " + o.Path, InputSchema: inputSchema(o)}
		if o.Description != "" {
			t.Description += ": " + o.Description
		}
		t.Definition = definitionOf(t)
		t.Pinned = in.Pins[o.Name]
		out = append(out, t)
	}
	return markAllowed(out, in.Uses)
}

// inputSchema is the JSON Schema of an operation's arguments.
func inputSchema(o agent.Operation) json.RawMessage {
	props := map[string]any{}
	var required []string
	for _, p := range o.Params {
		typ := p.Type
		if typ == "" {
			typ = "string"
		}
		prop := map[string]any{"type": typ}
		if p.Description != "" {
			prop["description"] = p.Description
		}
		props[p.Name] = prop
		if p.Required || p.In == "path" {
			required = append(required, p.Name)
		}
	}
	if len(o.Body) > 0 {
		props["body"] = json.RawMessage(o.Body)
		required = append(required, "body")
	}
	sort.Strings(required)
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	b, _ := json.Marshal(s)
	return b
}

func operationOf(in agent.Integration, name string) (agent.Operation, bool) {
	for _, o := range in.Operations {
		if o.Name == name {
			return o, true
		}
	}
	return agent.Operation{}, false
}

// paramValue is an argument as it goes into a path or a query.
func paramValue(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case json.Number:
		return x.String(), nil
	}
	return "", fmt.Errorf("is not a plain value")
}

// restRequest builds an operation's request from its arguments.
func restRequest(in agent.Integration, o agent.Operation, args map[string]any) (string, []byte, error) {
	declared := map[string]agent.OperationParam{}
	for _, p := range o.Params {
		declared[p.Name] = p
	}
	for k := range args {
		if _, ok := declared[k]; !ok && !(k == "body" && len(o.Body) > 0) {
			return "", nil, fmt.Errorf("%s does not take %q; it takes only what its declaration names", o.Name, clamp(k, 60))
		}
	}
	path := o.Path
	query := url.Values{}
	for _, p := range o.Params {
		v, present := args[p.Name]
		if !present {
			if p.Required || p.In == "path" {
				return "", nil, fmt.Errorf("%s needs %s", o.Name, p.Name)
			}
			continue
		}
		s, err := paramValue(v)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %s %w", o.Name, p.Name, err)
		}
		if p.In == "path" {
			if s == "" || s == "." || s == ".." {
				return "", nil, fmt.Errorf("%s: %s may not be %q", o.Name, p.Name, s)
			}
			path = strings.ReplaceAll(path, "{"+p.Name+"}", url.PathEscape(s))
		} else {
			query.Set(p.Name, s)
		}
	}
	base := strings.TrimSuffix(in.Path, "/")
	host := in.Endpoint
	if in.Port != 0 && in.Port != 443 {
		host += ":" + strconv.Itoa(in.Port)
	}
	u := "https://" + host + base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body []byte
	if b, ok := args["body"]; ok && len(o.Body) > 0 {
		// The body goes out only as its declaration describes it: a model's
		// arguments are what something it read may have steered, and a field
		// the API would also accept is the one it was steered to add.
		if err := jsonschema.Check(o.Body, b); err != nil {
			return "", nil, fmt.Errorf("%s: %w", o.Name, err)
		}
		var err error
		if body, err = json.Marshal(b); err != nil {
			return "", nil, err
		}
	}
	return u, body, nil
}

// restCall performs one operation.
func (c *Client) restCall(ctx context.Context, in agent.Integration, tool string, args map[string]any) (string, error) {
	o, ok := operationOf(in, tool)
	if !ok {
		return "", fmt.Errorf("%s declares no operation %q", in.Name, clamp(tool, 60))
	}
	u, body, err := restRequest(in, o, args)
	if err != nil {
		return "", err
	}
	headers := map[string]string{"Accept": "application/json"}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	if in.Secret != "" {
		if c.Secrets == nil {
			return "", fmt.Errorf("%s authenticates with the secret %q and this process has no vault to read it from",
				in.Name, in.Secret)
		}
		v, serr := c.Secrets(in.Secret)
		if serr != nil {
			return "", fmt.Errorf("%s: reading the secret %q: %w", in.Name, in.Secret, serr)
		}
		if h, named := strings.CutPrefix(in.Auth, "header:"); named {
			headers[h] = v
		} else {
			headers["Authorization"] = "Bearer " + v
		}
	}
	do := c.DoMethod
	if do == nil {
		client := c.Fetch
		if client == nil {
			client = fetch.New()
			client.Purpose = "integrations"
			client.UserAgent = "quilzo/1 (+rest client)"
			client.Limits = fetch.Limits{MaxBytes: MaxResult, Timeout: 30 * time.Second, MaxRedirects: -1}
		}
		ranges, err := in.Ranges()
		if err != nil {
			return "", err
		}
		if len(ranges) > 0 {
			own := *client
			own.Reach = fetch.Within(ranges)
			client = &own
		}
		do = client.Do
	}
	res, err := do(ctx, o.Method, u, body, headers)
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", in.Name, o.Name, err)
	}
	text := string(res.Body)
	if len(text) > MaxResult {
		text = text[:MaxResult]
	}
	if res.Status < 200 || res.Status > 299 {
		return "", fmt.Errorf("%s %s answered %d: %s", in.Name, o.Name, res.Status, clamp(text, 300))
	}
	if text == "" {
		text = fmt.Sprintf("%d, with nothing in the answer", res.Status)
	}
	return text, nil
}
