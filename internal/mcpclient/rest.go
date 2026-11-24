// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
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
		return "", refuse(fmt.Errorf("%s declares no operation %q", in.Name, clamp(tool, 60)))
	}
	// What its declaration does not name, or a body its schema does not
	// describe, is refused before anything is sent.
	u, body, err := restRequest(in, o, args)
	if err != nil {
		return "", refuse(err)
	}
	headers := map[string]string{"Accept": "application/json"}
	if body != nil {
		headers["Content-Type"] = "application/json"
	}
	if in.Connection != "" {
		tok, err := c.connected(ctx, in)
		if err != nil {
			return "", err
		}
		headers["Authorization"] = "Bearer " + tok
	}
	if in.Secret != "" {
		if c.Secrets == nil {
			return "", refuse(fmt.Errorf("%s authenticates with the secret %q and this process has no vault to read it from",
				in.Name, in.Secret))
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
	// A write carries the key that names it, so a far side that keeps
	// them answers a repeat as the first time rather than doing it twice:
	// the same step of a run, resumed or tried again, sends the same key.
	key, keyed := IdempotencyKeyOf(ctx)
	if keyed && o.Writes() {
		headers["Idempotency-Key"] = key
	}
	// Tried again, a little later, when the far side was busy or did not
	// answer; only a call that is safe to repeat: a read, or a write that
	// carries its key.
	safe := !o.Writes() || keyed
	var res *fetch.Result
	retryAfter := ""
	for attempt := 1; ; attempt++ {
		res, err = do(ctx, o.Method, u, body, headers)
		retryAfter = ""
		if res != nil && res.Header != nil {
			retryAfter = res.Header.Get("Retry-After")
		}
		if !safe || attempt >= MaxAttempts || !transient(res, err) || ctx.Err() != nil {
			break
		}
		// Longer than a run waits in place, and it is neither slept on nor
		// cut short: tried again before the time asked, it is turned away
		// again, so the call fails saying when (below).
		if asked, ok := askedWait(retryAfter, c.now()); ok && asked > MaxWait {
			break
		}
		wait := c.Wait
		if wait == nil {
			wait = func(attempt int, header string) time.Duration { return retryWait(attempt, header, c.now()) }
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait(attempt, retryAfter)):
		}
	}
	if guarded(err) {
		return "", refuse(fmt.Errorf("%s %s: %w", in.Name, o.Name, err))
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", in.Name, o.Name, err)
	}
	text := string(res.Body)
	if len(text) > MaxResult {
		text = text[:MaxResult]
	}
	if res.Status < 200 || res.Status > 299 {
		// A far side that said when it will take the call again is said so,
		// with the time, for a person or a later step to come back then.
		now := c.now()
		if asked, ok := askedWait(retryAfter, now); ok && transient(res, nil) {
			return "", fmt.Errorf("%s %s answered %d and asks to be tried again after %s: %s", in.Name, o.Name,
				res.Status, now.Add(asked).UTC().Format(time.RFC3339), clamp(text, 300))
		}
		return "", fmt.Errorf("%s %s answered %d: %s", in.Name, o.Name, res.Status, clamp(text, 300))
	}
	if text == "" {
		text = fmt.Sprintf("%d, with nothing in the answer", res.Status)
	}
	return text, nil
}

type idempotencyKey struct{}

// WithIdempotencyKey names the write a call makes, for the far side to
// recognise a repeat of it.
func WithIdempotencyKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, idempotencyKey{}, key)
}

// IdempotencyKeyOf is the key a call's write is named by, when it has one.
func IdempotencyKeyOf(ctx context.Context) (string, bool) {
	k, ok := ctx.Value(idempotencyKey{}).(string)
	return k, ok && k != ""
}

// MaxAttempts is how many times a call safe to repeat is made, at most.
const MaxAttempts = 3

// transient reports whether a call failed in a way that trying again a
// little later may mend: no answer, or an answer that says busy.
func transient(res *fetch.Result, err error) bool {
	if err != nil {
		return true
	}
	switch res.Status {
	case 408, 425, 429, 502, 503, 504:
		return true
	}
	return rateLimited(res)
}

// rateLimits are the codes that make a refusal a rate limit though its
// status says otherwise, by status: TikTok answers rate_limit_exceeded in
// a 400, and Google's APIs, YouTube's among them, quotaExceeded or
// rateLimitExceeded in a 403. Read by status alone they were final, and a
// read that waiting would have let through failed at once.
var rateLimits = map[int][]string{
	400: {"rate_limit_exceeded"},
	403: {"quotaExceeded", "rateLimitExceeded", "userRateLimitExceeded"},
}

// rateLimited reports whether an answer is one of rateLimits: the code is
// TikTok's error.code, or one of Google's error.errors[].reason. Only the
// code is read, never the message, so a refusal that merely quotes the
// words is still a refusal.
func rateLimited(res *fetch.Result) bool {
	codes := rateLimits[res.Status]
	if len(codes) == 0 {
		return false
	}
	var answer struct {
		Error struct {
			Code   json.RawMessage `json:"code"`
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if json.Unmarshal(res.Body, &answer) != nil {
		return false
	}
	var said []string
	var code string
	if json.Unmarshal(answer.Error.Code, &code) == nil {
		said = append(said, code)
	}
	for _, e := range answer.Error.Errors {
		said = append(said, e.Reason)
	}
	for _, s := range said {
		for _, c := range codes {
			if strings.EqualFold(s, c) {
				return true
			}
		}
	}
	return false
}

// MaxWait is the longest a call waits in place before trying again. A
// far side that asks for longer is not tried again in this call.
const MaxWait = 10 * time.Second

// askedWait is how long the far side asked to be left, from a Retry-After
// header in either of its forms (RFC 9110 10.2.3): a number of seconds,
// or a date, which a date gone by makes nothing.
func askedWait(header string, now time.Time) (time.Duration, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, false
	}
	if s, err := strconv.ParseInt(header, 10, 64); err == nil && s >= 0 {
		return time.Duration(min(s, int64(math.MaxInt64/time.Second))) * time.Second, true
	}
	if at, err := http.ParseTime(header); err == nil {
		return max(at.Sub(now), 0), true
	}
	return 0, false
}

// RetryAfter is how long to wait before another attempt: what the far side
// asked, up to MaxWait, or else a time drawn at random up to a ceiling of
// one second that doubles each attempt (full jitter). A fixed wait sent
// every caller a busy service turned away at once back to it in the same
// instant, to be turned away together again.
func RetryAfter(attempt int, header string) time.Duration {
	return retryWait(attempt, header, time.Now())
}

func retryWait(attempt int, header string, now time.Time) time.Duration {
	if asked, ok := askedWait(header, now); ok {
		return min(asked, MaxWait)
	}
	ceiling := min(time.Second<<min(max(attempt-1, 0), 4), MaxWait)
	return time.Duration(rand.Int64N(int64(ceiling) + 1))
}
