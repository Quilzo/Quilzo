// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package mcp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type called struct{ tool, op string }

func endpoint(t *testing.T) (*Endpoint, *[]called) {
	t.Helper()
	var calls []called
	e := &Endpoint{
		Metadata:     "https://admin.example.org/.well-known/oauth-protected-resource/mcp",
		DefaultScope: "mcp:read",
		Authenticate: func(r *http.Request, token string) (*Caller, error) {
			switch token {
			case "reader", "writer":
				return &Caller{Principal: "dana", Data: token}, nil
			}
			return nil, errors.New("no such token")
		},
		Build: func(r *http.Request, c *Caller) (*Server, error) {
			s := NewServer("quilzo", "test")
			s.Authorise = func(op Operation) error {
				if op.Writes && c.Data == "reader" {
					return &ScopeError{Scope: "mcp:write", Reason: "this token reads only"}
				}
				if op.Name == "forbidden" {
					return errors.New("the policy refuses it")
				}
				return nil
			}
			s.Register(Operation{Name: "list_pages", NeedsRole: "reader", Summary: "list"},
				func(map[string]any) (any, error) { return "home, about", nil })
			s.Register(Operation{Name: "write_page", NeedsRole: "author", Writes: true, Summary: "write"},
				func(map[string]any) (any, error) { return "written", nil })
			s.Register(Operation{Name: "forbidden", NeedsRole: "reader", Summary: "no"},
				func(map[string]any) (any, error) { return "should not run", nil })
			return s, nil
		},
		SameOrigin: func(o string) bool { return o == "https://admin.example.org" },
		Called: func(r *http.Request, c *Caller, tool, op string, err *Error) {
			calls = append(calls, called{tool, op})
		},
	}
	return e, &calls
}

type hcall struct {
	token   string
	version string
	method  string
	name    string
	body    string
	headers map[string]string
	verb    string
	ctype   string
}

func modern(method, name, params string) hcall {
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	if params != "" {
		params = params + "," + meta
	} else {
		params = meta
	}
	return hcall{token: "writer", version: Modern, method: method, name: name,
		body: `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + params + `}}`}
}

func (c hcall) do(t *testing.T, e *Endpoint) (*httptest.ResponseRecorder, Response) {
	t.Helper()
	verb := c.verb
	if verb == "" {
		verb = "POST"
	}
	r := httptest.NewRequest(verb, "/mcp", strings.NewReader(c.body))
	ct := c.ctype
	if ct == "" {
		ct = "application/json"
	}
	r.Header.Set("Content-Type", ct)
	r.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		r.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.version != "" {
		r.Header.Set("MCP-Protocol-Version", c.version)
	}
	if c.method != "" {
		r.Header.Set("Mcp-Method", c.method)
	}
	if c.name != "" {
		r.Header.Set("Mcp-Name", c.name)
	}
	for k, v := range c.headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	var resp Response
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

func TestNoTokenIsAChallengeThatSaysWhereToSignIn(t *testing.T) {
	e, _ := endpoint(t)
	c := modern("tools/list", "", "")
	c.token = ""
	w, _ := c.do(t, e)
	want := `Bearer resource_metadata="https://admin.example.org/.well-known/oauth-protected-resource/mcp", scope="mcp:read"`
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != want {
		t.Fatalf("%d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	c.token = "stolen"
	w, _ = c.do(t, e)
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("%d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	for _, auth := range []string{"Basic abc", "Bearer", "Bearer a b", "bearer"} {
		c.token = ""
		c.headers = map[string]string{"Authorization": auth}
		if w, _ := c.do(t, e); w.Code != 401 {
			t.Errorf("%q: %d", auth, w.Code)
		}
	}
}

func TestTheShapeOfARequest(t *testing.T) {
	e, _ := endpoint(t)
	cases := map[string]struct {
		mutate func(*hcall)
		status int
		code   int
	}{
		"GET":             {func(c *hcall) { c.verb = "GET"; c.body = "" }, 405, 0},
		"DELETE":          {func(c *hcall) { c.verb = "DELETE" }, 405, 0},
		"form body":       {func(c *hcall) { c.ctype = "application/x-www-form-urlencoded" }, 415, 0},
		"foreign origin":  {func(c *hcall) { c.headers = map[string]string{"Origin": "https://evil.example"} }, 403, 0},
		"null origin":     {func(c *hcall) { c.headers = map[string]string{"Origin": "null"} }, 403, 0},
		"batch":           {func(c *hcall) { c.body = "[" + c.body + "]" }, 400, CodeInvalidRequest},
		"two messages":    {func(c *hcall) { c.body = c.body + c.body }, 400, CodeParse},
		"not json":        {func(c *hcall) { c.body = "{" }, 400, CodeParse},
		"object id":       {func(c *hcall) { c.body = strings.Replace(c.body, `"id":1`, `"id":{}`, 1) }, 400, CodeInvalidRequest},
		"jsonrpc 1":       {func(c *hcall) { c.body = strings.Replace(c.body, `"2.0"`, `"1.0"`, 1) }, 400, CodeInvalidRequest},
		"method header":   {func(c *hcall) { c.method = "tools/call" }, 400, CodeHeaderMismatch},
		"no method hdr":   {func(c *hcall) { c.method = "" }, 400, CodeHeaderMismatch},
		"meta version":    {func(c *hcall) { c.body = strings.Replace(c.body, `"2026-07-28"`, `"2025-06-18"`, 1) }, 400, CodeHeaderMismatch},
		"no version hdr":  {func(c *hcall) { c.version = "" }, 400, CodeHeaderMismatch},
		"future version":  {func(c *hcall) { c.version = "2099-01-01" }, 400, CodeUnsupportedVersion},
		"initialize":      {func(c *hcall) { *c = modern("initialize", "", "") }, 404, CodeMethodNotFound},
		"ping":            {func(c *hcall) { *c = modern("ping", "", "") }, 404, CodeMethodNotFound},
		"unknown method":  {func(c *hcall) { *c = modern("resources/list", "", "") }, 404, CodeMethodNotFound},
		"same origin":     {func(c *hcall) { c.headers = map[string]string{"Origin": "https://admin.example.org"} }, 200, 0},
		"access in query": {func(c *hcall) {}, 200, 0},
	}
	for name, tc := range cases {
		c := modern("tools/list", "", "")
		tc.mutate(&c)
		w, resp := c.do(t, e)
		if w.Code != tc.status {
			t.Errorf("%s: status %d, want %d (%s)", name, w.Code, tc.status, w.Body.String())
			continue
		}
		if tc.code != 0 && (resp.Error == nil || resp.Error.Code != tc.code) {
			t.Errorf("%s: error %+v, want code %d", name, resp.Error, tc.code)
		}
	}
	// The supported versions are named when one is not.
	c := modern("tools/list", "", "")
	c.version = "2099-01-01"
	_, resp := c.do(t, e)
	data, _ := json.Marshal(resp.Error.Data)
	if !strings.Contains(string(data), `"supported":["2026-07-28","2025-11-25","2025-06-18","2025-03-26"]`) {
		t.Fatalf("%s", data)
	}
	// A token in the address is refused even with one in the header, on a
	// request that is otherwise exactly right.
	send := func(target string, auth []string) int {
		r := httptest.NewRequest("POST", target, strings.NewReader(modern("tools/list", "", "").body))
		for _, a := range auth {
			r.Header.Add("Authorization", a)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("MCP-Protocol-Version", Modern)
		r.Header.Set("Mcp-Method", "tools/list")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w.Code
	}
	if code := send("/mcp", []string{"Bearer writer"}); code != 200 {
		t.Fatalf("the plain request: %d", code)
	}
	if code := send("/mcp?access_token=x", []string{"Bearer writer"}); code != 400 {
		t.Fatalf("token in query: %d", code)
	}
	// Two Authorization headers are two answers to who this is.
	if code := send("/mcp", []string{"Bearer writer", "Bearer reader"}); code != 401 {
		t.Fatalf("two credentials: %d", code)
	}
}

func TestModernResults(t *testing.T) {
	e, _ := endpoint(t)
	w, resp := modern("tools/list", "", "").do(t, e)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	b, _ := json.Marshal(resp.Result)
	for _, want := range []string{`"resultType":"complete"`, `"cacheScope":"private"`, `"ttlMs":3600000`,
		`"io.modelcontextprotocol/serverInfo":{"name":"quilzo"`, `"readOnlyHint":true`, `"name":"quilzo_find"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("tools/list lacks %s: %s", want, b)
		}
	}
	_, resp = modern("server/discover", "", "").do(t, e)
	b, _ = json.Marshal(resp.Result)
	if !strings.Contains(string(b), `"supportedVersions":["2026-07-28"`) || !strings.Contains(string(b), `"resultType":"complete"`) {
		t.Fatalf("%s", b)
	}
}

func TestCallsAndScope(t *testing.T) {
	e, calls := endpoint(t)
	params := `"name":"quilzo_read","arguments":{"operation":"list_pages"}`
	w, resp := modern("tools/call", "quilzo_read", params).do(t, e)
	b, _ := json.Marshal(resp.Result)
	if w.Code != 200 || !strings.Contains(string(b), "home, about") || !strings.Contains(string(b), `"resultType":"complete"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// The name in the header must be the body's.
	c := modern("tools/call", "quilzo_write", params)
	if w, resp := c.do(t, e); w.Code != 400 || resp.Error.Code != CodeHeaderMismatch {
		t.Fatalf("name mismatch: %d", w.Code)
	}
	c.name = ""
	if w, _ := c.do(t, e); w.Code != 400 {
		t.Fatal("missing Mcp-Name accepted")
	}
	// Base64 sentinel is decoded before comparing.
	c.name = "=?base64?" + base64.StdEncoding.EncodeToString([]byte("quilzo_read")) + "?="
	if w, _ := c.do(t, e); w.Code != 200 {
		t.Fatalf("encoded name: %d", w.Code)
	}
	c.name = "=?base64?!!!?="
	if w, _ := c.do(t, e); w.Code != 400 {
		t.Fatal("broken base64 accepted")
	}
	// A scope too small is a 403 that asks for the scope.
	wc := modern("tools/call", "quilzo_write", `"name":"quilzo_write","arguments":{"operation":"write_page"}`)
	wc.token = "reader"
	w, resp = wc.do(t, e)
	if string(resp.ID) != "1" {
		t.Fatalf("the 403 does not answer the request: id %q", resp.ID)
	}
	if w.Code != 403 || !strings.Contains(w.Header().Get("WWW-Authenticate"), `error="insufficient_scope", scope="mcp:write"`) ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), `resource_metadata="https://admin.example.org/`) {
		t.Fatalf("%d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	wc.token = "writer"
	if w, _ := wc.do(t, e); w.Code != 200 {
		t.Fatalf("writer: %d", w.Code)
	}
	// Any other refusal is an answer, not an HTTP error.
	fc := modern("tools/call", "quilzo_read", `"name":"quilzo_read","arguments":{"operation":"forbidden"}`)
	w, resp = fc.do(t, e)
	if w.Code != 200 || resp.Error == nil || resp.Error.Code != CodeRefused || strings.Contains(w.Body.String(), "should not run") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	got := []string{}
	for _, c := range *calls {
		got = append(got, c.tool+"/"+c.op)
	}
	if strings.Join(got, " ") != "quilzo_read/list_pages quilzo_read/list_pages quilzo_write/write_page quilzo_write/write_page quilzo_read/forbidden" {
		t.Fatalf("calls %v", got)
	}
}

func TestLegacyClientsAreAnsweredWithoutASession(t *testing.T) {
	e, _ := endpoint(t)
	init := hcall{token: "writer", body: `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}`}
	w, resp := init.do(t, e)
	b, _ := json.Marshal(resp.Result)
	if w.Code != 200 || !strings.Contains(string(b), `"protocolVersion":"2025-06-18"`) || w.Header().Get("Mcp-Session-Id") != "" {
		t.Fatalf("%d %s %v", w.Code, b, w.Header())
	}
	// Asked for something older than offered: the newest legacy one.
	init.body = strings.Replace(init.body, "2025-06-18", "2024-11-05", 1)
	_, resp = init.do(t, e)
	if b, _ := json.Marshal(resp.Result); !strings.Contains(string(b), `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("%s", b)
	}
	note := hcall{token: "writer", version: "2025-06-18", body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`}
	if w, _ := note.do(t, e); w.Code != 202 || w.Body.Len() != 0 {
		t.Fatalf("notification: %d %q", w.Code, w.Body.String())
	}
	list := hcall{token: "writer", version: "2025-06-18", body: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`}
	w, resp = list.do(t, e)
	b, _ = json.Marshal(resp.Result)
	if w.Code != 200 || strings.Contains(string(b), "resultType") || !strings.Contains(string(b), "quilzo_find") {
		t.Fatalf("%d %s", w.Code, b)
	}
	// Unknown method: a JSON-RPC error, not a 404 a legacy client would
	// read as a lost session.
	unk := hcall{token: "writer", version: "2025-06-18", body: `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`}
	if w, resp := unk.do(t, e); w.Code != 200 || resp.Error.Code != CodeMethodNotFound {
		t.Fatalf("%d", w.Code)
	}
	// 2025-03-26 clients sent no header at all.
	bare := hcall{token: "writer", body: `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`}
	if w, _ := bare.do(t, e); w.Code != 200 {
		t.Fatalf("bare: %d", w.Code)
	}
	// Still no way round authentication.
	bare.token = ""
	if w, _ := bare.do(t, e); w.Code != 401 {
		t.Fatal("legacy without a token")
	}
}

func TestBodiesAreBounded(t *testing.T) {
	e, _ := endpoint(t)
	c := modern("tools/list", "", `"pad":"`+strings.Repeat("a", MaxBody)+`"`)
	if w, _ := c.do(t, e); w.Code != 413 {
		t.Fatalf("%d", w.Code)
	}
}

func TestHeaderValuesAreDecodedStrictly(t *testing.T) {
	for in, want := range map[string]string{
		"plain":               "plain",
		"=?base64?aMOpbGxv?=": "héllo",
		"=?base64?" + "?=":    "",
		"tab\there":           "tab\there",
	} {
		if got, err := decodeHeaderValue(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"new\nline", "nul\x00", "del\x7f", "high\xc3\xa9", "=?base64?/w==?="} {
		if _, err := decodeHeaderValue(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
