// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/search"
	"github.com/quilzo/quilzo/internal/site"
)

// nlwebSite is a bakery with a public page about bread and a page only
// members read.
func nlwebSite(t *testing.T) *Site {
	t.Helper()
	pages := map[string]any{
		"index":  map[string]any{"title": "Hart's Bakery", "description": "Bread baked before dawn in Leeds."},
		"bread":  map[string]any{"title": "Our sourdough", "description": "Sourdough fermented for thirty hours.", "body": "Sourdough, rye and spelt."},
		"secret": map[string]any{"title": "Sourdough starter recipe", "body": "The sourdough starter, for members.", MembersOnlyField: true},
	}
	st := published(t, pages)
	st.Name = "Hart's Bakery"
	st.Search = search.Build(st.Store.GetRef(site.RefLive), pages)
	return st
}

func askJSON(t *testing.T, st *Site, target string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	if w.Code != 200 {
		t.Fatalf("%s: %d %s", target, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %v\n%s", target, err, w.Body.String())
	}
	return out
}

// An agent asks in plain words and gets the published pages that match, as
// schema.org objects, and never a page only members read.
func TestAnAgentAsksTheSite(t *testing.T) {
	st := nlwebSite(t)
	out := askJSON(t, st, "/ask?query=sourdough&streaming=false")
	results, _ := out["results"].([]any)
	if len(results) != 1 || out["query_id"] == "" || out["mode"] != "list" {
		t.Fatalf("the answer: %v", out)
	}
	r := results[0].(map[string]any)
	obj, _ := r["schema_object"].(map[string]any)
	if r["url"] != "https://example.org/bread" || r["name"] != "Our sourdough" || r["site"] != "Hart's Bakery" ||
		r["description"] != "Sourdough fermented for thirty hours." || obj["@type"] != "WebPage" || obj["url"] != "https://example.org/bread" {
		t.Fatalf("the result: %v", r)
	}

	// Streamed by default, as the protocol says.
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ask?query=sourdough", nil))
	body := w.Body.String()
	if w.Header().Get("Content-Type") != "text/event-stream; charset=utf-8" ||
		!strings.Contains(body, `"message_type":"result_batch"`) || !strings.Contains(body, `"message_type":"complete"`) {
		t.Fatalf("streamed: %s\n%s", w.Header().Get("Content-Type"), body)
	}

	// Posted as JSON too, with the query put in context by the caller.
	req := httptest.NewRequest(http.MethodPost, "/ask", strings.NewReader(
		`{"query":"what about it","decontextualized_query":"sourdough","streaming":false}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "Our sourdough") {
		t.Fatalf("posted: %s", w.Body.String())
	}

	for _, bad := range []string{"/ask?streaming=false", "/ask?query=x&mode=shout", "/ask?query=" + strings.Repeat("a", 301)} {
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, bad, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
	// The chatbots at /ask/NAME are still theirs.
	w = httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ask/help", nil))
	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "query_id") {
		t.Fatal("/ask/NAME answered as NLWeb")
	}
}

// The same over MCP: one read-only tool, and no browser page on another
// origin may call it.
func TestAnAgentAsksOverMCP(t *testing.T) {
	st := nlwebSite(t)
	call := func(body, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, r)
		return w
	}
	if w := call(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, ""); !strings.Contains(w.Body.String(), `"readOnlyHint":true`) {
		t.Fatalf("tools/list: %s", w.Body.String())
	}
	w := call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ask","arguments":{"query":"sourdough"}}}`, "")
	if !strings.Contains(w.Body.String(), "Our sourdough") || strings.Contains(w.Body.String(), "starter recipe") {
		t.Fatalf("tools/call: %s", w.Body.String())
	}
	if w := call(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, "https://evil.example"); w.Code != http.StatusForbidden {
		t.Fatalf("another origin: %d", w.Code)
	}
	if w := call(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, ""); w.Code != http.StatusAccepted {
		t.Fatalf("a notification: %d", w.Code)
	}
}

// An agent on another revision of MCP is answered in a revision it speaks.
//
// # What this found
//
// The public /mcp answered every initialize with 2025-06-18, whatever the
// client asked for, ignored the MCP-Protocol-Version header, and did not
// know server/discover. A 2025-03-26 client was told a revision it may not
// speak, a request naming a revision nobody speaks was answered as if it
// were fine, and a client of the stateless revision found no method to
// start with. The admin's /mcp, in internal/mcp, negotiates all of this;
// the public one now does by the same rules and from the same list.
func TestAnAgentIsAnsweredInARevisionItSpeaks(t *testing.T) {
	st := nlwebSite(t)
	type answer struct {
		Result map[string]any `json:"result"`
		Error  *struct {
			Code int            `json:"code"`
			Data map[string]any `json:"data"`
		} `json:"error"`
	}
	call := func(body string, headers map[string]string) (int, answer) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, r)
		var a answer
		_ = json.Unmarshal(w.Body.Bytes(), &a)
		return w.Code, a
	}
	initialize := func(asked string) string {
		t.Helper()
		_, a := call(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+asked+
			`","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`, nil)
		v, _ := a.Result["protocolVersion"].(string)
		return v
	}

	// The handshake: the revision asked for when it is one this speaks, and
	// otherwise the newest it does.
	for _, v := range mcp.Legacy {
		if got := initialize(v); got != v {
			t.Errorf("a client asking for %s was answered %s", v, got)
		}
	}
	if got := initialize("1999-01-01"); got != mcp.Legacy[0] {
		t.Errorf("a client asking for a revision nobody speaks was answered %s, not %s", got, mcp.Legacy[0])
	}

	// After it: a header naming a revision this does not speak is a 400
	// that says which it does.
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	code, a := call(list, map[string]string{"MCP-Protocol-Version": "1999-01-01"})
	if code != http.StatusBadRequest || a.Error == nil || a.Error.Code != mcp.CodeUnsupportedVersion {
		t.Fatalf("a revision nobody speaks was answered %d %+v", code, a)
	}
	if supported, _ := a.Error.Data["supported"].([]any); len(supported) != len(mcp.Supported()) {
		t.Errorf("the refusal does not say which revisions are spoken: %v", a.Error.Data)
	}
	if code, a := call(list, map[string]string{"MCP-Protocol-Version": "2025-06-18"}); code != 200 || a.Result["tools"] == nil {
		t.Errorf("a client on 2025-06-18 was answered %d %+v", code, a)
	}

	// The stateless revision: no handshake, results marked final, and the
	// same tool.
	modern := func(method, name, params string) (int, answer) {
		meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"` + mcp.Modern + `"}`
		if params != "" {
			params += ","
		}
		h := map[string]string{"MCP-Protocol-Version": mcp.Modern, "Mcp-Method": method}
		if name != "" {
			h["Mcp-Name"] = name
		}
		return call(`{"jsonrpc":"2.0","id":3,"method":"`+method+`","params":{`+params+meta+`}}`, h)
	}
	code, a = modern("server/discover", "", "")
	if code != 200 || a.Result["resultType"] != "complete" {
		t.Fatalf("server/discover was answered %d %+v", code, a)
	}
	if supported, _ := a.Result["supportedVersions"].([]any); len(supported) == 0 || supported[0] != mcp.Modern {
		t.Errorf("server/discover does not name the revisions spoken: %v", a.Result)
	}
	if code, _ := modern("initialize", "", ""); code != http.StatusNotFound {
		t.Errorf("the stateless revision has no handshake, and initialize was answered %d", code)
	}
	code, a = modern("tools/call", "ask", `"name":"ask","arguments":{"query":"sourdough"}`)
	body, _ := json.Marshal(a.Result)
	if code != 200 || a.Result["resultType"] != "complete" || !strings.Contains(string(body), "Our sourdough") {
		t.Errorf("ask on the stateless revision was answered %d %s", code, body)
	}
	if code, a := modern("tools/call", "ask", `"name":"other","arguments":{}`); code != http.StatusBadRequest || a.Error == nil {
		t.Errorf("a header and a body naming different tools were answered %d %+v", code, a)
	}
}
