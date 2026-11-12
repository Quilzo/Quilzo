// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// A page on another origin may post its question as JSON, as /ask's answers
// say any origin may read them.
//
// A browser asks first, with OPTIONS, before it posts JSON to another site.
// /ask had no answer for that: it was redirected to /ask/ and then not
// found, with no Access-Control headers, so only a GET or a form post ever
// reached it from a page. Its refusals did not say any origin may read
// them either, so a page was told only that the request failed.
func TestABrowserOnAnotherOriginMayPostItsQuestion(t *testing.T) {
	st := nlwebSite(t)
	req := httptest.NewRequest(http.MethodOptions, "/ask", nil)
	req.Header.Set("Origin", "https://agent.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	h := w.Header()
	if w.Code != http.StatusNoContent || h.Get("Access-Control-Allow-Origin") != "*" ||
		!strings.Contains(h.Get("Access-Control-Allow-Methods"), "POST") ||
		!strings.Contains(strings.ToLower(h.Get("Access-Control-Allow-Headers")), "content-type") {
		t.Fatalf("the preflight was answered %d %v", w.Code, h)
	}
	if h.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("the preflight allows credentials")
	}
	// The chatbots under /ask/ are not opened to other origins by it.
	req = httptest.NewRequest(http.MethodOptions, "/ask/help", nil)
	req.Header.Set("Origin", "https://agent.example")
	w = httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("a chatbot answered a preflight with %v", w.Header())
	}
	// A refusal is readable by the page that asked, as an answer is.
	w = httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ask?streaming=false", nil))
	if w.Code != http.StatusBadRequest || w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("a refusal: %d %v", w.Code, w.Header())
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

// The tool takes a page's call from the site's own origin, its default port
// written or not, and refuses another scheme, another port and an Origin
// with anything after the host (sameorigin.Same).
//
// Compared by scheme and host as strings, the site's own origin with its
// port written was another site.
func TestTheToolKnowsTheSitesOwnOriginWithItsPortWritten(t *testing.T) {
	st := nlwebSite(t)
	st.BaseURL = "https://bakery.example/"
	for origin, allowed := range map[string]bool{
		"https://bakery.example":      true,
		"https://BAKERY.example:443":  true,
		"http://bakery.example":       false,
		"https://bakery.example:8443": false,
		"https://bakery.example/evil": false,
		"null":                        false,
	} {
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, r)
		if (w.Code != http.StatusForbidden) != allowed {
			t.Errorf("Origin %s: %d", origin, w.Code)
		}
	}
}

// The site's /mcp takes a request by the transport's rules, as the admin's
// does, and answers one it does not take in JSON-RPC.
//
// # What this found
//
// Only the revision was decided by the admin's rules. A GET looking for a
// stream was given the site's 404 page, which a client reads as no server
// here, where the transport answers 405; text/plain, jsonrpc 1.0 or none,
// an object for an id and data after the message were all answered as if
// they were right; and a batch, a body over the bound or one that was not
// JSON was a text/plain 400 a client cannot read as an answer. A page the
// site has at /mcp is still that page for a browser.
func TestTheSitesMCPTakesARequestByTheTransportsRules(t *testing.T) {
	st := nlwebSite(t)
	type answer struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Result map[string]any `json:"result"`
	}
	send := func(method, ctype, body string, headers map[string]string) (*httptest.ResponseRecorder, answer) {
		t.Helper()
		r := httptest.NewRequest(method, "/mcp", strings.NewReader(body))
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, r)
		var a answer
		_ = json.Unmarshal(w.Body.Bytes(), &a)
		return w, a
	}
	list := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	w, _ := send(http.MethodGet, "", "", map[string]string{"Accept": "text/event-stream"})
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Errorf("a GET for a stream: %d %q", w.Code, w.Header().Get("Allow"))
	}
	if w, _ := send(http.MethodPost, "text/plain", list, nil); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", w.Code)
	}
	for name, tc := range map[string]struct {
		body   string
		status int
		code   int
	}{
		"jsonrpc 1.0":   {strings.Replace(list, `"2.0"`, `"1.0"`, 1), http.StatusBadRequest, mcp.CodeInvalidRequest},
		"no jsonrpc":    {`{"id":1,"method":"tools/list"}`, http.StatusBadRequest, mcp.CodeInvalidRequest},
		"object id":     {strings.Replace(list, `"id":1`, `"id":{"x":1}`, 1), http.StatusBadRequest, mcp.CodeInvalidRequest},
		"trailing data": {list + `{"more":true}`, http.StatusBadRequest, mcp.CodeParse},
		"batch":         {"[" + list + "]", http.StatusBadRequest, mcp.CodeInvalidRequest},
		"not JSON":      {"{", http.StatusBadRequest, mcp.CodeParse},
		"40 KB":         {`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("a", 40<<10) + `"}}`, http.StatusRequestEntityTooLarge, mcp.CodeInvalidRequest},
	} {
		w, a := send(http.MethodPost, "application/json", tc.body, nil)
		if w.Code != tc.status || w.Header().Get("Content-Type") != "application/json" || a.Error == nil || a.Error.Code != tc.code {
			t.Errorf("%s: %d %q %s", name, w.Code, w.Header().Get("Content-Type"), w.Body.String())
		}
		if name == "40 KB" && (a.Error == nil || !strings.Contains(a.Error.Message, "at most 32768 bytes")) {
			t.Errorf("%s does not say the limit: %s", name, w.Body.String())
		}
	}
	// And a request as it should be is still answered.
	if w, a := send(http.MethodPost, "application/json", list, nil); w.Code != 200 || a.Result["tools"] == nil {
		t.Errorf("a right request: %d %s", w.Code, w.Body.String())
	}

	// A page called mcp is the site's, for anybody reading it.
	pages := map[string]any{"mcp": map[string]any{"title": "What MCP is"}}
	st = published(t, pages)
	st.Search = search.Build(st.Store.GetRef(site.RefLive), pages)
	if w, _ := send(http.MethodGet, "", "", map[string]string{"Accept": "text/html"}); w.Code != 200 || !strings.Contains(w.Body.String(), "What MCP is") {
		t.Errorf("the page at /mcp: %d %s", w.Code, w.Body.String())
	}
}

// A request to the site's /mcp that is not a POST is told the transport
// takes POST, whatever it says it accepts, unless the site has something of
// its own at that address or a browser is asking for a page.
//
// Only a GET that named text/event-stream was told so. A client that
// probed with a plain GET, accepting anything or nothing in particular, as
// a fetch does by default, was still given the site's 404 page and read it
// as no server here; so was one ending a session with DELETE.
func TestARequestToTheSitesMCPThatIsNotAPostIsToldItTakesPost(t *testing.T) {
	send := func(st *Site, method, accept string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/mcp", nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, r)
		return w
	}
	st := nlwebSite(t)
	for _, tc := range []struct{ method, accept string }{
		{http.MethodGet, ""},
		{http.MethodGet, "*/*"},
		{http.MethodGet, "application/json"},
		{http.MethodHead, ""},
		{http.MethodDelete, ""},
		{http.MethodPut, "*/*"},
	} {
		w := send(st, tc.method, tc.accept)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" || strings.Contains(w.Body.String(), "<html") {
			t.Errorf("%s accepting %q: %d, Allow %q, %s", tc.method, tc.accept, w.Code, w.Header().Get("Allow"),
				w.Header().Get("Content-Type"))
		}
	}
	// A browser reading the site is told what it always was: there is no
	// such page, by the site's own page.
	if w := send(st, http.MethodGet, "text/html,application/xhtml+xml,*/*;q=0.8"); w.Code != http.StatusNotFound ||
		!strings.Contains(w.Body.String(), "Page not found") {
		t.Errorf("a browser at /mcp: %d %s", w.Code, w.Header().Get("Content-Type"))
	}

	// What the site has at /mcp is the site's, for whoever asks for it and
	// however; only a client asking for a stream is told there is none.
	pages := map[string]any{"mcp": map[string]any{"title": "What MCP is"}}
	st = published(t, pages)
	st.Search = search.Build(st.Store.GetRef(site.RefLive), pages)
	for _, accept := range []string{"", "*/*", "text/html"} {
		if w := send(st, http.MethodGet, accept); w.Code != 200 || !strings.Contains(w.Body.String(), "What MCP is") {
			t.Errorf("the page at /mcp, accepting %q: %d", accept, w.Code)
		}
	}
	if w := send(st, http.MethodGet, "text/event-stream"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("a GET for a stream where there is a page: %d", w.Code)
	}

	// A site with no tool has no server at /mcp to speak for.
	st = published(t, map[string]any{"index": map[string]any{"title": "Home"}})
	if w := send(st, http.MethodGet, "*/*"); w.Code != http.StatusNotFound {
		t.Errorf("a site with no tool: %d", w.Code)
	}
}

// The site's one tool takes what its schema says, and a call that does not
// fit is invalid params naming the argument, as at the admin's /mcp.
//
// The arguments were read as they came. A query that was a number, or sent
// under another name, was no query, and the agent that had given one was
// told "a query is required"; a mode that was not text was no mode, and
// was answered as a list without a word; and arguments that were not an
// object were answered "the one tool here is ask" by a call to ask.
func TestTheSitesToolTakesWhatItsSchemaSays(t *testing.T) {
	st := nlwebSite(t)
	call := func(params string) (int, string, string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, r)
		var a struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
			t.Fatalf("%s: %s", params, w.Body.String())
		}
		if a.Error == nil {
			return 0, "", string(a.Result)
		}
		return a.Error.Code, a.Error.Message, ""
	}
	for name, tc := range map[string]struct {
		params string
		says   []string
	}{
		"a query that is a number":    {`{"name":"ask","arguments":{"query":12}}`, []string{"query", "string"}},
		"no query":                    {`{"name":"ask","arguments":{}}`, []string{"query"}},
		"no arguments":                {`{"name":"ask"}`, []string{"query"}},
		"the query under another":     {`{"name":"ask","arguments":{"question":"bread"}}`, []string{"needs query"}},
		"a mode that is a number":     {`{"name":"ask","arguments":{"query":"bread","mode":5}}`, []string{"mode", "string"}},
		"arguments that are text":     {`{"name":"ask","arguments":"query=bread"}`, []string{"arguments", "object"}},
		"arguments that are a list":   {`{"name":"ask","arguments":["bread"]}`, []string{"arguments", "object"}},
		"an argument it does not":     {`{"name":"ask","arguments":{"query":"bread","site":"elsewhere"}}`, []string{"site"}},
		"a name that is not a string": {`{"name":5,"arguments":{"query":"bread"}}`, []string{"name"}},
	} {
		code, message, result := call(tc.params)
		if code != mcp.CodeInvalidParams {
			t.Errorf("%s: %d %q %s", name, code, message, result)
			continue
		}
		for _, w := range tc.says {
			if !strings.Contains(message, w) {
				t.Errorf("%s: %q does not say %q", name, message, w)
			}
		}
	}
	// Which modes there are is still said in the tool's own words, which
	// name them.
	if code, message, result := call(`{"name":"ask","arguments":{"query":"bread","mode":"everything"}}`); !strings.Contains(message+result, "list, summarize or generate") {
		t.Errorf("a mode it does not have: %d %q %s", code, message, result)
	}
	// A tool it does not have is still told which it has.
	if code, message, _ := call(`{"name":"search","arguments":{"query":"bread"}}`); code == 0 || !strings.Contains(message, "ask") {
		t.Errorf("another tool: %d %q", code, message)
	}
	// And a call that fits is answered, a null standing for an argument
	// left out, as clients that fill every optional field send it.
	for _, params := range []string{
		`{"name":"ask","arguments":{"query":"bread"}}`,
		`{"name":"ask","arguments":{"query":"bread","mode":"list"}}`,
		`{"name":"ask","arguments":{"query":"bread","mode":null}}`,
	} {
		if code, message, result := call(params); code != 0 || !strings.Contains(result, "Hart") {
			t.Errorf("%s: %d %q %s", params, code, message, result)
		}
	}
}

// The site's agent interface is POST /mcp, and the transport it speaks has a
// client open GET /mcp for messages from the server and requires a server
// with none to send to answer 405. Every method but POST fell through to the
// page handler, which answered the site's HTML 404 (a client takes that for
// a server that is gone) and counted /mcp as somebody hunting for the admin,
// so a visitor's agent following the transport was one address from being
// slowed down. A page published at /mcp is still served there.
func TestTheSitesAgentInterfaceTakesPOSTAndSaysSo(t *testing.T) {
	st := nlwebSite(t)
	clock := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	heard := watching(st, &clock)
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions, http.MethodPut} {
		req := httptest.NewRequest(m, "/mcp", nil)
		req.Header.Set("Accept", "text/event-stream")
		req.RemoteAddr = "203.0.113.9:4000"
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" ||
			strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s /mcp answered %d, Allow %q, %s", m, w.Code, w.Header().Get("Allow"), w.Header().Get("Content-Type"))
		}
	}
	// Two of the admin's addresses besides, under the threshold of three.
	from(st, http.MethodGet, "/signin", "203.0.113.9", nil)
	from(st, http.MethodGet, "/tokens", "203.0.113.9", nil)
	if len(*heard) != 0 {
		t.Fatalf("heard %v; the site's own agent interface is no admin address", *heard)
	}
	// The interface itself still answers.
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"result"`) {
		t.Fatalf("POST /mcp: %d %s", w.Code, w.Body.String())
	}

	pages := map[string]any{"index": map[string]any{"title": "Home"},
		"mcp": map[string]any{"title": "Our MCP guide"}}
	withPage := published(t, pages)
	withPage.Search = search.Build(withPage.Store.GetRef(site.RefLive), pages)
	if w := get(withPage, "/mcp", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Our MCP guide") {
		t.Fatalf("the page published at /mcp answered %d", w.Code)
	}
}

// A browser asking the site's agent interface for a page is told by the
// site's own page that there is none, and is not heard as hunting for the
// admin: the two rules above, held together. While the site has the tool,
// /mcp is its own address, whoever asks for it and however.
func TestABrowserAtTheSitesAgentInterfaceIsNotHuntingForTheAdmin(t *testing.T) {
	st := nlwebSite(t)
	clock := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	heard := watching(st, &clock)
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.RemoteAddr = "203.0.113.9:4000"
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "Page not found") {
		t.Fatalf("a browser at /mcp: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	// Two of the admin's addresses besides, under the threshold of three.
	from(st, http.MethodGet, "/signin", "203.0.113.9", nil)
	from(st, http.MethodGet, "/tokens", "203.0.113.9", nil)
	if len(*heard) != 0 {
		t.Fatalf("heard %v; the site's own agent interface is no admin address", *heard)
	}
}
