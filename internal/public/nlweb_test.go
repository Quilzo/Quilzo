// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
