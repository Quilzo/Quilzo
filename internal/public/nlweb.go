// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// The site asked in natural language by any agent (NLWeb).
//
// NLWeb is an open protocol for a site to answer a question with the
// schema.org objects that match it: GET or POST /ask with the query, and
// the same over MCP at /mcp. An agent then reads the site as data rather
// than scraping pages built for people.
//
// What it answers from is what a visitor may read now: the published pages
// the site's own search finds, nothing for members, nothing outside its
// publish window. "summarize" and "generate" add the answer the site's
// question box gives, when it has one, with the same limits, refusals and
// disclosure. It writes nothing, and the crawl gate in front of the whole
// site decides, as it does for every page, who may ask at all.

// nlwebResults bounds a result list.
const nlwebResults = 10

// nlwebQuery is what an /ask request asks.
type nlwebQuery struct {
	Query, Mode, QueryID string
	Streaming            bool
}

// readNLWebQuery reads a query from the URL, a form, or a JSON body.
func readNLWebQuery(r *http.Request) (nlwebQuery, string) {
	q := nlwebQuery{Streaming: true}
	get := r.URL.Query().Get
	if r.Method == http.MethodPost {
		ct := r.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "application/json") {
			var body map[string]any
			if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
				return q, "the body is not JSON"
			}
			get = func(k string) string {
				switch v := body[k].(type) {
				case string:
					return v
				case bool:
					if v {
						return "true"
					}
					return "false"
				}
				return ""
			}
		} else {
			r.Body = http.MaxBytesReader(nil, r.Body, 16<<10)
			if err := r.ParseForm(); err != nil {
				return q, "the form could not be read"
			}
			get = r.FormValue
		}
	}
	q.Query = strings.TrimSpace(get("query"))
	// A query already put in context by the caller is the one to answer.
	if d := strings.TrimSpace(get("decontextualized_query")); d != "" {
		q.Query = d
	}
	q.Mode = strings.TrimSpace(get("mode"))
	if q.Mode == "" {
		q.Mode = "list"
	}
	q.QueryID = strings.TrimSpace(get("query_id"))
	if s := strings.ToLower(strings.TrimSpace(get("streaming"))); s == "0" || s == "false" {
		q.Streaming = false
	}
	switch {
	case q.Query == "":
		return q, "a query is required"
	case utf8.RuneCountInString(q.Query) > 300:
		return q, "the query is too long"
	case q.Mode != "list" && q.Mode != "summarize" && q.Mode != "generate":
		return q, "mode is list, summarize or generate"
	case len(q.QueryID) > 64:
		return q, "the query_id is too long"
	}
	if q.QueryID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		q.QueryID = hex.EncodeToString(b)
	}
	return q, ""
}

// nlwebAnswer is the results, and the answer when asked for one.
func (st *Site) nlwebAnswer(r *http.Request, q nlwebQuery) map[string]any {
	visible, _, err := st.pages()
	if err != nil {
		visible = map[string]any{}
	}
	// A record's page answers as a page does, from what it shows.
	visible = st.withRecords(visible)
	results := []any{}
	for _, res := range st.searchVisible(q.Query, visible, nlwebResults) {
		body, _ := visible[res.Page].(map[string]any)
		href := st.absoluteURL(st.pagePath(res.Page))
		name := res.Title
		if name == "" {
			name = res.Page
		}
		object := documentLD(body, st.Name)
		if object == nil {
			object = map[string]any{"@context": "https://schema.org", "@type": "WebPage", "name": name}
		}
		object["url"] = href
		results = append(results, map[string]any{
			"url": href, "name": name, "site": st.Name, "score": res.Score,
			"description": describe(body), "schema_object": object,
		})
	}
	out := map[string]any{"query_id": q.QueryID, "query": q.Query, "mode": q.Mode, "site": st.Name,
		"results": results}
	if q.Mode != "list" {
		if ans := st.searchAnswer(r, q.Query); ans != nil {
			var text []string
			for _, s := range ans["sentences"].([]any) {
				text = append(text, s.(map[string]any)["text"].(string))
			}
			key := "summary"
			if q.Mode == "generate" {
				key = "answer"
			}
			out[key] = strings.Join(text, " ")
			out["sources"] = ans["sources"]
			out["disclosure"] = ans["disclosure"]
		}
	}
	return out
}

// describe is what a page says it is: its description, or its lead.
func describe(body map[string]any) string {
	if d, _ := body["description"].(string); d != "" {
		return d
	}
	if h, ok := body["hero"].(map[string]any); ok {
		if l, _ := h["lead"].(string); l != "" {
			return l
		}
	}
	return ""
}

// absoluteURL is a path on this site, absolute when the site knows its
// address.
func (st *Site) absoluteURL(path string) string {
	if st.BaseURL == "" {
		return path
	}
	return strings.TrimSuffix(st.BaseURL, "/") + path
}

// nlwebAsk answers GET or POST /ask.
func (st *Site) nlwebAsk(w http.ResponseWriter, r *http.Request) {
	if st.searchIndex() == nil {
		http.NotFound(w, r)
		return
	}
	q, problem := readNLWebQuery(r)
	if problem != "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": problem})
		return
	}
	answer := st.nlwebAnswer(r, q)
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Access-Control-Allow-Origin", "*")
	if !q.Streaming {
		h.Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(answer)
		return
	}
	// Streamed as server-sent events: the results in one batch, then the
	// summary or answer when there is one, then the end.
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	send := func(v map[string]any) {
		b, _ := json.Marshal(v)
		_, _ = w.Write([]byte("data: " + string(b) + "\n\n"))
	}
	send(map[string]any{"message_type": "result_batch", "query_id": q.QueryID, "results": answer["results"]})
	for _, key := range []string{"summary", "answer"} {
		if text, ok := answer[key].(string); ok {
			send(map[string]any{"message_type": key, "query_id": q.QueryID, "message": text,
				"sources": answer["sources"], "disclosure": answer["disclosure"]})
		}
	}
	send(map[string]any{"message_type": "complete", "query_id": q.QueryID})
}

// nlwebMCP is the same over MCP: one tool, ask, read-only.
func (st *Site) nlwebMCP(w http.ResponseWriter, r *http.Request) {
	if st.searchIndex() == nil {
		http.NotFound(w, r)
		return
	}
	// A browser page on another origin is not who this is for, and a
	// request from one is what DNS rebinding looks like.
	if o := r.Header.Get("Origin"); o != "" && (st.BaseURL == "" || !sameOrigin(o, st.BaseURL)) {
		http.Error(w, "this origin may not call the tool", http.StatusForbidden)
		return
	}
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<10)).Decode(&req); err != nil {
		http.Error(w, "not JSON-RPC", http.StatusBadRequest)
		return
	}
	reply := func(result any, code int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		out := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if msg != "" {
			out["error"] = map[string]any{"code": code, "message": msg}
		} else {
			out["result"] = result
		}
		_ = json.NewEncoder(w).Encode(out)
	}
	if len(req.ID) == 0 {
		// A notification: nothing to answer.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		reply(map[string]any{"protocolVersion": "2025-06-18",
			"capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo":   map[string]any{"name": st.siteLabel(), "version": "nlweb"},
			"instructions": "Ask this site a question; answers come only from its published pages."}, 0, "")
	case "ping":
		reply(map[string]any{}, 0, "")
	case "tools/list":
		reply(map[string]any{"tools": []any{map[string]any{
			"name": "ask",
			"description": "Ask " + st.siteLabel() + " in plain words. Answers with the published pages that match, " +
				"as schema.org objects, and in summarize or generate mode the site's own answer with its sources.",
			"inputSchema": map[string]any{"type": "object", "required": []string{"query"},
				"properties": map[string]any{
					"query": map[string]any{"type": "string", "description": "The question or the words to look for."},
					"mode": map[string]any{"type": "string", "enum": []string{"list", "summarize", "generate"},
						"description": "list (the default) for matching pages; summarize or generate for an answer too."},
				}},
			"annotations": map[string]any{"readOnlyHint": true, "openWorldHint": false},
		}}}, 0, "")
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name != "ask" {
			reply(nil, -32602, "the one tool here is ask")
			return
		}
		v := url.Values{}
		for _, k := range []string{"query", "mode"} {
			if s, ok := p.Arguments[k].(string); ok {
				v.Set(k, s)
			}
		}
		inner := r.Clone(r.Context())
		inner.Method, inner.URL = http.MethodGet, &url.URL{Path: "/ask", RawQuery: v.Encode()}
		q, problem := readNLWebQuery(inner)
		if problem != "" {
			reply(map[string]any{"isError": true, "content": []any{map[string]any{"type": "text", "text": problem}}}, 0, "")
			return
		}
		b, _ := json.Marshal(st.nlwebAnswer(r, q))
		reply(map[string]any{"content": []any{map[string]any{"type": "text", "text": string(b)}}}, 0, "")
	default:
		reply(nil, -32601, "no such method")
	}
}

// sameOrigin compares an Origin header with the site's own address.
func sameOrigin(origin, base string) bool {
	o, err1 := url.Parse(origin)
	b, err2 := url.Parse(base)
	return err1 == nil && err2 == nil && strings.EqualFold(o.Scheme, b.Scheme) && strings.EqualFold(o.Host, b.Host)
}
