// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package websearch is the web search providers an agent's web_search can
// ask, as data, and reading what each answers into one shape.
//
// # Why data
//
// Every one of them is an address, a way of sending the key, a query in
// the address or in a JSON body, and a list of results whose title, link
// and summary have names of their own. What differs is those names, not
// code, so each provider is a profile and one function asks any of them.
//
// # What a profile pins
//
// A search goes to the provider's own host and nowhere else, over https,
// through the client that refuses private addresses (internal/fetch); its
// key is a sealed credential (quilzo secret set search-ID), sent only in
// the way the profile names and only to that host. A provider run on the
// operator's own network (SearXNG) is the one exception to the public
// address rule, and its address is a setting (agents.search_url).
//
// The query is the model's words and goes to a third party: the breaker
// (internal/agent) holds a search for a person once a run holds something
// private.
package websearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Provider is one search provider's profile.
type Provider struct {
	ID, Name string
	// Method is GET, with the query in the address, or POST, with it in
	// Body.
	Method string
	// Address is where a search goes, with {query} and {count} put in,
	// escaped, for GET. A provider on the operator's network takes it
	// from agents.search_url instead, with Path after it.
	Address string
	Path    string
	// Body is the JSON a POST sends, with "{query}" and {count} put in.
	Body string
	// Key is how the key is sent: "header:NAME", "bearer", "prefix:WORD"
	// (Authorization: WORD KEY), "query:NAME", or "none".
	Key string
	// Headers are sent on every search.
	Headers map[string]string
	// Results is where the list is in the answer, by dotted names.
	Results string
	// Title, Link and Summary name each result's fields; Summary may name
	// a list, whose parts are joined.
	Title, Link, Summary string
	// Local is a provider on the operator's own network.
	Local bool
	// Docs is where the profile came from.
	Docs string
}

// Providers are the built-in profiles, by id.
var Providers = []Provider{
	{ID: "brave", Name: "Brave Search", Method: "GET",
		Address: "https://api.search.brave.com/res/v1/web/search?q={query}&count={count}",
		Key:     "header:X-Subscription-Token", Headers: map[string]string{"Accept": "application/json"},
		Results: "web.results", Title: "title", Link: "url", Summary: "description",
		Docs: "https://api-dashboard.search.brave.com/app/documentation/web-search/get-started"},
	{ID: "tavily", Name: "Tavily", Method: "POST", Address: "https://api.tavily.com/search",
		Body: `{"query":"{query}","max_results":{count}}`, Key: "bearer",
		Results: "results", Title: "title", Link: "url", Summary: "content",
		Docs: "https://docs.tavily.com/documentation/api-reference/endpoint/search"},
	{ID: "exa", Name: "Exa", Method: "POST", Address: "https://api.exa.ai/search",
		Body: `{"query":"{query}","numResults":{count},"contents":{"text":{"maxCharacters":400}}}`, Key: "header:x-api-key",
		Results: "results", Title: "title", Link: "url", Summary: "text",
		Docs: "https://docs.exa.ai/reference/search"},
	{ID: "serper", Name: "Serper (Google results)", Method: "POST", Address: "https://google.serper.dev/search",
		Body: `{"q":"{query}","num":{count}}`, Key: "header:X-API-KEY",
		Results: "organic", Title: "title", Link: "link", Summary: "snippet",
		Docs: "https://serper.dev/"},
	{ID: "serpapi", Name: "SerpApi (Google results)", Method: "GET",
		Address: "https://serpapi.com/search.json?engine=google&q={query}&num={count}", Key: "query:api_key",
		Results: "organic_results", Title: "title", Link: "link", Summary: "snippet",
		Docs: "https://serpapi.com/search-api"},
	{ID: "kagi", Name: "Kagi", Method: "GET", Address: "https://kagi.com/api/v0/search?q={query}&limit={count}",
		Key: "prefix:Bot", Results: "data", Title: "title", Link: "url", Summary: "snippet",
		Docs: "https://help.kagi.com/kagi/api/search.html"},
	{ID: "perplexity", Name: "Perplexity Search", Method: "POST", Address: "https://api.perplexity.ai/search",
		Body: `{"query":"{query}","max_results":{count}}`, Key: "bearer",
		Results: "results", Title: "title", Link: "url", Summary: "snippet",
		Docs: "https://docs.perplexity.ai/api-reference/search-post"},
	{ID: "jina", Name: "Jina Search", Method: "GET", Address: "https://s.jina.ai/?q={query}",
		Key: "bearer", Headers: map[string]string{"Accept": "application/json", "X-Respond-With": "no-content"},
		Results: "data", Title: "title", Link: "url", Summary: "description",
		Docs: "https://jina.ai/reader/"},
	{ID: "searxng", Name: "SearXNG on your own network", Method: "GET", Path: "/search?q={query}&format=json",
		Key: "none", Results: "results", Title: "title", Link: "url", Summary: "content", Local: true,
		Docs: "https://docs.searxng.org/dev/search_api.html"},
}

// Get is a provider by id.
func Get(id string) (Provider, bool) {
	i := slices.IndexFunc(Providers, func(p Provider) bool { return p.ID == id })
	if i < 0 {
		return Provider{}, false
	}
	return Providers[i], true
}

// IDs are the providers' ids.
func IDs() []string {
	out := make([]string, len(Providers))
	for i, p := range Providers {
		out[i] = p.ID
	}
	return out
}

// Secret is the name of the sealed credential a provider's key is kept as.
func (p Provider) Secret() string { return "search-" + p.ID }

// Bounds on a search.
const (
	MaxQuery   = 400
	MaxResults = 20
)

// Result is one thing a search found.
type Result struct {
	Title, URL, Summary string
}

// Do sends one request: the program's guarded client in a run, a stand-in
// in a test. It answers with the status and the body.
type Do func(ctx context.Context, method, address string, body []byte, headers map[string]string) (int, []byte, error)

// Request is what a search sends, before it is sent: the address, the body
// and the headers, the key among them. base is agents.search_url, for a
// provider on the operator's network.
func (p Provider) Request(query string, count int, key, base string) (method, address string, body []byte, headers map[string]string, err error) {
	query = strings.TrimSpace(query)
	switch {
	case query == "":
		return "", "", nil, nil, errors.New("say what to search for")
	case len(query) > MaxQuery:
		return "", "", nil, nil, fmt.Errorf("a search is at most %d characters", MaxQuery)
	}
	if count <= 0 {
		count = 8
	}
	count = min(count, MaxResults)
	address = p.Address
	if p.Local {
		u, perr := url.Parse(strings.TrimRight(strings.TrimSpace(base), "/"))
		if perr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
			return "", "", nil, nil, fmt.Errorf("%s is reached at agents.search_url, an https address on your own network", p.Name)
		}
		address = u.String() + p.Path
	}
	address = strings.ReplaceAll(address, "{query}", url.QueryEscape(query))
	address = strings.ReplaceAll(address, "{count}", strconv.Itoa(count))
	headers = map[string]string{}
	for k, v := range p.Headers {
		headers[k] = v
	}
	if p.Body != "" {
		// As JSON, without escaping & and < as a page would need: this is
		// a request body, and the provider reads the query as it was.
		var qb bytes.Buffer
		enc := json.NewEncoder(&qb)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(query)
		b := strings.ReplaceAll(p.Body, `"{query}"`, strings.TrimSpace(qb.String()))
		body = []byte(strings.ReplaceAll(b, "{count}", strconv.Itoa(count)))
		headers["Content-Type"] = "application/json"
	}
	if p.Key != "none" && key == "" {
		return "", "", nil, nil, fmt.Errorf("%s needs its key: quilzo secret set %s", p.Name, p.Secret())
	}
	kind, name, _ := strings.Cut(p.Key, ":")
	switch kind {
	case "none":
	case "bearer":
		headers["Authorization"] = "Bearer " + key
	case "header":
		headers[name] = key
	case "prefix":
		headers["Authorization"] = name + " " + key
	case "query":
		sep := "?"
		if strings.Contains(address, "?") {
			sep = "&"
		}
		address += sep + url.QueryEscape(name) + "=" + url.QueryEscape(key)
	default:
		return "", "", nil, nil, fmt.Errorf("%s sends its key %q, which this does not know", p.ID, p.Key)
	}
	return p.Method, address, body, headers, nil
}

// Search asks a provider, and reads what it answers.
func (p Provider) Search(ctx context.Context, do Do, query string, count int, key, base string) ([]Result, error) {
	method, address, body, headers, err := p.Request(query, count, key, base)
	if err != nil {
		return nil, err
	}
	status, answer, err := do(ctx, method, address, body, headers)
	if err != nil {
		if key != "" {
			return nil, errors.New(strings.ReplaceAll(err.Error(), url.QueryEscape(key), "[key]"))
		}
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("%s answered %d: %s", p.Name, status, clip(string(bytes.TrimSpace(answer)), 200))
	}
	return p.Read(answer, count)
}

// Read is the results in a provider's answer, at most count of them, each
// with a link.
func (p Provider) Read(answer []byte, count int) ([]Result, error) {
	if count <= 0 {
		count = 8
	}
	count = min(count, MaxResults)
	var doc any
	if err := json.Unmarshal(answer, &doc); err != nil {
		return nil, fmt.Errorf("%s did not answer in JSON: %v", p.Name, err)
	}
	if _, ok := doc.(map[string]any); !ok {
		return nil, fmt.Errorf("%s did not answer with an object", p.Name)
	}
	// A provider that found nothing may leave the list out altogether.
	at := doc
	for _, part := range strings.Split(p.Results, ".") {
		m, _ := at.(map[string]any)
		at = m[part]
	}
	list, _ := at.([]any)
	var out []Result
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		r := Result{Title: text(m[p.Title]), URL: text(m[p.Link]), Summary: text(m[p.Summary])}
		if u, err := url.Parse(r.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			continue
		}
		out = append(out, r)
		if len(out) == count {
			break
		}
	}
	return out, nil
}

// text is a field as words: a string, or a list of them joined.
func text(v any) string {
	switch t := v.(type) {
	case string:
		return clip(strings.Join(strings.Fields(t), " "), 500)
	case []any:
		var parts []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				parts = append(parts, s)
			}
		}
		return text(strings.Join(parts, " … "))
	}
	return ""
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
