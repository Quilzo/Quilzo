// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package apiimport turns descriptions other people publish into
// integration declarations: an OpenAPI 3 document into a REST integration,
// and an MCP registry server.json into an MCP server.
//
// # What it never does
//
// It never enables what it declares, and never agrees to a tool on its own:
// the operations or tools an install may call are the ones a person names,
// and the declaration arrives switched off. It never fetches anything a
// description points at. A $ref to anything outside the document is left
// unresolved and named, which is the server-side request forgery that schema
// validators keep shipping; a local $ref is followed to a bounded depth. A
// parameter in a header or a cookie is left out and named, because an
// operation's headers are Quilzo's to set, and an API key in a query string
// is not imported, because a query string ends up in logs.
package apiimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
)

// MaxDocument bounds what is read.
const MaxDocument = 8 << 20

// Imported is a declaration and what was decided making it.
type Imported struct {
	Integration agent.Integration
	// Available is every operation or tool the description offers, for the
	// person choosing which to use.
	Available []Offered
	Notes     []string
}

// Offered is one operation or tool on offer.
type Offered struct {
	Name, Method, Path, Summary string
	Writes                      bool
}

var reWord = regexp.MustCompile(`[^A-Za-z0-9]+`)

// opName is an operation's name: its operationId when it has a usable one,
// otherwise its method and path.
func opName(id, method, path string, taken map[string]bool) string {
	n := strings.Trim(reWord.ReplaceAllString(id, "_"), "_")
	if n == "" {
		n = strings.ToLower(method) + "_" + strings.Trim(reWord.ReplaceAllString(path, "_"), "_")
	}
	if n == "" || !(n[0] >= 'A' && n[0] <= 'Z' || n[0] >= 'a' && n[0] <= 'z') {
		n = "op_" + n
	}
	if len(n) > 60 {
		n = n[:60]
	}
	base, i := n, 2
	for taken[n] {
		n = fmt.Sprintf("%s_%d", base, i)
		i++
	}
	taken[n] = true
	return n
}

type document struct {
	OpenAPI string `json:"openapi"`
	Swagger string `json:"swagger"`
	Info    struct {
		Title       string `json:"title"`
		Description string `json:"description"`
	} `json:"info"`
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Parameters      map[string]json.RawMessage `json:"parameters"`
		Schemas         map[string]json.RawMessage `json:"schemas"`
		RequestBodies   map[string]json.RawMessage `json:"requestBodies"`
		SecuritySchemes map[string]struct {
			Type   string `json:"type"`
			Scheme string `json:"scheme"`
			In     string `json:"in"`
			Name   string `json:"name"`
		} `json:"securitySchemes"`
	} `json:"components"`
	Security []map[string][]string `json:"security"`
}

type operation struct {
	OperationID string            `json:"operationId"`
	Summary     string            `json:"summary"`
	Description string            `json:"description"`
	Parameters  []json.RawMessage `json:"parameters"`
	RequestBody json.RawMessage   `json:"requestBody"`
	Deprecated  bool              `json:"deprecated"`
}

type parameter struct {
	Ref         string `json:"$ref"`
	Name        string `json:"name"`
	In          string `json:"in"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Schema      struct {
		Type string `json:"type"`
	} `json:"schema"`
}

// Options are what a person chooses.
type Options struct {
	Name string
	// Endpoint overrides the document's server: a host, or a URL.
	Endpoint string
	// Uses are the operations or tools agreed to; empty lists what is on
	// offer and declares nothing.
	Uses   []string
	Secret string
}

// OpenAPI reads an OpenAPI 3 document (JSON) into a REST integration.
func OpenAPI(body []byte, opts Options) (*Imported, error) {
	if len(body) > MaxDocument {
		return nil, fmt.Errorf("the document is over %d MiB", MaxDocument>>20)
	}
	var d document
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("this is not an OpenAPI document in JSON (YAML is read once converted to JSON): %w", err)
	}
	if d.Swagger != "" || !strings.HasPrefix(d.OpenAPI, "3.") {
		return nil, errors.New("this reads OpenAPI 3.0 and 3.1; convert a Swagger 2.0 document first")
	}
	out := &Imported{}
	in := agent.Integration{Kind: agent.IntegrationHTTP, Secret: opts.Secret}
	in.Name = opts.Name
	if in.Name == "" {
		in.Name = strings.ToLower(strings.Trim(reWord.ReplaceAllString(d.Info.Title, "-"), "-"))
	}
	in.Purpose = firstLine(d.Info.Title)
	if desc := firstLine(d.Info.Description); desc != "" {
		in.Purpose += ": " + desc
	}
	if len(in.Purpose) > 300 {
		in.Purpose = in.Purpose[:300]
	}

	server := opts.Endpoint
	if server == "" && len(d.Servers) > 0 {
		server = d.Servers[0].URL
	}
	if err := place(&in, server); err != nil {
		return nil, err
	}

	// How it authenticates.
	for _, req := range d.Security {
		for name := range req {
			s, ok := d.Components.SecuritySchemes[name]
			if !ok {
				continue
			}
			switch {
			case s.Type == "http" && strings.EqualFold(s.Scheme, "bearer"), s.Type == "oauth2", s.Type == "openIdConnect":
				in.Auth = "bearer"
			case s.Type == "apiKey" && s.In == "header":
				in.Auth = "header:" + s.Name
			case s.Type == "apiKey":
				out.Notes = append(out.Notes, fmt.Sprintf("the API key goes in the %s, which is not imported: a key in a %s ends up in logs", s.In, s.In))
			case s.Type == "http":
				out.Notes = append(out.Notes, fmt.Sprintf("%s authentication is not imported; a bearer token or a key in a header is", s.Scheme))
			}
		}
	}
	if in.Auth == "bearer" {
		in.Auth = ""
	}

	paths := make([]string, 0, len(d.Paths))
	for p := range d.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	taken := map[string]bool{}
	var all []agent.Operation
	for _, path := range paths {
		item := d.Paths[path]
		var shared []json.RawMessage
		if raw, ok := item["parameters"]; ok {
			_ = json.Unmarshal(raw, &shared)
		}
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			raw, ok := item[method]
			if !ok {
				continue
			}
			var op operation
			if err := json.Unmarshal(raw, &op); err != nil {
				out.Notes = append(out.Notes, fmt.Sprintf("%s %s could not be read: %v", strings.ToUpper(method), path, err))
				continue
			}
			o := agent.Operation{Name: opName(op.OperationID, method, path, taken), Method: strings.ToUpper(method), Path: path,
				Description: firstLine(nonEmpty(op.Summary, op.Description))}
			if len(o.Description) > 200 {
				o.Description = o.Description[:200]
			}
			seen := map[string]bool{}
			for _, praw := range append(append([]json.RawMessage(nil), op.Parameters...), shared...) {
				p, note := resolveParam(d, praw)
				if note != "" {
					out.Notes = append(out.Notes, o.Name+": "+note)
					continue
				}
				if seen[p.In+" "+p.Name] {
					continue
				}
				seen[p.In+" "+p.Name] = true
				switch p.In {
				case "path", "query":
					o.Params = append(o.Params, agent.OperationParam{Name: p.Name, In: p.In, Required: p.Required || p.In == "path",
						Type: primitive(p.Schema.Type), Description: firstLine(p.Description)})
				default:
					out.Notes = append(out.Notes, fmt.Sprintf("%s: the %s parameter %s is left out; Quilzo sets an operation's headers", o.Name, p.In, p.Name))
				}
			}
			if len(op.RequestBody) > 0 && o.Writes() {
				schema, note := bodySchema(d, op.RequestBody)
				if note != "" {
					out.Notes = append(out.Notes, o.Name+": "+note)
				}
				o.Body = schema
			}
			all = append(all, o)
			out.Available = append(out.Available, Offered{Name: o.Name, Method: o.Method, Path: path, Summary: o.Description, Writes: o.Writes()})
		}
	}
	if len(all) == 0 {
		return nil, errors.New("the document describes no operations")
	}
	if len(opts.Uses) == 0 {
		out.Integration = in
		return out, nil
	}
	byName := map[string]agent.Operation{}
	for _, op := range all {
		byName[op.Name] = op
	}
	for _, u := range opts.Uses {
		op, ok := byName[u]
		if !ok {
			return nil, fmt.Errorf("the document has no operation %q; quilzo integrations import lists them", u)
		}
		in.Operations = append(in.Operations, op)
		in.Uses = append(in.Uses, u)
		in.Writes = in.Writes || op.Writes()
	}
	if left := len(all) - len(in.Operations); left > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("%d other operations are not declared; import again naming them to add them", left))
	}
	if err := in.Validate(); err != nil {
		return nil, err
	}
	out.Integration = in
	return out, nil
}

// place sets an integration's host, port and base path from a URL or host.
func place(in *agent.Integration, server string) error {
	if server == "" {
		return errors.New("the document names no server; give one with --endpoint")
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not a server address; give one with --endpoint", server)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s is %s; Quilzo reaches an API over https only", server, u.Scheme)
	}
	if strings.Contains(u.Host, "{") {
		return fmt.Errorf("the server %s has variables; give the real one with --endpoint", server)
	}
	in.Endpoint = u.Hostname()
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("%s has no usable port", server)
		}
		in.Port = n
	}
	in.Path = strings.TrimSuffix(u.EscapedPath(), "/")
	return nil
}

const refDepth = 4

// resolveParam follows a local parameter reference.
func resolveParam(d document, raw json.RawMessage) (parameter, string) {
	var p parameter
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, "a parameter could not be read"
	}
	if p.Ref != "" {
		name, ok := strings.CutPrefix(p.Ref, "#/components/parameters/")
		if !ok {
			return p, fmt.Sprintf("the parameter %s is outside this document and is not fetched", p.Ref)
		}
		r, ok := d.Components.Parameters[name]
		if !ok {
			return p, fmt.Sprintf("the parameter %s is not in the document", p.Ref)
		}
		p = parameter{}
		if err := json.Unmarshal(r, &p); err != nil || p.Ref != "" {
			return p, fmt.Sprintf("the parameter %s could not be read", name)
		}
	}
	if p.Name == "" {
		return p, "a parameter has no name"
	}
	return p, ""
}

// bodySchema is a JSON request body's schema, with local references
// followed to a bounded depth and anything else left as an open object.
func bodySchema(d document, raw json.RawMessage) (json.RawMessage, string) {
	var rb struct {
		Ref     string `json:"$ref"`
		Content map[string]struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &rb); err != nil {
		return nil, "its body could not be read"
	}
	if rb.Ref != "" {
		name, ok := strings.CutPrefix(rb.Ref, "#/components/requestBodies/")
		if !ok || d.Components.RequestBodies[name] == nil {
			return json.RawMessage(`{"type":"object"}`), "its body is described elsewhere and is not fetched"
		}
		return bodySchema(d, d.Components.RequestBodies[name])
	}
	c, ok := rb.Content["application/json"]
	if !ok || len(c.Schema) == 0 {
		return json.RawMessage(`{"type":"object"}`), "its body is not JSON, or has no schema; it takes any object"
	}
	var v any
	if err := json.Unmarshal(c.Schema, &v); err != nil {
		return json.RawMessage(`{"type":"object"}`), "its body schema could not be read"
	}
	note := ""
	v = inline(d, v, 0, &note)
	b, _ := json.Marshal(v)
	if len(b) > 32<<10 {
		return json.RawMessage(`{"type":"object"}`), "its body schema is over 32 KiB; it takes any object"
	}
	return b, note
}

// inline replaces local schema references with what they name.
func inline(d document, v any, depth int, note *string) any {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			name, local := strings.CutPrefix(ref, "#/components/schemas/")
			if !local {
				*note = "its body refers outside this document, which is not fetched"
				return map[string]any{"type": "object"}
			}
			if depth >= refDepth || d.Components.Schemas[name] == nil {
				return map[string]any{"type": "object"}
			}
			var inner any
			if json.Unmarshal(d.Components.Schemas[name], &inner) != nil {
				return map[string]any{"type": "object"}
			}
			return inline(d, inner, depth+1, note)
		}
		for k, val := range x {
			x[k] = inline(d, val, depth, note)
		}
		return x
	case []any:
		for i := range x {
			x[i] = inline(d, x[i], depth, note)
		}
		return x
	}
	return v
}

func primitive(t string) string {
	switch t {
	case "integer", "number", "boolean":
		return t
	}
	return "string"
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// server is an MCP registry entry, as server.json gives it.
type server struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Remotes     []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"remotes"`
	Packages []struct {
		RegistryType string `json:"registryType"`
		Identifier   string `json:"identifier"`
	} `json:"packages"`
}

// IsServerJSON reports whether a document is an MCP registry entry.
func IsServerJSON(body []byte) bool {
	var probe struct {
		Remotes  json.RawMessage `json:"remotes"`
		Packages json.RawMessage `json:"packages"`
		OpenAPI  string          `json:"openapi"`
	}
	return json.Unmarshal(body, &probe) == nil && probe.OpenAPI == "" && (len(probe.Remotes) > 0 || len(probe.Packages) > 0)
}

// MCPServer reads an MCP registry server.json into an MCP server
// declaration. Only a remote it reaches over Streamable HTTP is declared; a
// package is something to run first.
func MCPServer(body []byte, o Options) (*Imported, error) {
	var s server
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("this is not an MCP registry server.json: %w", err)
	}
	out := &Imported{}
	in := agent.Integration{Kind: agent.IntegrationMCP, Secret: o.Secret, Purpose: firstLine(s.Description)}
	if in.Purpose == "" {
		in.Purpose = s.Name
	}
	in.Name = o.Name
	if in.Name == "" {
		last := s.Name
		if i := strings.LastIndexAny(last, "/."); i >= 0 {
			last = last[i+1:]
		}
		in.Name = strings.ToLower(strings.Trim(reWord.ReplaceAllString(last, "-"), "-"))
	}
	remote := o.Endpoint
	for _, r := range s.Remotes {
		if remote == "" && r.Type == "streamable-http" {
			remote = r.URL
		}
	}
	for _, p := range s.Packages {
		out.Notes = append(out.Notes, fmt.Sprintf("the %s package %s runs locally; run it, then declare where it answers with --endpoint",
			p.RegistryType, p.Identifier))
	}
	if remote == "" {
		return nil, errors.New("the server offers no Streamable HTTP remote; run one of its packages and give its address with --endpoint")
	}
	if err := place(&in, remote); err != nil {
		return nil, err
	}
	if in.Path == "" {
		in.Path = "/"
	}
	in.Uses = o.Uses
	out.Integration = in
	return out, nil
}
