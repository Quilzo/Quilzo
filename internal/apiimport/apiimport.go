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
	"github.com/quilzo/quilzo/internal/plaintext"
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
// otherwise its method and path. next is, for a name taken, the number to
// try first after it: every one below it is taken. Counting up from 2
// again for each, 4,000 operations with one operationId took four and a
// half seconds, and the 8 MiB a document may be would have taken hours.
func opName(id, method, path string, taken map[string]bool, next map[string]int) string {
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
	base := n
	for i := max(2, next[base]); taken[n]; i++ {
		n = fmt.Sprintf("%s_%d", base, i)
		next[base] = i + 1
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
	taken, next := map[string]bool{}, map[string]int{}
	follow := &refs{d: d, params: map[string]decoded[parameter]{}, bodies: map[bodyAt]bodyResult{},
		schemas: map[string]decoded[any]{}}
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
			o := agent.Operation{Name: opName(op.OperationID, method, path, taken, next), Method: strings.ToUpper(method), Path: path,
				Description: firstLine(nonEmpty(op.Summary, op.Description))}
			if len(o.Description) > 200 {
				o.Description = o.Description[:200]
			}
			seen := map[string]bool{}
			for _, praw := range append(append([]json.RawMessage(nil), op.Parameters...), shared...) {
				p, note := follow.param(praw)
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
				schema, note := follow.bodySchema(op.RequestBody, 0)
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

// maxBody bounds a request body's schema, as JSON, once its references are
// followed.
const maxBody = 32 << 10

// maxBodies bounds the body schemas one document makes, together: room for
// five hundred of the largest, more than any API describes. Each is bounded
// by maxBody, but a reference lets a few bytes of operation name a large
// schema, and 1.1 MB of operations that each named one of 20 KiB took
// nineteen seconds and kept 380 MB, so 8 MiB would have kept three
// gigabytes.
const maxBodies = 16 << 20

// refs follows one document's local references. A component is decoded the
// first time a reference names it and kept, and a request body's schema is
// made once for all the operations that name it: read afresh at every
// reference, a 2 MB schema named by two hundred properties cost twenty
// seconds and 2.9 GB, and a parameter or a body named by every operation was
// read again for each one, all within the 8 MiB a document may be.
type refs struct {
	d       document
	params  map[string]decoded[parameter]
	bodies  map[bodyAt]bodyResult
	schemas map[string]decoded[any]
	// made is how much body schema the document has made, as expansion
	// counts it.
	made int
}

// decoded is a component as it was decoded, and whether it could be.
type decoded[T any] struct {
	v  T
	ok bool
}

// decode is the component of that name, decoded the first time it is asked
// for. What it gives is shared, and never changed by whoever asked.
func decode[T any](kept map[string]decoded[T], name string, raw json.RawMessage) (T, bool) {
	c, seen := kept[name]
	if !seen {
		c.ok = raw != nil && json.Unmarshal(raw, &c.v) == nil
		kept[name] = c
	}
	return c.v, c.ok
}

// bodyAt is a request body named at a depth of references, which decides
// whether it is followed further.
type bodyAt struct {
	name  string
	depth int
}

type bodyResult struct {
	schema json.RawMessage
	note   string
}

// param follows a local parameter reference.
func (r *refs) param(raw json.RawMessage) (parameter, string) {
	var p parameter
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, "a parameter could not be read"
	}
	if p.Ref != "" {
		name, ok := strings.CutPrefix(p.Ref, "#/components/parameters/")
		if !ok {
			return p, fmt.Sprintf("the parameter %s is outside this document and is not fetched", p.Ref)
		}
		named, ok := r.d.Components.Parameters[name]
		if !ok {
			return p, fmt.Sprintf("the parameter %s is not in the document", p.Ref)
		}
		if p, ok = decode(r.params, name, named); !ok || p.Ref != "" {
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
// depth counts the request bodies followed to reach this one, so that one
// naming itself, or another that names it back, ends as an open object: it
// was followed until the stack ran out, a fatal error that no recover
// catches, and a 263-byte document ended the whole server.
func (r *refs) bodySchema(raw json.RawMessage, depth int) (json.RawMessage, string) {
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
		if !ok || r.d.Components.RequestBodies[name] == nil {
			return json.RawMessage(`{"type":"object"}`), "its body is described elsewhere and is not fetched"
		}
		if depth >= refDepth {
			return json.RawMessage(`{"type":"object"}`), "its body refers to itself, or through too many others; it takes any object"
		}
		at := bodyAt{name, depth + 1}
		got, seen := r.bodies[at]
		if !seen {
			got.schema, got.note = r.bodySchema(r.d.Components.RequestBodies[name], depth+1)
			r.bodies[at] = got
		}
		return got.schema, got.note
	}
	c, ok := rb.Content["application/json"]
	if !ok || len(c.Schema) == 0 {
		return json.RawMessage(`{"type":"object"}`), "its body is not JSON, or has no schema; it takes any object"
	}
	var v any
	if err := json.Unmarshal(c.Schema, &v); err != nil {
		return json.RawMessage(`{"type":"object"}`), "its body schema could not be read"
	}
	if r.made > maxBodies {
		return json.RawMessage(`{"type":"object"}`), "the document's body schemas are over 16 MiB together; this one takes any object"
	}
	e := expansion{refs: r}
	v = e.inline(v, 0)
	r.made += e.size
	if e.size > maxBody {
		return json.RawMessage(`{"type":"object"}`), "its body schema is over 32 KiB; it takes any object"
	}
	b, _ := json.Marshal(v)
	if len(b) > maxBody {
		return json.RawMessage(`{"type":"object"}`), "its body schema is over 32 KiB; it takes any object"
	}
	return b, e.note
}

// expansion is one body schema having its references followed. size counts
// no more bytes than what has been made so far will take as JSON, so once it
// is over maxBody the schema is known to be too, and the expansion stops
// there rather than once the whole schema is made: a reference is expanded
// where it is used, so a schema whose properties each name another, whose
// properties each name another, grows as the power of its fan-out, and 8.6 KB
// of document reached 1.6 GB of memory before its size was looked at.
type expansion struct {
	*refs
	size int
	note string
}

// inline is a schema with local schema references replaced by what they
// name. It is made afresh, never changing what it was made from, which may
// be a component other references share.
func (e *expansion) inline(v any, depth int) any {
	if e.size > maxBody {
		return nil
	}
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			name, local := strings.CutPrefix(ref, "#/components/schemas/")
			if !local {
				e.note = "its body refers outside this document, which is not fetched"
				return e.open()
			}
			if depth >= refDepth {
				return e.open()
			}
			inner, ok := decode(e.schemas, name, e.d.Components.Schemas[name])
			if !ok {
				return e.open()
			}
			return e.inline(inner, depth+1)
		}
		e.size += len(`{}`)
		out := make(map[string]any, e.room(len(x), len(`"":0`)))
		for k, val := range x {
			if e.size > maxBody {
				break
			}
			e.size += len(k) + len(`"":`)
			out[k] = e.inline(val, depth)
		}
		return out
	case []any:
		e.size += len(`[]`)
		out := make([]any, 0, e.room(len(x), len(`0`)))
		for _, val := range x {
			if e.size > maxBody {
				break
			}
			out = append(out, e.inline(val, depth))
		}
		return out
	case string:
		e.size += len(x) + len(`""`)
	default:
		// A number, true, false or null is a byte at the least.
		e.size++
	}
	return v
}

// room is how many of n elements, each least bytes at the least, a copy
// makes room for: no more than fit in what is left of maxBody. Room made
// for all of a schema's elements was made at every reference to it,
// however few were then copied, and a list of two million named by six
// hundred operations cost thirty-seven seconds and 16 GB.
func (e *expansion) room(n, least int) int {
	return min(n, max(0, maxBody-e.size)/least+1)
}

// open is the schema of any object, for what is not followed.
func (e *expansion) open() any {
	e.size += len(`{"type":"object"}`)
	return map[string]any{"type": "object"}
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

// IsAgentCard reports whether a document is an Agent2Agent agent card.
func IsAgentCard(body []byte) bool {
	var probe struct {
		URL     string          `json:"url"`
		Skills  json.RawMessage `json:"skills"`
		OpenAPI string          `json:"openapi"`
	}
	return json.Unmarshal(body, &probe) == nil && probe.OpenAPI == "" && probe.URL != "" && len(probe.Skills) > 0
}

// AgentCard reads an A2A agent card into a declaration of that agent: its
// host from the card's own service address, each skill on offer.
func AgentCard(body []byte, o Options) (*Imported, error) {
	var c struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		URL         string `json:"url"`
		Skills      []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"skills"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("this is not an agent card: %w", err)
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("the card's address %q is not https", clip(c.URL, 120))
	}
	in := agent.Integration{Kind: agent.IntegrationA2A, Secret: o.Secret, Endpoint: strings.ToLower(u.Hostname()),
		Purpose: firstLine(c.Description)}
	if in.Purpose == "" {
		in.Purpose = "ask " + c.Name
	}
	in.Name = o.Name
	if in.Name == "" {
		in.Name = strings.ToLower(strings.Trim(reWord.ReplaceAllString(c.Name, "-"), "-"))
	}
	if o.Endpoint != "" && !strings.EqualFold(o.Endpoint, in.Endpoint) {
		return nil, fmt.Errorf("the card is for %s, not %s", in.Endpoint, o.Endpoint)
	}
	out := &Imported{}
	for _, s := range c.Skills {
		if s.ID != "" {
			out.Available = append(out.Available, Offered{Name: s.ID, Summary: clip(s.Name+": "+s.Description, 100), Writes: true})
		}
	}
	out.Notes = append(out.Notes, "its card is read again from https://"+in.Endpoint+"/.well-known/agent-card.json each time; "+
		"pin its skills once you have read them")
	in.Uses = o.Uses
	in.Writes = true
	out.Integration = in
	return out, nil
}

// clip bounds what a card says, at a character boundary.
func clip(s string, n int) string { return plaintext.Clip(s, n, "") }
