package agent

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Integrations: reaching other people's systems, without carrying their code.
//
// # The rule this does not break
//
// "No third-party dependencies" is about the `require` block in go.mod — code
// compiled into this binary, whose release process becomes part of ours. It has
// never meant "does not talk to other systems", and it cannot: this program
// already speaks to any OIDC provider, any RFC 3161 timestamp authority, any
// webhook receiver, any model endpoint and the Bitcoin network, all written
// against the protocol using the standard library.
//
// So integrations are not an exception to the rule. Vendoring an SDK to get one
// would be.
//
// # Why declarations rather than a connector for each service
//
// Writing a client per service does not scale past a handful and is how a CMS
// acquires forty half-maintained integrations. Three shapes cover nearly
// everything, none of them needs a dependency, and all three are declared as
// data an operator can read:
//
//	mcp      an MCP server. There were about 18,850 in the official registry
//	         by July 2026, one for most SaaS a customer will name. The protocol
//	         is JSON-RPC, which is encoding/json and an io.Reader.
//	http     a REST endpoint described declaratively, for the long tail that
//	         has no MCP server.
//	process  a local program speaking the extension protocol, for what is left.
//
// The measured state of that ecosystem is also why none of this is trusted by
// default: of the remote servers surveyed in July 2026, 17.2% were simply dead,
// and the security literature's name for the live risk is tool poisoning — a
// server that adds or redefines a tool after you decided to trust it.
//
// # Off unless somebody turned it on
//
// Every integration is disabled until an operator enables it, per install. A
// customer who wants none carries none, and the attack surface of the feature
// they did not ask for is not theirs. That is what makes this optional in the
// sense that matters: not a build flag, but a default of nothing.

// IntegrationKind is how an integration is reached.
type IntegrationKind string

const (
	// IntegrationMCP is a Model Context Protocol server.
	IntegrationMCP IntegrationKind = "mcp"
	// IntegrationHTTP is a declaratively described REST endpoint.
	IntegrationHTTP IntegrationKind = "http"
	// IntegrationProcess is a local program speaking the extension protocol.
	IntegrationProcess IntegrationKind = "process"
)

// IntegrationKinds in the order they should be preferred.
//
// Ordered by how much of somebody else's judgement you are trusting: an MCP
// server you call over the network cannot read this store's files; a local
// process can read anything the account running it can.
var IntegrationKinds = []IntegrationKind{
	IntegrationMCP, IntegrationHTTP, IntegrationProcess,
}

func (k IntegrationKind) Valid() bool {
	for _, v := range IntegrationKinds {
		if v == k {
			return true
		}
	}
	return false
}

// reDigest is a sha256 hex digest, the way an object id is checked.
var reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Integration is one external system this install may reach.
type Integration struct {
	Name string          `json:"name"`
	Kind IntegrationKind `json:"kind"`

	// Enabled is false until an operator says otherwise. The zero value of a
	// struct somebody pasted from an example is therefore "off", which is the
	// direction that fails safe.
	Enabled bool `json:"enabled"`

	// Purpose is why this install reaches it, for the person reviewing rather
	// than for the machine.
	Purpose string `json:"purpose"`

	// Endpoint is the host for mcp and http kinds. Exactly one hostname, no
	// scheme, no path, no wildcard — the same rule Tool.Host follows, and for
	// the same reason.
	Endpoint string `json:"endpoint,omitempty"`

	// Command is the program for the process kind.
	Command string `json:"command,omitempty"`

	// Digest pins what is executed or loaded locally. Required for the process
	// kind: a command resolved from PATH at run time is whatever was on PATH
	// at run time, which is a supply chain with no record of what was in it.
	Digest string `json:"digest,omitempty"`

	// Uses is the allow-list of tool names this install may call on the far
	// side. Never "everything the server offers".
	//
	// This is the control that answers tool poisoning. An MCP server can add a
	// tool, or redefine one, after the day somebody decided to trust it — and
	// a client that calls whatever is advertised has delegated its capability
	// list to a third party's next release.
	Uses []string `json:"uses"`

	// Writes marks an integration that changes something on the far side, so
	// the reviewer does not have to infer it from the tool names.
	Writes bool `json:"writes,omitempty"`

	// Secret names the credential in the vault. Never the value: this is
	// stored in a content-addressed object, and an object cannot be deleted.
	Secret string `json:"secret,omitempty"`
}

// Validate refuses an integration that cannot mean what it appears to.
func (in *Integration) Validate() error {
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("an integration needs a name, so a log entry can say which one acted")
	}
	if !in.Kind.Valid() {
		return fmt.Errorf("%q is not an integration kind; use %s",
			in.Kind, joinKinds())
	}
	if strings.TrimSpace(in.Purpose) == "" {
		return fmt.Errorf(
			"%s has no stated purpose. An integration nobody can review "+
				"against an intention is one nobody reviews", in.Name)
	}

	switch in.Kind {
	case IntegrationMCP, IntegrationHTTP:
		if err := checkHost(in.Name, in.Endpoint); err != nil {
			return err
		}
		if in.Command != "" {
			return fmt.Errorf(
				"%s is a %s integration and names a command; it reaches a host",
				in.Name, in.Kind)
		}
	case IntegrationProcess:
		if strings.TrimSpace(in.Command) == "" {
			return fmt.Errorf("%s runs a process and names no command", in.Name)
		}
		if !strings.HasPrefix(in.Command, "/") {
			// Resolved from PATH means whatever was on PATH, which is a
			// different program on a different machine and no record of
			// which.
			return fmt.Errorf(
				"%s runs %q, which would be resolved from PATH. Give an "+
					"absolute path: a command found on PATH is whichever "+
					"program was there at the time, and nothing records which",
				in.Name, in.Command)
		}
		if !reDigest.MatchString(in.Digest) {
			return fmt.Errorf(
				"%s runs a local program and is not pinned. Give a "+
					"sha256:… digest — executing whatever is at that path "+
					"today is the supply chain this project refuses at build "+
					"time and would be accepting at run time", in.Name)
		}
		if in.Endpoint != "" {
			return fmt.Errorf(
				"%s is a process integration and names an endpoint", in.Name)
		}
	}

	if len(in.Uses) == 0 {
		return fmt.Errorf(
			"%s names no tools to use. An integration that may call anything "+
				"the far side offers has handed its capability list to "+
				"somebody else's next release", in.Name)
	}
	seen := map[string]bool{}
	for _, u := range in.Uses {
		if strings.TrimSpace(u) == "" {
			return fmt.Errorf("%s lists an empty tool name", in.Name)
		}
		if u == "*" {
			return fmt.Errorf(
				"%s asks for \"*\". There is no wildcard here: name the tools, "+
					"and adding one later is a change somebody makes on purpose",
				in.Name)
		}
		if seen[u] {
			return fmt.Errorf("%s lists %q twice", in.Name, u)
		}
		seen[u] = true
	}
	return nil
}

// checkHost applies the one-exact-hostname rule.
func checkHost(who, host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return fmt.Errorf("%s names no endpoint", who)
	}
	if strings.ContainsAny(h, "*?") {
		return fmt.Errorf(
			"%s reaches %q. A wildcard host is a promise about DNS that "+
				"whoever registers a subdomain gets to break", who, h)
	}
	if strings.Contains(h, "/") || strings.Contains(h, ":") {
		return fmt.Errorf(
			"%s should name a host, not a URL: %q", who, h)
	}
	return nil
}

func joinKinds() string {
	parts := make([]string, len(IntegrationKinds))
	for i, k := range IntegrationKinds {
		parts[i] = string(k)
	}
	return strings.Join(parts, ", ")
}

// Integrations is what an install has declared.
type Integrations struct {
	// AllowProcess gates the process kind for the whole install.
	//
	// Separate from the per-integration Enabled flag, and deliberately
	// awkward: a process integration is arbitrary code execution beside the
	// content store, which is the terminal step in the kill chain this whole
	// program is arranged to remove. An operator turning it on should have to
	// say so once, at the top, rather than discovering they enabled it by
	// enabling something that happened to be one.
	AllowProcess bool `json:"allow_process"`

	Declared []Integration `json:"declared"`
}

// Enabled returns the integrations an agent may actually reach.
//
// The filter is the product: everything is off until somebody turns it on, and
// a process integration is off until somebody turned that on as well.
func (s Integrations) Enabled() []Integration {
	var out []Integration
	for _, in := range s.Declared {
		if !in.Enabled {
			continue
		}
		if in.Kind == IntegrationProcess && !s.AllowProcess {
			continue
		}
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Validate checks every declaration, enabled or not.
//
// Not only the enabled ones: a declaration that does not validate is a landmine
// for whoever enables it later, and "it was fine until I turned it on" is the
// report nobody can act on.
func (s Integrations) Validate() error {
	seen := map[string]bool{}
	for i := range s.Declared {
		in := &s.Declared[i]
		if err := in.Validate(); err != nil {
			return err
		}
		if seen[in.Name] {
			return fmt.Errorf("two integrations are called %q", in.Name)
		}
		seen[in.Name] = true
	}
	return nil
}

// Resolve returns the enabled integration providing a named tool, and whether
// this install may call it.
//
// The lookup is by tool name across enabled integrations, because that is the
// question a runner has: something asked to call "create_issue" — may it, and
// through what. Two integrations offering the same tool name is refused rather
// than resolved by order, since order is not something anybody reviewed.
func (s Integrations) Resolve(tool string) (Integration, error) {
	var found []Integration
	for _, in := range s.Enabled() {
		for _, u := range in.Uses {
			if u == tool {
				found = append(found, in)
				break
			}
		}
	}
	switch len(found) {
	case 0:
		return Integration{}, fmt.Errorf(
			"no enabled integration offers %q", tool)
	case 1:
		return found[0], nil
	default:
		names := make([]string, len(found))
		for i, in := range found {
			names[i] = in.Name
		}
		return Integration{}, fmt.Errorf(
			"%s all offer %q, and which one runs would be decided by the "+
				"order they happen to be listed in. Rename the tool or "+
				"disable one", strings.Join(names, ", "), tool)
	}
}

// Hosts returns the hostnames the enabled integrations reach, for building an
// agent's tool allow-list from what the install actually has.
func (s Integrations) Hosts() []string {
	var out []string
	for _, in := range s.Enabled() {
		if in.Endpoint != "" {
			out = append(out, in.Endpoint)
		}
	}
	sort.Strings(out)
	return out
}
