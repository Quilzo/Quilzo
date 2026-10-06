// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package oauthas lets an AI app connect to Quilzo's agent interface on a
// person's behalf: an OAuth 2.1 authorization server for exactly one
// resource, the interface at /mcp.
//
// # Why Quilzo issues these itself
//
// An app such as an AI assistant connects to an MCP server by OAuth: it
// finds the authorization server from the resource's metadata (RFC 9728),
// sends the person there to agree, and gets a token bound to the resource
// (RFC 8707). The person who agrees is somebody Quilzo already knows — they
// sign in to the admin with a passkey, single sign-on or a token — so the
// consent belongs on the admin's own sign-in, under the same access policy,
// throttle, lockdown and shield as everything else there. A second identity
// system for this would be a second set of rules to keep the same.
//
// # What it does and does not do
//
//   - Authorization code with PKCE (S256 only) and refresh tokens, for
//     public clients; there are no client secrets anywhere.
//   - Clients identify themselves by a Client ID Metadata Document (an HTTPS
//     URL the app publishes), or are registered here by an administrator.
//     Dynamic client registration is not offered: the 2026-07-28 revision
//     deprecated it, and an endpoint that registers anybody who asks is the
//     part of OAuth most often abused.
//   - Which apps may connect is the organisation's decision: a list of the
//     hosts whose apps are allowed, empty until an administrator adds one.
//   - Access tokens last an hour and are bound to the interface: the admin,
//     the content API and the command line all refuse them
//     (auth.Token.Audience). Refresh tokens rotate on every use, and one used
//     twice ends the whole grant, because only a copy can be used twice.
//   - The token is never more than the person: the scopes offered are the
//     ones their role reaches, and every call is still checked against the
//     access policy as it stands when the call is made.
package oauthas

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Scope is one thing a person can let an app do.
type Scope struct {
	Name string
	Role auth.Role
	What string
}

// Scopes are the interface's scopes, smallest first. Each is a role: a
// token carries the highest one it was given, and an operation needing more
// is answered with a request for the scope that reaches it.
var Scopes = []Scope{
	{"mcp:read", auth.RoleReader, "read pages, records and reports"},
	{"mcp:write", auth.RoleAuthor, "change drafts (never the live site)"},
	{"mcp:publish", auth.RolePublisher, "publish"},
	{"mcp:admin", auth.RoleAdmin, "everything an administrator can do through the interface"},
}

// DefaultScope is what an app gets when it asks for nothing in particular.
const DefaultScope = "mcp:read"

// ScopeNames lists the scope names.
func ScopeNames() []string {
	out := make([]string, len(Scopes))
	for i, s := range Scopes {
		out[i] = s.Name
	}
	return out
}

func scopeByName(name string) (Scope, bool) {
	for _, s := range Scopes {
		if s.Name == name {
			return s, true
		}
	}
	return Scope{}, false
}

// RoleFor is the role a set of scopes carries: the highest of them.
func RoleFor(scopes []string) auth.Role {
	role := auth.RoleNone
	for _, n := range scopes {
		if s, ok := scopeByName(n); ok && s.Role.AtLeast(role) {
			role = s.Role
		}
	}
	return role
}

// ScopeFor is the scope that reaches a role.
func ScopeFor(role auth.Role) string {
	for _, s := range Scopes {
		if s.Role.AtLeast(role) {
			return s.Name
		}
	}
	return Scopes[len(Scopes)-1].Name
}

// Within are the scopes a role may give away.
func Within(role auth.Role) []string {
	var out []string
	for _, s := range Scopes {
		if role.AtLeast(s.Role) {
			out = append(out, s.Name)
		}
	}
	return out
}

// Config is the server as the deployment sets it up.
type Config struct {
	// Issuer is where the admin is reached, as an origin: https://host, or
	// http on loopback for trying it out.
	Issuer string
	// AccessTTL is how long an access token lasts; at most an hour.
	AccessTTL time.Duration
	// GrantTTL is how long a person's consent lasts before they are asked
	// again, however often the app refreshes.
	GrantTTL time.Duration
	// Hosts are the hosts whose apps may connect by their metadata
	// document. "*" allows any, which the organisation must choose to say.
	Hosts []string
}

// Limits.
const (
	MaxAccessTTL = time.Hour
	MaxGrantTTL  = 90 * 24 * time.Hour
	codeTTL      = time.Minute
	pendingTTL   = 10 * time.Minute
)

// Resource is the interface's address, which every token names.
func (c Config) Resource() string { return c.Issuer + "/mcp" }

// MetadataURL is where the resource's metadata is served (RFC 9728, with
// the resource's path inserted after the well-known prefix).
func (c Config) MetadataURL() string {
	return c.Issuer + "/.well-known/oauth-protected-resource/mcp"
}

func (c Config) accessTTL() time.Duration {
	if c.AccessTTL <= 0 || c.AccessTTL > MaxAccessTTL {
		return MaxAccessTTL
	}
	return c.AccessTTL
}

func (c Config) grantTTL() time.Duration {
	if c.GrantTTL <= 0 || c.GrantTTL > MaxGrantTTL {
		return 30 * 24 * time.Hour
	}
	return c.GrantTTL
}

// CheckIssuer checks the admin's address is one an OAuth server may have:
// https, or http on this machine; an origin with nothing after it.
func CheckIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("%q is not an address like https://admin.example.com", issuer)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(issuer, "/") {
		return fmt.Errorf("%q has more than a scheme and a host; the admin's address is an origin", issuer)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !Loopback(u.Hostname()) {
			return fmt.Errorf("%q is plain http on another machine; OAuth needs https except on this machine", issuer)
		}
	default:
		return fmt.Errorf("%q is neither https nor http", issuer)
	}
	if strings.ToLower(issuer) != issuer {
		return fmt.Errorf("%q has capitals; give it in lower case, as it is compared exactly", issuer)
	}
	return nil
}

// Loopback reports a host name that is this machine.
func Loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// AuthorizationMetadata is the server's RFC 8414 document.
func (c Config) AuthorizationMetadata(docs string) map[string]any {
	m := map[string]any{
		"issuer":                                         c.Issuer,
		"authorization_endpoint":                         c.Issuer + "/oauth/authorize",
		"token_endpoint":                                 c.Issuer + "/oauth/token",
		"revocation_endpoint":                            c.Issuer + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"revocation_endpoint_auth_methods_supported":     []string{"none"},
		"scopes_supported":                               ScopeNames(),
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
	}
	if docs != "" {
		m["service_documentation"] = docs
	}
	return m
}

// ResourceMetadata is the interface's RFC 9728 document.
func (c Config) ResourceMetadata(docs string) map[string]any {
	m := map[string]any{
		"resource":                 c.Resource(),
		"authorization_servers":    []string{c.Issuer},
		"scopes_supported":         []string{DefaultScope},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Quilzo agent interface",
	}
	if docs != "" {
		m["resource_documentation"] = docs
	}
	return m
}

// SameResource compares a resource indicator with the interface's address,
// accepting a capitalised scheme or host and a trailing slash, as clients
// are told servers should.
func (c Config) SameResource(given string) bool {
	u, err := url.Parse(strings.TrimSpace(given))
	if err != nil || u.Fragment != "" || u.User != nil || u.RawQuery != "" {
		return false
	}
	norm := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimSuffix(u.EscapedPath(), "/")
	return norm == c.Resource()
}

// HostAllowed reports whether apps published from a host may connect.
func (c Config) HostAllowed(host string) bool {
	host = strings.ToLower(host)
	for _, h := range c.Hosts {
		if h == "*" || strings.ToLower(h) == host {
			return true
		}
	}
	return false
}

func newSecret(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func hashOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// normScopes parses a scope parameter: known names, each once, in the
// order Scopes lists them.
func normScopes(raw string) ([]string, error) {
	seen := map[string]bool{}
	for _, f := range strings.Fields(raw) {
		if _, ok := scopeByName(f); !ok {
			return nil, fmt.Errorf("%q is not a scope here; the scopes are %s", f, strings.Join(ScopeNames(), ", "))
		}
		seen[f] = true
	}
	var out []string
	for _, s := range Scopes {
		if seen[s.Name] {
			out = append(out, s.Name)
		}
	}
	return out, nil
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
