// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

// An agent's reach onto the web without a browser: reading an address
// (web_fetch) and asking a search provider (web_search).
//
// Reading is a GET, over https, through the client that refuses private
// addresses, of hosts the declaration names, or of any public host when it
// says so in as many words ("any": true). Searching asks the provider the
// operator configured (agents.search). What either brings back is
// somebody else's words, so the run is tainted by it; and the address and
// the query are the model's words, carried to a host, so once a run holds
// something private the breaker holds them for a person (browserSends).

// WebCapabilities are the web's actions, each a capability.
var WebCapabilities = []string{"web_fetch", "web_search"}

// IsWeb reports whether a capability is one of the web's.
func IsWeb(op string) bool { return slices.Contains(WebCapabilities, op) }

// Web is what a declaration says about its reach onto the web.
type Web struct {
	// Fetch are the hosts web_fetch may read.
	Fetch []string `json:"fetch,omitempty"`
	// Any lets web_fetch read any public host: the web, said in as many
	// words, since a list of every host is not one anybody can read.
	Any bool `json:"any,omitempty"`
}

// Reads reports whether web_fetch may read host.
func (w *Web) Reads(host string) bool {
	if w == nil {
		return false
	}
	return w.Any || slices.Contains(w.Fetch, strings.ToLower(host))
}

// validateWeb refuses a web declaration that cannot mean what it appears
// to.
func (m *Manifest) validateWeb() error {
	fetches := slices.Contains(m.Capabilities, "web_fetch")
	w := m.Web
	if !slices.ContainsFunc(m.Capabilities, IsWeb) {
		if w != nil && (w.Any || len(w.Fetch) > 0) {
			return fmt.Errorf("%s declares the web and holds none of its capabilities (%s)",
				m.Name, strings.Join(WebCapabilities, ", "))
		}
		return nil
	}
	if m.Program != nil {
		return fmt.Errorf("%s has a program and holds the web's capabilities; a program reaches the web "+
			"through its proxy, and these are for agents Quilzo drives", m.Name)
	}
	if fetches && (w == nil || (!w.Any && len(w.Fetch) == 0)) {
		return fmt.Errorf(`%s holds web_fetch and names nothing it may read: declare "web": {"fetch": [...]}, `+
			`or {"any": true} for any public host`, m.Name)
	}
	if w == nil {
		return nil
	}
	if !fetches && (w.Any || len(w.Fetch) > 0) {
		return fmt.Errorf("%s declares hosts to read and does not hold web_fetch", m.Name)
	}
	if w.Any && len(w.Fetch) > 0 {
		return fmt.Errorf(`%s's web says both "any" and a list of hosts; say one`, m.Name)
	}
	if len(w.Fetch) > MaxBrowserHosts {
		return fmt.Errorf("%s's web names %d hosts; at most %d, or \"any\": true", m.Name, len(w.Fetch), MaxBrowserHosts)
	}
	seen := map[string]bool{}
	for _, h := range w.Fetch {
		switch {
		case net.ParseIP(h) != nil:
			return fmt.Errorf("%s's web names %s, which is an address: name the host", m.Name, h)
		case h != strings.ToLower(h) || !reBrowserHost.MatchString(h):
			return fmt.Errorf("%s's web names %q, which is not one host name: lower case, "+
				"no scheme, port, path or wildcard", m.Name, h)
		case seen[h]:
			return fmt.Errorf("%s's web names %s twice", m.Name, h)
		}
		seen[h] = true
	}
	return nil
}

// narrowWeb is the narrower of two web declarations: the hosts both may
// read, and any public host only when both say so.
func narrowWeb(m, by *Web) *Web {
	if m == nil || by == nil {
		return nil
	}
	out := &Web{Any: m.Any && by.Any}
	switch {
	case m.Any && !by.Any:
		out.Fetch = slices.Clone(by.Fetch)
	case by.Any && !m.Any:
		out.Fetch = slices.Clone(m.Fetch)
	default:
		for _, h := range m.Fetch {
			if slices.Contains(by.Fetch, h) {
				out.Fetch = append(out.Fetch, h)
			}
		}
	}
	return out
}

// webSends is where a web action carries the model's words: the address it
// reads, whose path and query are the model's, or the query it searches.
func webSends(a Action) (string, bool) {
	switch a.Op {
	case "web_fetch":
		raw, _ := a.Input["url"].(string)
		if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname()), true
		}
		return "the address it reads", true
	case "web_search":
		return "the search provider", true
	}
	return "", false
}
