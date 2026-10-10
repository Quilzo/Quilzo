// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// An agent's browser, as its declaration says it may use one.
//
// The browser is Chromium in the agent's box, driven by Quilzo
// (internal/browser); what an agent may do with it is these capabilities,
// each one step of its run. What it may reach is two lists of hosts: the
// ones it may read, and the ones it may also send to. Every request a page
// makes is held to them as it is made, so a page cannot carry what it read
// to a host nobody named, and a form cannot be sent to a host only meant to
// be read.

// BrowserCapabilities are the browser's actions, each a capability.
var BrowserCapabilities = []string{
	"browser_open", "browser_read", "browser_look", "browser_type",
	"browser_choose", "browser_click", "browser_sign_in",
}

// IsBrowser reports whether a capability is one of the browser's.
func IsBrowser(op string) bool {
	for _, c := range BrowserCapabilities {
		if c == op {
			return true
		}
	}
	return false
}

// Browser is what a declaration says about its browser.
type Browser struct {
	// Read are the hosts it may open and read: only GET reaches them.
	Read []string `json:"read,omitempty"`
	// Write are the hosts it may also send forms and data to.
	Write []string `json:"write,omitempty"`
	// Credentials it may sign in with, each typed only into its host.
	Credentials []BrowserCredential `json:"credentials,omitempty"`
	// Pictures allows browser_look: a screenshot, for a model that reads
	// pictures. Off unless declared, since the outline is cheaper and never
	// carries a picture of somebody's record to a model.
	Pictures bool `json:"pictures,omitempty"`
}

// BrowserCredential is a sealed secret and the one host it may be typed into.
type BrowserCredential struct {
	Secret string `json:"secret"`
	Host   string `json:"host"`
}

var reBrowserHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$`)
var reBrowserSecret = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// MaxBrowserHosts bounds each list. A list longer than this is the web,
// and an agent that may reach the web is one nobody declared.
const MaxBrowserHosts = 32

// Writes reports whether the browser may send to host.
func (b *Browser) Writes(host string) bool {
	if b == nil {
		return false
	}
	return contains(b.Write, strings.ToLower(host))
}

// Reads reports whether the browser may read host.
func (b *Browser) Reads(host string) bool {
	if b == nil {
		return false
	}
	h := strings.ToLower(host)
	return contains(b.Read, h) || contains(b.Write, h)
}

// CredentialFor is the declared credential named secret.
func (b *Browser) CredentialFor(secret string) (BrowserCredential, bool) {
	if b == nil {
		return BrowserCredential{}, false
	}
	for _, c := range b.Credentials {
		if c.Secret == secret {
			return c, true
		}
	}
	return BrowserCredential{}, false
}

// validateBrowser refuses a browser declaration that cannot mean what it
// appears to.
func (m *Manifest) validateBrowser() error {
	uses := map[string]bool{}
	for _, c := range m.Capabilities {
		if IsBrowser(c) {
			uses[c] = true
		}
	}
	b := m.Browser
	if len(uses) == 0 {
		if b != nil && (len(b.Read) > 0 || len(b.Write) > 0 || len(b.Credentials) > 0) {
			return fmt.Errorf("%s declares a browser and holds none of its capabilities (%s)",
				m.Name, strings.Join(BrowserCapabilities, ", "))
		}
		return nil
	}
	if b == nil || len(b.Read)+len(b.Write) == 0 {
		return fmt.Errorf("%s holds the browser's capabilities and names no host it may reach: "+
			`declare "browser": {"read": [...], "write": [...]}`, m.Name)
	}
	if m.Program != nil {
		return fmt.Errorf("%s has a program and holds the browser's capabilities; a program "+
			"reaches the web through its proxy, and the browser is for agents Quilzo drives", m.Name)
	}
	for list, hosts := range map[string][]string{"read": b.Read, "write": b.Write} {
		if len(hosts) > MaxBrowserHosts {
			return fmt.Errorf("%s's browser may %s %d hosts; at most %d", m.Name, list, len(hosts), MaxBrowserHosts)
		}
		seen := map[string]bool{}
		for _, h := range hosts {
			switch {
			case net.ParseIP(h) != nil:
				return fmt.Errorf("%s's browser names %s, which is an address: name the host, "+
					"since a certificate is for a name and the box never reaches an address inside the network", m.Name, h)
			case h != strings.ToLower(h) || !reBrowserHost.MatchString(h):
				return fmt.Errorf("%s's browser names %q, which is not one host name: lower case, "+
					"no scheme, port, path or wildcard", m.Name, h)
			case seen[h]:
				return fmt.Errorf("%s's browser names %s twice", m.Name, h)
			}
			seen[h] = true
		}
	}
	for _, c := range b.Credentials {
		switch {
		case !reBrowserSecret.MatchString(c.Secret):
			return fmt.Errorf("%s's browser names the credential %q, which is not a credential's name", m.Name, c.Secret)
		case !contains(b.Write, c.Host):
			return fmt.Errorf("%s's browser signs in to %s with %s, which is not a host it may write to: "+
				"signing in sends a form", m.Name, c.Host, c.Secret)
		}
	}
	if uses["browser_look"] && !b.Pictures {
		return fmt.Errorf(`%s holds browser_look and its browser does not allow pictures ("pictures": true)`, m.Name)
	}
	if uses["browser_sign_in"] && len(b.Credentials) == 0 {
		return fmt.Errorf("%s holds browser_sign_in and declares no credential to sign in with", m.Name)
	}
	return nil
}

// narrowBrowser is the narrower of two browser declarations: the hosts
// both may reach, written to only where both may write, the credentials
// both hold, and pictures only when both allow them.
func narrowBrowser(m, by *Browser) *Browser {
	if m == nil || by == nil {
		return nil
	}
	out := &Browser{Pictures: m.Pictures && by.Pictures}
	for _, h := range by.Write {
		if m.Writes(h) {
			out.Write = append(out.Write, h)
		}
	}
	for _, h := range append(append([]string(nil), by.Read...), by.Write...) {
		if m.Reads(h) && !contains(out.Write, h) && !contains(out.Read, h) {
			out.Read = append(out.Read, h)
		}
	}
	for _, c := range by.Credentials {
		if mc, ok := m.CredentialFor(c.Secret); ok && mc.Host == c.Host && contains(out.Write, c.Host) {
			out.Credentials = append(out.Credentials, c)
		}
	}
	sort.Strings(out.Read)
	sort.Strings(out.Write)
	return out
}

// FromWeb is a run that read a web page in its browser.
const FromWeb SourceKind = "web"

// ReadWeb records that the run read a page from host, at where: somebody
// else's words, so the run is tainted from here, as reading stored content
// taints it.
func (s *Session) ReadWeb(host, where string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tainted = true
	s.note(FromWeb, host, where)
}

// browserSends is where a browser action would carry words the model chose:
// an address it opens, whose path and query are the model's, or text it
// types into a page, which the page may send wherever its rule allows.
// Reading, choosing from a page's own list and pressing what the page shows
// carry nothing of the model's, and a form a click submits holds only what
// was typed into it, which was asked about as it was typed.
func browserSends(a Action) (string, bool) {
	switch a.Op {
	case "browser_open":
		raw, _ := a.Input["url"].(string)
		if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname()), true
		}
		return "the address it opens", true
	case "browser_type":
		return "the page open in its browser", true
	}
	return "", false
}
