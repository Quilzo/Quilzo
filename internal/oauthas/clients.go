// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package oauthas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Client is an app that may ask a person for access.
type Client struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"client_name"`
	URI          string   `json:"client_uri,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	// Registered marks one an administrator added here, as against one
	// that described itself in a metadata document.
	Registered bool      `json:"registered,omitempty"`
	AddedBy    string    `json:"added_by,omitempty"`
	Added      time.Time `json:"added,omitzero"`
}

// Host is the host the client's identity is published from: for a
// metadata document, its URL's; for a registered client, none.
func (c Client) Host() string {
	if c.Registered {
		return ""
	}
	if u, err := url.Parse(c.ID); err == nil {
		return u.Host
	}
	return ""
}

// The limits on a metadata document. The draft recommends reading at most
// five kilobytes; a client's name and a few addresses need far less.
const (
	maxDocument    = 5 << 10
	maxRedirects   = 10
	maxName        = 100
	maxURI         = 2000
	cacheFloor     = 5 * time.Minute
	cacheCeiling   = 24 * time.Hour
	maxCachedApps  = 1000
	registeredPref = "qzc_"
)

// IsMetadataURL reports whether a client_id is a metadata document's
// address rather than an id registered here.
func IsMetadataURL(id string) bool { return strings.HasPrefix(id, "https://") }

// CheckMetadataURL checks a client_id is an address a metadata document may
// have: https, a path, and nothing that parsers read differently.
func CheckMetadataURL(id string) (*url.URL, error) {
	if len(id) > maxURI || !utf8.ValidString(id) {
		return nil, errors.New("the client_id is not a usable address")
	}
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("a client_id address is https with a host")
	}
	if u.User != nil {
		return nil, errors.New("a client_id address carries no user name or password")
	}
	if u.Fragment != "" || strings.Contains(id, "#") {
		return nil, errors.New("a client_id address has no fragment")
	}
	if u.RawQuery != "" || strings.Contains(id, "?") {
		return nil, errors.New("a client_id address has no query")
	}
	if u.Path == "" || u.Path == "/" {
		return nil, errors.New("a client_id address has a path")
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." || strings.EqualFold(seg, "%2e") || strings.EqualFold(seg, "%2e%2e") {
			return nil, errors.New("a client_id address has no . or .. segments")
		}
	}
	if u.String() != id {
		return nil, errors.New("the client_id address is not written in its plain form")
	}
	return u, nil
}

// document is a Client ID Metadata Document as read.
type document struct {
	ClientID                string          `json:"client_id"`
	ClientName              string          `json:"client_name"`
	ClientURI               string          `json:"client_uri"`
	RedirectURIs            []string        `json:"redirect_uris"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	ClientSecret            json.RawMessage `json:"client_secret"`
	ClientSecretExpiresAt   json.RawMessage `json:"client_secret_expires_at"`
	JWKS                    json.RawMessage `json:"jwks"`
	JWKSURI                 string          `json:"jwks_uri"`
}

// ParseDocument checks a metadata document fetched from id.
func ParseDocument(id string, body []byte) (Client, error) {
	if len(body) > maxDocument {
		return Client{}, fmt.Errorf("the metadata document is more than %d bytes", maxDocument)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var d document
	if err := dec.Decode(&d); err != nil || dec.More() {
		return Client{}, errors.New("the metadata document is not one JSON object")
	}
	if d.ClientID != id {
		return Client{}, errors.New("the metadata document names a different client_id than its own address")
	}
	if len(d.ClientSecret) > 0 || len(d.ClientSecretExpiresAt) > 0 {
		return Client{}, errors.New("a metadata document carries no client secret")
	}
	switch d.TokenEndpointAuthMethod {
	case "", "none":
	default:
		// private_key_jwt is allowed by the draft and not offered here: a
		// public client with PKCE is what an app on a person's machine is.
		return Client{}, fmt.Errorf("token_endpoint_auth_method %q is not offered; only none (a public client with PKCE)", d.TokenEndpointAuthMethod)
	}
	for _, g := range d.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			return Client{}, fmt.Errorf("grant type %q is not offered", g)
		}
	}
	for _, rt := range d.ResponseTypes {
		if rt != "code" {
			return Client{}, fmt.Errorf("response type %q is not offered", rt)
		}
	}
	name := strings.TrimSpace(d.ClientName)
	if name == "" || utf8.RuneCountInString(name) > maxName || strings.ContainsAny(name, "\r\n\t") {
		return Client{}, fmt.Errorf("the metadata document needs a client_name of at most %d characters on one line", maxName)
	}
	for _, r := range name {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			// Control and direction characters make a name read as
			// something else on the consent screen.
			return Client{}, errors.New("the client_name has characters that change how it reads")
		}
	}
	if len(d.RedirectURIs) == 0 || len(d.RedirectURIs) > maxRedirects {
		return Client{}, fmt.Errorf("the metadata document lists one to %d redirect_uris", maxRedirects)
	}
	for _, r := range d.RedirectURIs {
		if err := CheckRedirect(r); err != nil {
			return Client{}, err
		}
	}
	c := Client{ID: id, Name: name, RedirectURIs: d.RedirectURIs}
	if d.ClientURI != "" {
		if u, err := url.Parse(d.ClientURI); err == nil && u.Scheme == "https" && u.User == nil && len(d.ClientURI) <= maxURI {
			c.URI = d.ClientURI
		}
	}
	return c, nil
}

// CheckRedirect checks an address sign-in may return to: https, or http to
// this machine, and nothing that hides where it goes.
func CheckRedirect(raw string) error {
	if len(raw) > maxURI {
		return errors.New("a redirect address is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%q is not a redirect address: an absolute URL with a host and no fragment", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !Loopback(u.Hostname()) {
			return fmt.Errorf("%q is plain http to another machine; redirects are https or to this machine", raw)
		}
	default:
		return fmt.Errorf("%q is neither https nor http to this machine", raw)
	}
	return nil
}

// RedirectMatches reports whether a requested redirect is one a client
// registered: exactly, or, for a loopback address, exactly but for the
// port, which a native app chooses when it starts (RFC 8252, section 7.3).
func RedirectMatches(registered []string, requested string) bool {
	for _, r := range registered {
		if r == requested {
			return true
		}
	}
	req, err := url.Parse(requested)
	if err != nil || req.Scheme != "http" || !Loopback(req.Hostname()) {
		return false
	}
	for _, r := range registered {
		reg, err := url.Parse(r)
		if err != nil || reg.Scheme != "http" || !Loopback(reg.Hostname()) {
			continue
		}
		if reg.Hostname() == req.Hostname() && reg.EscapedPath() == req.EscapedPath() &&
			reg.RawQuery == req.RawQuery {
			return true
		}
	}
	return false
}

// Fetcher reads a metadata document: no redirects followed, at most a few
// kilobytes, never from an address inside the network. The host supplies
// it (internal/fetch does all three).
type Fetcher func(ctx context.Context, url string) (body []byte, maxAge time.Duration, err error)

type cached struct {
	client Client
	until  time.Time
}

// Directory resolves client_ids to clients.
type Directory struct {
	// Registered are the clients an administrator added.
	Registered func() ([]Client, error)
	Fetch      Fetcher

	mu    sync.Mutex
	cache map[string]cached
}

// Resolve finds a client: registered here, or described by its own
// metadata document, which is fetched (and kept for as long as it says,
// between five minutes and a day) only when its host is allowed.
func (d *Directory) Resolve(ctx context.Context, cfg Config, id string, now time.Time) (Client, error) {
	if strings.HasPrefix(id, registeredPref) {
		if d.Registered != nil {
			list, err := d.Registered()
			if err != nil {
				return Client{}, err
			}
			for _, c := range list {
				if c.ID == id {
					return c, nil
				}
			}
		}
		return Client{}, errors.New("no app is registered with that client_id")
	}
	if !IsMetadataURL(id) {
		return Client{}, errors.New("the client_id is neither an app registered here nor a metadata document's address")
	}
	u, err := CheckMetadataURL(id)
	if err != nil {
		return Client{}, err
	}
	if !cfg.HostAllowed(u.Host) {
		return Client{}, &NotAllowed{Host: u.Host}
	}
	d.mu.Lock()
	if c, ok := d.cache[id]; ok && now.Before(c.until) {
		d.mu.Unlock()
		return c.client, nil
	}
	d.mu.Unlock()
	if d.Fetch == nil {
		return Client{}, errors.New("metadata documents cannot be fetched here")
	}
	body, maxAge, err := d.Fetch(ctx, id)
	if err != nil {
		return Client{}, fmt.Errorf("the app's metadata document could not be read: %w", err)
	}
	c, err := ParseDocument(id, body)
	if err != nil {
		return Client{}, err
	}
	// Kept for as long as the document says, within bounds; an error or a
	// bad document is never kept, so a fix is seen at once.
	if maxAge < cacheFloor {
		maxAge = cacheFloor
	}
	if maxAge > cacheCeiling {
		maxAge = cacheCeiling
	}
	d.mu.Lock()
	if d.cache == nil {
		d.cache = map[string]cached{}
	}
	if len(d.cache) >= maxCachedApps {
		for k, v := range d.cache {
			if now.After(v.until) {
				delete(d.cache, k)
			}
		}
		if len(d.cache) >= maxCachedApps {
			d.cache = map[string]cached{}
		}
	}
	d.cache[id] = cached{client: c, until: now.Add(maxAge)}
	d.mu.Unlock()
	return c, nil
}

// Forget drops a cached document, for when a host stops being allowed.
func (d *Directory) Forget() {
	d.mu.Lock()
	d.cache = nil
	d.mu.Unlock()
}

// NotAllowed is an app from a host the organisation has not allowed.
type NotAllowed struct{ Host string }

func (e *NotAllowed) Error() string {
	return fmt.Sprintf("apps from %s are not allowed to connect here", e.Host)
}

// NewRegistered makes a client an administrator registers, for an app that
// cannot publish a metadata document.
func NewRegistered(name string, redirects []string, by string, now time.Time) (Client, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxName || strings.ContainsAny(name, "\r\n\t") {
		return Client{}, fmt.Errorf("an app's name is one line of at most %d characters", maxName)
	}
	if len(redirects) == 0 || len(redirects) > maxRedirects {
		return Client{}, fmt.Errorf("an app has one to %d redirect addresses", maxRedirects)
	}
	for _, r := range redirects {
		if err := CheckRedirect(r); err != nil {
			return Client{}, err
		}
	}
	return Client{ID: newID(registeredPref), Name: name, RedirectURIs: redirects,
		Registered: true, AddedBy: by, Added: now}, nil
}
