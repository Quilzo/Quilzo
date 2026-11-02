// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Discovery: who authorises a remote MCP server, read from what the server
// publishes, as the MCP authorization specification asks.
//
//  1. The server's protected-resource metadata (RFC 9728): from the
//     resource_metadata the 401 it answers an unauthenticated request with
//     names, or the well-known address for it.
//  2. That metadata's authorization server, and its own metadata
//     (RFC 8414, or OpenID Connect discovery).
//  3. PKCE with S256 required: a server that does not say it supports it
//     is refused, since a code without it is a code anybody who sees it
//     can use.
//  4. A client id: one given, or registered there (RFC 7591) as a public
//     client, which PKCE alone protects.
//
// Every address is https and every answer is bounded; the resource
// indicator (RFC 8707) goes on every authorization and token request, so a
// token is for this server and no other.

// Getter fetches one address and says how it answered.
type Getter func(ctx context.Context, url string) (status int, header http.Header, body []byte, err error)

// JSONPoster posts a JSON body and returns the answer.
type JSONPoster func(ctx context.Context, url string, body []byte) (status int, answer []byte, err error)

// Discovered is what a protected resource and its authorization server
// say.
type Discovered struct {
	Resource     string   `json:"resource"`
	Issuer       string   `json:"issuer"`
	AuthURL      string   `json:"authorization_endpoint"`
	TokenURL     string   `json:"token_endpoint"`
	RevokeURL    string   `json:"revocation_endpoint,omitempty"`
	RegisterURL  string   `json:"registration_endpoint,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	MetadataDocs bool     `json:"client_id_metadata_document_supported,omitempty"`
}

var reResourceMetadata = regexp.MustCompile(`resource_metadata="([^"]+)"`)

// Discover reads who authorises the resource at resourceURL.
func Discover(ctx context.Context, get Getter, resourceURL string) (Discovered, error) {
	res, err := url.Parse(resourceURL)
	if err != nil || res.Scheme != "https" || res.Host == "" || res.User != nil {
		return Discovered{}, fmt.Errorf("%q is not an https address of a server", resourceURL)
	}
	res.Fragment, res.RawQuery = "", ""
	resource := strings.TrimRight(res.String(), "/")

	// Where its metadata is: what its 401 says, or the well-known address.
	prmURL := ""
	if status, h, _, err := get(ctx, resource); err == nil && status == http.StatusUnauthorized {
		if m := reResourceMetadata.FindStringSubmatch(h.Get("WWW-Authenticate")); m != nil {
			prmURL = m[1]
		}
	}
	if prmURL == "" {
		prmURL = wellKnown(res, "oauth-protected-resource")
	}
	if err := checkEndpoint(prmURL); err != nil {
		return Discovered{}, fmt.Errorf("its protected-resource metadata: %w", err)
	}
	var prm struct {
		Resource string   `json:"resource"`
		Servers  []string `json:"authorization_servers"`
		Scopes   []string `json:"scopes_supported"`
	}
	if err := getJSON(ctx, get, prmURL, &prm); err != nil {
		return Discovered{}, fmt.Errorf("its protected-resource metadata at %s: %w", prmURL, err)
	}
	// The metadata is for the resource asked about, not another (RFC 9728
	// section 3.3): one server cannot speak for somebody else's.
	if strings.TrimRight(prm.Resource, "/") != resource {
		return Discovered{}, fmt.Errorf("its metadata is for %q, not %q", clip(prm.Resource, 120), resource)
	}
	if len(prm.Servers) == 0 {
		return Discovered{}, errors.New("its metadata names no authorization server")
	}
	issuer := strings.TrimRight(prm.Servers[0], "/")
	is, err := url.Parse(issuer)
	if err != nil || is.Scheme != "https" || is.Host == "" {
		return Discovered{}, fmt.Errorf("its authorization server %q is not an https address", clip(issuer, 120))
	}

	var as struct {
		Issuer      string   `json:"issuer"`
		Auth        string   `json:"authorization_endpoint"`
		Token       string   `json:"token_endpoint"`
		Revoke      string   `json:"revocation_endpoint"`
		Register    string   `json:"registration_endpoint"`
		Methods     []string `json:"code_challenge_methods_supported"`
		Scopes      []string `json:"scopes_supported"`
		ClientIDDoc bool     `json:"client_id_metadata_document_supported"`
	}
	var last error
	found := false
	for _, u := range []string{wellKnown(is, "oauth-authorization-server"), wellKnown(is, "openid-configuration"),
		issuer + "/.well-known/openid-configuration"} {
		if err := getJSON(ctx, get, u, &as); err != nil {
			last = err
			continue
		}
		found = true
		break
	}
	if !found {
		return Discovered{}, fmt.Errorf("the authorization server %s publishes no metadata: %v", issuer, last)
	}
	if strings.TrimRight(as.Issuer, "/") != issuer {
		return Discovered{}, fmt.Errorf("the authorization server's metadata is for %q, not %q", clip(as.Issuer, 120), issuer)
	}
	if !slices.Contains(as.Methods, "S256") {
		return Discovered{}, fmt.Errorf("%s does not say it supports PKCE with S256, which this requires", issuer)
	}
	for _, e := range []struct{ name, raw string }{{"authorization", as.Auth}, {"token", as.Token}} {
		if err := checkEndpoint(e.raw); err != nil {
			return Discovered{}, fmt.Errorf("its %s endpoint: %w", e.name, err)
		}
	}
	d := Discovered{Resource: resource, Issuer: issuer, AuthURL: as.Auth, TokenURL: as.Token, MetadataDocs: as.ClientIDDoc}
	if as.Revoke != "" && checkEndpoint(as.Revoke) == nil {
		d.RevokeURL = as.Revoke
	}
	if as.Register != "" && checkEndpoint(as.Register) == nil {
		d.RegisterURL = as.Register
	}
	scopes := prm.Scopes
	if len(scopes) == 0 {
		scopes = as.Scopes
	}
	for _, s := range scopes {
		if reScope.MatchString(s) && len(d.Scopes) < 32 {
			d.Scopes = append(d.Scopes, s)
		}
	}
	return d, nil
}

// wellKnown is a well-known address for a URL with a path: inserted
// between the host and the path (RFC 8414 section 3.1, RFC 9728 3.1).
func wellKnown(u *url.URL, name string) string {
	path := strings.TrimRight(u.EscapedPath(), "/")
	return "https://" + u.Host + "/.well-known/" + name + path
}

func getJSON(ctx context.Context, get Getter, u string, into any) error {
	if err := checkEndpoint(u); err != nil {
		return err
	}
	status, _, body, err := get(ctx, u)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("answered %d", status)
	}
	if len(body) > 64<<10 {
		return errors.New("answered more than metadata is")
	}
	if err := json.Unmarshal(body, into); err != nil {
		return errors.New("did not answer in JSON")
	}
	return nil
}

// Register registers this installation as a public client of an
// authorization server that takes registrations (RFC 7591), and returns
// the client id it was given. A server that insists on a client secret is
// refused: give its client id and secret by hand instead.
func Register(ctx context.Context, post JSONPoster, d Discovered, clientName, redirect string) (string, error) {
	if d.RegisterURL == "" {
		return "", errors.New("the authorization server takes no registrations: give the client id it issued")
	}
	if err := checkEndpoint(redirect); err != nil {
		return "", fmt.Errorf("the redirect: %w", err)
	}
	req := map[string]any{
		"client_name":                clip(clientName, 100),
		"redirect_uris":              []string{redirect},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	if len(d.Scopes) > 0 {
		req["scope"] = strings.Join(d.Scopes, " ")
	}
	body, _ := json.Marshal(req)
	status, answer, err := post(ctx, d.RegisterURL, body)
	if err != nil {
		return "", fmt.Errorf("registering: %w", err)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", fmt.Errorf("registering: the server answered %d", status)
	}
	var out struct {
		ClientID string `json:"client_id"`
		Secret   string `json:"client_secret"`
		Auth     string `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(answer, &out); err != nil || strings.TrimSpace(out.ClientID) == "" || len(out.ClientID) > 256 {
		return "", errors.New("registering: the server gave no client id")
	}
	if out.Secret != "" || (out.Auth != "" && out.Auth != "none") {
		return "", errors.New("the server registered a confidential client and sent a secret; give a client id and " +
			"secret it issued by hand instead, kept as a credential")
	}
	return out.ClientID, nil
}

// FromDiscovered is a provider for a discovered resource, with a client id.
func FromDiscovered(name, title, clientID string, d Discovered) (Provider, error) {
	u, err := url.Parse(d.Resource)
	if err != nil || u.Hostname() == "" {
		return Provider{}, errors.New("the resource has no host")
	}
	p := Provider{Name: name, Title: title, AuthURL: d.AuthURL, TokenURL: d.TokenURL, RevokeURL: d.RevokeURL,
		ClientID: clientID, Scopes: d.Scopes, Hosts: []string{strings.ToLower(u.Hostname())}, Resource: d.Resource}
	return p, p.Check()
}
