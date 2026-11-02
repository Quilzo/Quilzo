// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package connect is a person's accounts elsewhere, connected with OAuth
// 2.1, so an agent acting for them can act there as them, and no more.
//
// # Why per person
//
// An integration's credential was one key for the whole install: an agent
// filing into somebody's calendar did it as whoever the key belonged to,
// and every agent that could reach the integration could do it in every
// calendar the key reached. A connection is one person's account, which
// they connected themselves and can disconnect, and an agent uses it only
// on the authority of that person: its sponsor.
//
// # What the flow is
//
// Authorization code with PKCE (S256 always: OAuth 2.1 requires it), a
// state that is single-use, expires in ten minutes and is bound to the
// person who started it, and an exact redirect address. The client secret,
// when there is one, is a sealed credential named by the declaration and
// sent only to the token endpoint. Tokens are kept sealed, refreshed when
// due (a rotated refresh token replaces the old one), and revoked at the
// provider when somebody disconnects (RFC 7009), where it offers that.
//
// # Where a token may go
//
// A provider names the API hosts its tokens are for. A token is sent to
// those and nothing else: an integration declared at another host is not
// handed it, so a declaration cannot carry somebody's account off to a
// server that was never theirs.
package connect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Provider is an OAuth provider somebody may connect an account at.
type Provider struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	// AuthURL and TokenURL are the provider's endpoints; RevokeURL, when it
	// offers one, is where a token is revoked.
	AuthURL   string `json:"auth_url"`
	TokenURL  string `json:"token_url"`
	RevokeURL string `json:"revoke_url,omitempty"`
	ClientID  string `json:"client_id"`
	// Secret names the sealed credential holding the client secret. Empty
	// is a public client, which PKCE alone protects.
	Secret string `json:"secret,omitempty"`
	// Scopes are asked for, and shown to the person connecting.
	Scopes []string `json:"scopes"`
	// Hosts are the API hosts a token may be sent to: exactly these names.
	Hosts []string `json:"hosts"`
	// Params are sent on the authorization request beside the standard
	// ones, such as Google's access_type=offline.
	Params map[string]string `json:"params,omitempty"`
	// Resource is the server a token is for (RFC 8707), sent on every
	// authorization and token request: a remote MCP server's address, as
	// discovered (discover.go). Empty sends none.
	Resource string `json:"resource,omitempty"`
}

var (
	reName   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	reHost   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	reScope  = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]{1,200}$`)
	reParam  = regexp.MustCompile(`^[a-z_]{1,32}$`)
	reSecret = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// reserved are the authorization request's own parameters, which a
// declaration may not set.
var reserved = map[string]bool{"response_type": true, "client_id": true, "redirect_uri": true, "scope": true,
	"state": true, "code_challenge": true, "code_challenge_method": true, "nonce": true, "resource": true}

// Check says what is wrong with a provider, or nil.
func (p Provider) Check() error {
	if !reName.MatchString(p.Name) {
		return fmt.Errorf("%q is not a provider's name: lower-case letters, digits and hyphens", p.Name)
	}
	if strings.TrimSpace(p.Title) == "" {
		return fmt.Errorf("%s needs a title a person connecting will recognise", p.Name)
	}
	for _, u := range []struct{ name, raw string }{{"auth_url", p.AuthURL}, {"token_url", p.TokenURL}, {"revoke_url", p.RevokeURL}} {
		if u.raw == "" && u.name == "revoke_url" {
			continue
		}
		if err := checkEndpoint(u.raw); err != nil {
			return fmt.Errorf("%s's %s: %w", p.Name, u.name, err)
		}
	}
	if strings.TrimSpace(p.ClientID) == "" || len(p.ClientID) > 256 {
		return fmt.Errorf("%s needs the client id the provider issued", p.Name)
	}
	if p.Secret != "" && !reSecret.MatchString(p.Secret) {
		return fmt.Errorf("%s: %q is not a credential's name (quilzo secret set NAME); the secret itself is never "+
			"written here", p.Name, p.Secret)
	}
	if len(p.Scopes) > 32 {
		return fmt.Errorf("%s asks for more than 32 scopes", p.Name)
	}
	for _, s := range p.Scopes {
		if !reScope.MatchString(s) {
			return fmt.Errorf("%s: %q is not a scope", p.Name, s)
		}
	}
	if p.Resource != "" {
		if err := checkEndpoint(p.Resource); err != nil {
			return fmt.Errorf("%s's resource: %w", p.Name, err)
		}
	}
	if len(p.Hosts) == 0 || len(p.Hosts) > 16 {
		return fmt.Errorf("%s names 1 to 16 hosts its tokens are for: a token with nowhere declared to go goes nowhere", p.Name)
	}
	for _, h := range p.Hosts {
		if !reHost.MatchString(h) {
			return fmt.Errorf("%s: %q is not a host name; exactly one name each, no wildcard", p.Name, h)
		}
	}
	for k, v := range p.Params {
		if !reParam.MatchString(k) || reserved[k] || len(v) > 100 || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("%s: %s=%q is not a parameter it may add", p.Name, k, v)
		}
	}
	return nil
}

// checkEndpoint refuses an endpoint that is not https: a code, a secret
// and a token go there.
func checkEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%q is not an address", raw)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%q is not https: a code, a secret and a token go there", raw)
	}
	return nil
}

// Allows reports whether a token from this provider may be sent to host.
func (p Provider) Allows(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range p.Hosts {
		if h == host {
			return true
		}
	}
	return false
}

// Templates are providers whose endpoints are well known: a declaration
// starts from one and adds its client id and secret.
var Templates = map[string]Provider{
	"google": {Name: "google", Title: "Google",
		AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token",
		RevokeURL: "https://oauth2.googleapis.com/revoke",
		Hosts: []string{"www.googleapis.com", "gmail.googleapis.com", "sheets.googleapis.com", "docs.googleapis.com",
			"people.googleapis.com", "tasks.googleapis.com"},
		// A refresh token is issued only when asked for, and only on consent.
		Params: map[string]string{"access_type": "offline", "prompt": "consent"}},
	"microsoft": {Name: "microsoft", Title: "Microsoft",
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		Hosts:    []string{"graph.microsoft.com"},
		// A refresh token is issued only for offline_access.
		Scopes: []string{"offline_access"}},
	"github": {Name: "github", Title: "GitHub",
		AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token",
		Hosts: []string{"api.github.com"}},
}

// TemplateNames are the templates, sorted.
func TemplateNames() []string {
	out := make([]string, 0, len(Templates))
	for k := range Templates {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MaxPending is how long a connection may take to finish.
const MaxPending = 10 * time.Minute

// Pending is a connection in progress.
type Pending struct {
	State    string    `json:"state"`
	Verifier string    `json:"verifier"`
	Provider string    `json:"provider"`
	Person   string    `json:"person"`
	Redirect string    `json:"redirect"`
	Created  time.Time `json:"created"`
}

// Expired reports whether it took too long.
func (p Pending) Expired(now time.Time) bool {
	return now.Sub(p.Created) > MaxPending || now.Before(p.Created.Add(-time.Minute))
}

func random() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidState reports whether s could be a state this package made.
func ValidState(s string) bool {
	if len(s) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// Begin starts connecting a person's account: the pending connection to
// keep, and the address to send their browser to.
func Begin(p Provider, redirect, person string, now time.Time) (Pending, string, error) {
	if err := p.Check(); err != nil {
		return Pending{}, "", err
	}
	if err := checkEndpoint(redirect); err != nil {
		return Pending{}, "", fmt.Errorf("the address the provider sends people back to: %w", err)
	}
	if strings.TrimSpace(person) == "" {
		return Pending{}, "", errors.New("a connection is somebody's")
	}
	state, err := random()
	if err != nil {
		return Pending{}, "", err
	}
	verifier, err := random()
	if err != nil {
		return Pending{}, "", err
	}
	pd := Pending{State: state, Verifier: verifier, Provider: p.Name, Person: person, Redirect: redirect, Created: now.UTC()}
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{}
	for k, v := range p.Params {
		q.Set(k, v)
	}
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", redirect)
	if len(p.Scopes) > 0 {
		q.Set("scope", strings.Join(p.Scopes, " "))
	}
	q.Set("state", state)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	if p.Resource != "" {
		q.Set("resource", p.Resource)
	}
	sep := "?"
	if strings.Contains(p.AuthURL, "?") {
		sep = "&"
	}
	return pd, p.AuthURL + sep + q.Encode(), nil
}

// Token is a connection's tokens.
type Token struct {
	Access  string    `json:"access"`
	Refresh string    `json:"refresh,omitempty"`
	Expiry  time.Time `json:"expiry,omitempty"`
	Scope   string    `json:"scope,omitempty"`
}

// Due reports whether the access token is expired, or will be within a
// minute: refreshed before, not after, a call fails with it.
func (t Token) Due(now time.Time) bool {
	return !t.Expiry.IsZero() && now.Add(time.Minute).After(t.Expiry)
}

// Poster sends a form to a token endpoint and returns its body, whatever
// its status: OAuth's errors are a 400 with the reason inside.
type Poster func(ctx context.Context, url string, form url.Values) ([]byte, error)

// Exchange trades a code for tokens, with the verifier the challenge
// committed to.
func Exchange(ctx context.Context, post Poster, p Provider, secret string, pd Pending, code string, now time.Time) (Token, error) {
	if pd.Expired(now) {
		return Token{}, fmt.Errorf("connecting took longer than %s; start again", MaxPending)
	}
	if pd.Provider != p.Name {
		return Token{}, errors.New("this answer is for another provider's connection")
	}
	if code == "" || len(code) > 2048 {
		return Token{}, errors.New("the provider sent no code")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {pd.Redirect},
		"client_id": {p.ClientID}, "code_verifier": {pd.Verifier}}
	if p.Resource != "" {
		form.Set("resource", p.Resource)
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	return token(ctx, post, p, form, "", now)
}

// Refresh trades a refresh token for new tokens. A provider that rotates
// refresh tokens sends a new one, which replaces the old; one that does
// not keeps the old.
func Refresh(ctx context.Context, post Poster, p Provider, secret, refresh string, now time.Time) (Token, error) {
	if refresh == "" {
		return Token{}, errors.New("the connection has no refresh token: connect again")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {p.ClientID}}
	if p.Resource != "" {
		form.Set("resource", p.Resource)
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	return token(ctx, post, p, form, refresh, now)
}

func token(ctx context.Context, post Poster, p Provider, form url.Values, keep string, now time.Time) (Token, error) {
	body, err := post(ctx, p.TokenURL, form)
	if err != nil {
		return Token{}, fmt.Errorf("%s's token endpoint: %w", p.Title, err)
	}
	var out struct {
		Access    string `json:"access_token"`
		Type      string `json:"token_type"`
		ExpiresIn int64  `json:"expires_in"`
		Refresh   string `json:"refresh_token"`
		Scope     string `json:"scope"`
		Error     string `json:"error"`
		Desc      string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Token{}, fmt.Errorf("%s's token endpoint did not answer in JSON", p.Title)
	}
	if out.Error != "" {
		return Token{}, fmt.Errorf("%s refused: %s %s", p.Title, clip(out.Error, 60), clip(out.Desc, 200))
	}
	if out.Access == "" || len(out.Access) > 16<<10 {
		return Token{}, fmt.Errorf("%s sent no access token", p.Title)
	}
	if out.Type != "" && !strings.EqualFold(out.Type, "bearer") {
		return Token{}, fmt.Errorf("%s sent a %q token, and this sends bearer tokens only", p.Title, clip(out.Type, 20))
	}
	t := Token{Access: out.Access, Refresh: out.Refresh, Scope: clip(out.Scope, 2000)}
	if t.Refresh == "" {
		t.Refresh = keep
	}
	if out.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(out.ExpiresIn) * time.Second).UTC()
	}
	return t, nil
}

// Revoke asks the provider to forget a token (RFC 7009), where it offers
// that; a provider that does not is told nothing, and the token is only
// forgotten here.
func Revoke(ctx context.Context, post Poster, p Provider, secret, tok string) error {
	if p.RevokeURL == "" || tok == "" {
		return nil
	}
	form := url.Values{"token": {tok}, "client_id": {p.ClientID}}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	_, err := post(ctx, p.RevokeURL, form)
	return err
}

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
