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
// Authorization code with PKCE (S256: OAuth 2.1 requires it, and only
// TikTok's dialect goes without, a confidential client whose web flow
// takes no challenge), a state that is single-use, expires in ten minutes
// and is bound to the person who started it, and an exact redirect
// address. The client secret, when there is one, is a sealed credential
// named by the declaration and sent only to the token endpoint (and, for
// Meta, to the address its tokens are exchanged at). Tokens are kept
// sealed, refreshed when due (a rotated refresh token replaces the old
// one), and revoked at the provider when somebody disconnects (RFC 7009),
// where it offers that.
//
// # Dialects
//
// The social platforms each depart from that in their own way, and a
// provider declared as plain OAuth 2 at one of them did not work: TikTok
// takes its client id as client_key and its scopes separated by commas,
// and refused the request; Meta issues no refresh token, so every
// Instagram connection lapsed within the hour and said "connect again";
// LinkedIn's refresh token lapses a year after it was first issued, and
// nothing here knew when. A provider names its dialect from a closed list
// (dialects, below): what each departs in is written here in Go, not in a
// declaration, so a declaration cannot invent one. The standard, oauth2,
// is the default, and every provider declared before dialects existed
// speaks it unchanged.
//
// # Where a token may go
//
// A provider names the API hosts its tokens are for. A token is sent to
// those and nothing else: an integration declared at another host is not
// handed it, so a declaration cannot carry somebody's account off to a
// server that was never theirs.
package connect

import (
	"cmp"
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

	"github.com/quilzo/quilzo/internal/plaintext"
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
	// Dialect is how the provider departs from standard OAuth 2, one of
	// dialects. Empty is oauth2, so a declaration written before there
	// were dialects means what it always did.
	Dialect Dialect `json:"dialect,omitempty"`
	// ExchangeURL and RenewURL are where Meta's dialects trade the
	// short-lived token a code buys for a long-lived one, and renew that:
	// Meta issues no refresh token. Empty is where Meta documents them:
	// Facebook's token endpoint for both, and Instagram's two addresses on
	// graph.instagram.com.
	ExchangeURL string `json:"exchange_url,omitempty"`
	RenewURL    string `json:"renew_url,omitempty"`
}

// Dialect is a way of speaking OAuth 2 that one provider has.
type Dialect string

// The dialects. Each is written here because a provider's documentation
// says so, not because a declaration asked for it.
const (
	// OAuth2 is the standard: client_id, scopes separated by spaces, PKCE,
	// a refresh token to refresh with.
	OAuth2 Dialect = "oauth2"
	// TikTok's Login Kit takes client_key where the standard has
	// client_id, on the authorization request and at the token endpoint
	// alike, and its scopes separated by commas; it says how long the
	// refresh token lives (refresh_expires_in, a year). Its web flow takes
	// no PKCE: TikTok documents the challenge for desktop and mobile apps
	// only, encoded in hex rather than as RFC 7636 says, so a standard
	// challenge sent to it is one it would check differently. The state,
	// single-use and bound to the person, and the client secret, which
	// its token endpoint requires, are what protect it.
	TikTok Dialect = "tiktok"
	// MetaInstagram is Instagram's login: scopes separated by commas, a
	// code that buys a token for an hour, exchanged at once (a GET, with
	// ig_exchange_token) for one that lasts sixty days, and renewed by
	// another GET (ig_refresh_token) once it is a day old and before it
	// expires. There is no refresh token.
	MetaInstagram Dialect = "meta-instagram"
	// MetaFacebook is Facebook Login: the same, with fb_exchange_token for
	// both the exchange and the renewal, at the token endpoint.
	MetaFacebook Dialect = "meta-facebook"
	// LinkedIn issues a refresh token only to its approved partners, and
	// that one lapses 365 days after it was first issued: a refresh does
	// not move the date, however often it is done.
	LinkedIn Dialect = "linkedin"
)

// dialects are the ones there are, and what each is for a person reading
// the list.
var dialects = map[Dialect]string{
	OAuth2:        "standard OAuth 2 (the default)",
	TikTok:        "TikTok's Login Kit",
	MetaInstagram: "Instagram's login, through Meta",
	MetaFacebook:  "Facebook Login, through Meta",
	LinkedIn:      "LinkedIn's OAuth 2",
}

// DialectNames are the dialects, sorted.
func DialectNames() []string {
	out := make([]string, 0, len(dialects))
	for d := range dialects {
		out = append(out, string(d))
	}
	sort.Strings(out)
	return out
}

// dialect is the provider's dialect, the empty one being the standard.
func (p Provider) dialect() Dialect {
	if p.Dialect == "" {
		return OAuth2
	}
	return p.Dialect
}

// meta reports whether the provider is one of Meta's, whose tokens are
// exchanged and renewed rather than refreshed.
func (p Provider) meta() bool { return p.dialect() == MetaInstagram || p.dialect() == MetaFacebook }

// clientParam is the name the provider reads its client id under. One
// place says it, so the authorization request, the token endpoint, the
// refresh and the revocation cannot disagree: TikTok's was refused at the
// first because client_id was written out at each of them.
func (p Provider) clientParam() string {
	if p.dialect() == TikTok {
		return "client_key"
	}
	return "client_id"
}

// scopeSeparator is what the provider separates the scopes it is asked
// for with.
func (p Provider) scopeSeparator() string {
	switch p.dialect() {
	case TikTok, MetaInstagram, MetaFacebook:
		return ","
	}
	return " "
}

// pkce reports whether the provider is sent a PKCE challenge.
func (p Provider) pkce() bool { return p.dialect() != TikTok }

// exchangeURL and renewURL are where a Meta dialect's tokens are traded
// for long-lived ones and renewed: the declaration's addresses, or where
// Meta documents them.
func (p Provider) exchangeURL() string {
	if p.dialect() == MetaInstagram {
		return cmp.Or(p.ExchangeURL, "https://graph.instagram.com/access_token")
	}
	return cmp.Or(p.ExchangeURL, p.TokenURL)
}

func (p Provider) renewURL() string {
	if p.dialect() == MetaInstagram {
		return cmp.Or(p.RenewURL, "https://graph.instagram.com/refresh_access_token")
	}
	return cmp.Or(p.RenewURL, p.TokenURL)
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
	if _, ok := dialects[p.dialect()]; !ok {
		return fmt.Errorf("%s: %q is not a dialect; there are %s", p.Name, p.Dialect, strings.Join(DialectNames(), ", "))
	}
	// Every dialect but the standard is a confidential client: TikTok's
	// and LinkedIn's token endpoints and Meta's exchange take the client
	// secret, and a declaration without one would be refused only when
	// somebody had already consented.
	if p.dialect() != OAuth2 && p.Secret == "" {
		return fmt.Errorf("%s speaks %s, whose tokens are issued only with the client secret: --client-secret NAME",
			p.Name, dialects[p.dialect()])
	}
	if (p.ExchangeURL != "" || p.RenewURL != "") && !p.meta() {
		return fmt.Errorf("%s: only Meta's dialects exchange and renew tokens; the rest refresh them at the token endpoint", p.Name)
	}
	for _, u := range []struct{ name, raw string }{{"exchange_url", p.ExchangeURL}, {"renew_url", p.RenewURL}} {
		if u.raw == "" {
			continue
		}
		if err := checkEndpoint(u.raw); err != nil {
			return fmt.Errorf("%s's %s: %w", p.Name, u.name, err)
		}
	}
	if len(p.Scopes) > 32 {
		return fmt.Errorf("%s asks for more than 32 scopes", p.Name)
	}
	for _, s := range p.Scopes {
		if !reScope.MatchString(s) {
			return fmt.Errorf("%s: %q is not a scope", p.Name, s)
		}
		// A scope with the separator in it would be read as two.
		if strings.Contains(s, p.scopeSeparator()) {
			return fmt.Errorf("%s: %q is not one scope to %s, which separates them with %q", p.Name, s,
				dialects[p.dialect()], p.scopeSeparator())
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
		if !reParam.MatchString(k) || reserved[k] || k == p.clientParam() || len(v) > 100 || strings.ContainsAny(v, "\r\n") {
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
	// The social platforms, for posting as the person who connected. Each
	// asks for what posting needs; an administrator adds the app's client
	// id and secret, and the platform's own app review decides when it
	// may post publicly.
	"youtube": {Name: "youtube", Title: "YouTube",
		AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token",
		RevokeURL: "https://oauth2.googleapis.com/revoke",
		Scopes:    []string{"https://www.googleapis.com/auth/youtube.upload", "https://www.googleapis.com/auth/youtube.readonly"},
		Hosts:     []string{"www.googleapis.com", "youtube.googleapis.com", "youtubeanalytics.googleapis.com"},
		Params:    map[string]string{"access_type": "offline", "prompt": "consent"}},
	"tiktok": {Name: "tiktok", Title: "TikTok", Dialect: TikTok,
		AuthURL: "https://www.tiktok.com/v2/auth/authorize/", TokenURL: "https://open.tiktokapis.com/v2/oauth/token/",
		RevokeURL: "https://open.tiktokapis.com/v2/oauth/revoke/",
		Scopes:    []string{"user.info.basic", "video.upload", "video.publish"},
		Hosts:     []string{"open.tiktokapis.com"}},
	"instagram": {Name: "instagram", Title: "Instagram", Dialect: MetaInstagram,
		AuthURL: "https://www.instagram.com/oauth/authorize", TokenURL: "https://api.instagram.com/oauth/access_token",
		ExchangeURL: "https://graph.instagram.com/access_token", RenewURL: "https://graph.instagram.com/refresh_access_token",
		Scopes: []string{"instagram_business_basic", "instagram_business_content_publish"},
		Hosts:  []string{"graph.instagram.com"}},
	// Facebook's Graph API is versioned and each version retires on a
	// schedule; an address without a version is answered by the oldest
	// one still served, so a template naming none does not stop working
	// the day Meta retires the version it was written against.
	"facebook": {Name: "facebook", Title: "Facebook", Dialect: MetaFacebook,
		AuthURL: "https://www.facebook.com/dialog/oauth", TokenURL: "https://graph.facebook.com/oauth/access_token",
		Scopes: []string{"pages_show_list", "pages_read_engagement", "pages_manage_posts"},
		Hosts:  []string{"graph.facebook.com"}},
	"linkedin": {Name: "linkedin", Title: "LinkedIn", Dialect: LinkedIn,
		AuthURL: "https://www.linkedin.com/oauth/v2/authorization", TokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
		Scopes: []string{"openid", "profile", "w_member_social"},
		Hosts:  []string{"api.linkedin.com"}},
}

// PlatformDialect is the dialect of the platform whose site an
// authorization endpoint is on, as its template says, or empty for any
// other site. A provider declared by hand at TikTok's address and naming
// no dialect was asked as plain OAuth 2, and TikTok refused it: that is
// how the defect was first found, and the template alone did not stop it.
func PlatformDialect(authURL string) Dialect {
	u, err := url.Parse(authURL)
	if err != nil {
		return ""
	}
	host := strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), "www.")
	for _, name := range TemplateNames() {
		t := Templates[name]
		if t.Dialect == "" {
			continue
		}
		at, err := url.Parse(t.AuthURL)
		if err != nil {
			continue
		}
		site := strings.TrimPrefix(at.Hostname(), "www.")
		if host == site || strings.HasSuffix(host, "."+site) {
			return t.Dialect
		}
	}
	return ""
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
	q.Set(p.clientParam(), p.ClientID)
	q.Set("redirect_uri", redirect)
	if len(p.Scopes) > 0 {
		q.Set("scope", strings.Join(p.Scopes, p.scopeSeparator()))
	}
	q.Set("state", state)
	if p.pkce() {
		q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
		q.Set("code_challenge_method", "S256")
	}
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
	// RefreshExpiry is when the refresh token itself lapses, where the
	// provider says: TikTok's a year from when it was issued, LinkedIn's
	// a year from the first issue, never moved by a refresh, and a
	// standard provider's when it says (GitHub's refresh_token_expires_in).
	// Past it a refresh cannot work, and the person is told to connect
	// again, with the date, rather than the provider being asked.
	RefreshExpiry time.Time `json:"refresh_expiry,omitempty"`
	// Renew is when a token of Meta's is renewed although it has not
	// expired. Meta renews a long-lived token only by exchanging it, once
	// it is a day old and never once it has expired, so a token kept until
	// it was about to expire would be one failed renewal from somebody
	// having to connect again.
	Renew time.Time `json:"renew,omitempty"`
}

// Ends is when a connection's tokens end, as far as the provider said.
//
// Nothing in it is secret, so it is kept beside the sealed tokens and shown
// to the person whose connection it is. Kept only inside them, it was shown
// nowhere: a connection simply stopped working one day (an Instagram token
// sixty days old, a LinkedIn refresh token a year old), and the first
// anybody heard of it was a post that failed. A zero time is one not known:
// the provider did not say, or the connection was kept before this was.
type Ends struct {
	Access  time.Time `json:"access_expires,omitzero"`
	Refresh time.Time `json:"refresh_expires,omitzero"`
	// Renews says it has a refresh token, so the access token's end is
	// not the connection's.
	Renews bool `json:"renews,omitempty"`
}

// Ends is when the tokens end.
func (t Token) Ends() Ends {
	return Ends{Access: t.Expiry, Refresh: t.RefreshExpiry, Renews: t.Refresh != ""}
}

// ExpiryNotice is how long before a connection stops working its person
// is told to connect it again.
const ExpiryNotice = 7 * 24 * time.Hour

// Lapses is when the connection stops working unless its person connects
// it again: the refresh token's end when it renews, or else the access
// token's. Zero is not known.
func (e Ends) Lapses() time.Time {
	if e.Renews {
		return e.Refresh
	}
	return e.Access
}

// LapsesSoon reports whether the connection stops working within
// ExpiryNotice of now, or already has.
func (e Ends) LapsesSoon(now time.Time) bool {
	at := e.Lapses()
	return !at.IsZero() && at.Before(now.Add(ExpiryNotice))
}

// Said is when the tokens end, in words, with times in loc: the same on
// Your accounts and in quilzo connect list.
func (e Ends) Said(loc *time.Location) string {
	access := "access token: end not known"
	if !e.Access.IsZero() {
		access = "access token until " + e.Access.In(loc).Format("2 Jan 2006 15:04 MST")
		if e.Renews {
			access += ", renewed when due"
		}
	}
	var refresh string
	switch {
	case e.Renews && !e.Refresh.IsZero():
		refresh = "refresh token until " + e.Refresh.In(loc).Format("2 Jan 2006")
	case e.Renews:
		refresh = "refresh token: end not known"
	case !e.Access.IsZero():
		refresh = "no refresh token: connect it again when access ends"
	default:
		refresh = "refresh token: not known"
	}
	return access + "; " + refresh
}

// Due reports whether the token is refreshed before it is used: its
// access token is expired or will be within a minute (refreshed before,
// not after, a call fails with it), or it has come to the time its
// dialect renews it at.
func (t Token) Due(now time.Time) bool {
	return t.Lapsing(now) || (!t.Renew.IsZero() && !now.Before(t.Renew))
}

// Lapsing reports whether the access token is expired, or will be within
// a minute. A token that is only due to be renewed is not lapsing: when
// its renewal fails it still works, and is used as it is.
func (t Token) Lapsing(now time.Time) bool {
	return !t.Expiry.IsZero() && now.Add(time.Minute).After(t.Expiry)
}

// Poster sends a form to a token endpoint and returns its body, whatever
// its status: OAuth's errors are a 400 with the reason inside.
type Poster func(ctx context.Context, url string, form url.Values) ([]byte, error)

// Exchange trades a code for tokens, with the verifier the challenge
// committed to. For Meta, the token the code buys lasts an hour, and is
// traded at once for one that lasts sixty days: kept as it came, every
// connection lapsed within the hour.
func Exchange(ctx context.Context, post Poster, get Getter, p Provider, secret string, pd Pending, code string,
	now time.Time) (Token, error) {
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
		p.clientParam(): {p.ClientID}}
	if p.pkce() {
		form.Set("code_verifier", pd.Verifier)
	}
	if p.Resource != "" {
		form.Set("resource", p.Resource)
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	t, err := token(ctx, post, p, form, Token{}, now)
	if err != nil || !p.meta() {
		return t, err
	}
	q := url.Values{"client_secret": {secret}}
	if p.dialect() == MetaInstagram {
		q.Set("grant_type", "ig_exchange_token")
		q.Set("access_token", t.Access)
	} else {
		q.Set("grant_type", "fb_exchange_token")
		q.Set(p.clientParam(), p.ClientID)
		q.Set("fb_exchange_token", t.Access)
	}
	long, err := exchange(ctx, get, p, p.exchangeURL(), q, t, now)
	if err != nil {
		return Token{}, fmt.Errorf("%s gave a token for an hour and did not exchange it for a lasting one: %w", p.Title, err)
	}
	return long, nil
}

// Refresh trades the refresh token of old for new tokens. A provider that
// rotates refresh tokens sends a new one, which replaces the old; one that
// does not keeps the old. Meta's dialects, which issue none, renew the
// access token itself.
func Refresh(ctx context.Context, post Poster, get Getter, p Provider, secret string, old Token, now time.Time) (Token, error) {
	if p.meta() {
		return renew(ctx, get, p, secret, old, now)
	}
	if old.Refresh == "" {
		if p.dialect() == LinkedIn {
			return Token{}, errors.New("LinkedIn issues refresh tokens only to the apps it has approved for them, " +
				"and gave this connection none: connect again")
		}
		return Token{}, errors.New("the connection has no refresh token: connect again")
	}
	if !old.RefreshExpiry.IsZero() && !now.Before(old.RefreshExpiry) {
		return Token{}, fmt.Errorf("the connection's refresh token lapsed on %s: connect again",
			old.RefreshExpiry.Format("2 Jan 2006"))
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {old.Refresh}, p.clientParam(): {p.ClientID}}
	if p.Resource != "" {
		form.Set("resource", p.Resource)
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	return token(ctx, post, p, form, old, now)
}

// renew renews a token of Meta's by exchanging it, which Meta allows once
// it is a day old and only before it expires.
func renew(ctx context.Context, get Getter, p Provider, secret string, old Token, now time.Time) (Token, error) {
	if old.Access == "" {
		return Token{}, errors.New("the connection has no token to renew: connect again")
	}
	if !old.Expiry.IsZero() && !now.Before(old.Expiry) {
		return Token{}, fmt.Errorf("the connection's token lapsed on %s, and %s renews a token only before it does: connect again",
			old.Expiry.Format("2 Jan 2006"), p.Title)
	}
	q := url.Values{}
	if p.dialect() == MetaInstagram {
		q.Set("grant_type", "ig_refresh_token")
		q.Set("access_token", old.Access)
	} else {
		q.Set("grant_type", "fb_exchange_token")
		q.Set(p.clientParam(), p.ClientID)
		q.Set("client_secret", secret)
		q.Set("fb_exchange_token", old.Access)
	}
	return exchange(ctx, get, p, p.renewURL(), q, old, now)
}

// exchange asks one of Meta's exchange addresses for a long-lived token
// in place of old, and says when to renew what comes back: a day on.
// Meta exchanges and renews its tokens with a GET, the client secret and
// the token in its query, and documents no other way; only its dialects
// are given one to make.
func exchange(ctx context.Context, get Getter, p Provider, endpoint string, q url.Values, old Token, now time.Time) (Token, error) {
	if get == nil {
		return Token{}, fmt.Errorf("%s exchanges its tokens with a GET, and nothing here was given to make one", p.Title)
	}
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	// Meta's refusals are a 400 with the reason inside, so the status is
	// left to the answer to say.
	_, _, body, err := get(ctx, endpoint+sep+q.Encode())
	if err != nil {
		// The address carries the client secret and the token, and Go's
		// errors quote an address whole: said as it came, the error would
		// carry them into the audit log and onto the screen.
		return Token{}, fmt.Errorf("%s's token exchange: %s", p.Title, clip(redact(err.Error(), q), 300))
	}
	t, err := answer(p, body, old, now)
	if err != nil {
		return Token{}, err
	}
	if t.Scope == "" {
		t.Scope = old.Scope
	}
	t.Renew = now.Add(24 * time.Hour).UTC()
	return t, nil
}

// redact takes the secret values of a query, as they are and as they are
// escaped in an address, out of a message about it.
func redact(msg string, q url.Values) string {
	for _, k := range []string{"client_secret", "access_token", "fb_exchange_token"} {
		if v := q.Get(k); v != "" {
			msg = strings.ReplaceAll(strings.ReplaceAll(msg, url.QueryEscape(v), "[redacted]"), v, "[redacted]")
		}
	}
	return msg
}

func token(ctx context.Context, post Poster, p Provider, form url.Values, old Token, now time.Time) (Token, error) {
	body, err := post(ctx, p.TokenURL, form)
	if err != nil {
		return Token{}, fmt.Errorf("%s's token endpoint: %w", p.Title, err)
	}
	return answer(p, body, old, now)
}

// answer reads what a provider answered with tokens in, in its dialect;
// old is the token it replaces, whose refresh token is kept when the
// answer has none.
func answer(p Provider, body []byte, old Token, now time.Time) (Token, error) {
	if p.dialect() == MetaInstagram {
		// Instagram's login answers a code inside a list.
		var wrapped struct {
			Data []json.RawMessage `json:"data"`
		}
		if json.Unmarshal(body, &wrapped) == nil && len(wrapped.Data) == 1 {
			body = wrapped.Data[0]
		}
	}
	var out struct {
		Access    string `json:"access_token"`
		Type      string `json:"token_type"`
		ExpiresIn int64  `json:"expires_in"`
		Refresh   string `json:"refresh_token"`
		Scope     string `json:"scope"`
		// Error is a string in OAuth 2 and an object in Meta's Graph API.
		Error json.RawMessage `json:"error"`
		Desc  string          `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return Token{}, fmt.Errorf("%s's token endpoint did not answer in JSON", p.Title)
	}
	if why := refusal(p, body, out.Error, out.Desc); why != "" {
		return Token{}, fmt.Errorf("%s refused: %s", p.Title, why)
	}
	if out.Access == "" || len(out.Access) > 16<<10 {
		return Token{}, fmt.Errorf("%s sent no access token", p.Title)
	}
	if out.Type != "" && !strings.EqualFold(out.Type, "bearer") {
		return Token{}, fmt.Errorf("%s sent a %q token, and this sends bearer tokens only", p.Title, clip(out.Type, 20))
	}
	t := Token{Access: out.Access, Refresh: out.Refresh, Scope: clip(out.Scope, 2000)}
	if t.Refresh == "" {
		t.Refresh = old.Refresh
	}
	if out.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(out.ExpiresIn) * time.Second).UTC()
	}
	// What each dialect says beside the standard's fields is read for that
	// dialect alone: the same refresh_token_expires_in is a standard
	// provider's lifetime for its refresh token (GitHub's), but under
	// LinkedIn's year from the first issue only a nearer end, never a new
	// year.
	var extra struct {
		// The refresh token's lifetime, by the two names providers send it
		// under: TikTok's, and LinkedIn's and GitHub's.
		RefreshIn      int64           `json:"refresh_expires_in"`
		RefreshTokenIn int64           `json:"refresh_token_expires_in"`
		Permissions    json.RawMessage `json:"permissions"`
	}
	_ = json.Unmarshal(body, &extra)
	switch p.dialect() {
	case TikTok:
		t.RefreshExpiry = old.RefreshExpiry
		if extra.RefreshIn > 0 {
			t.RefreshExpiry = now.Add(time.Duration(extra.RefreshIn) * time.Second).UTC()
		}
	case LinkedIn:
		// A year from the first issue, and never later: LinkedIn counts
		// down from then, and a refresh does not start it again.
		if t.Refresh != "" {
			at := old.RefreshExpiry
			if at.IsZero() {
				at = now.Add(365 * 24 * time.Hour).UTC()
			}
			if extra.RefreshTokenIn > 0 {
				if said := now.Add(time.Duration(extra.RefreshTokenIn) * time.Second).UTC(); said.Before(at) {
					at = said
				}
			}
			t.RefreshExpiry = at
		}
	case MetaInstagram:
		if t.Scope == "" {
			t.Scope = clip(permissions(extra.Permissions), 2000)
		}
	case OAuth2:
		// The standard says nothing of when a refresh token lapses; a
		// provider that does (GitHub's refresh_token_expires_in, or
		// refresh_expires_in) is taken at its word. A refresh that keeps
		// the refresh token and says nothing of its end leaves it zero
		// here, and the caller that keeps the token keeps the end it knew.
		if in := max(extra.RefreshTokenIn, extra.RefreshIn); in > 0 && t.Refresh != "" {
			t.RefreshExpiry = now.Add(time.Duration(in) * time.Second).UTC()
		}
	}
	return t, nil
}

// refusal is why a provider refused, in whichever shape its dialect says
// it, or empty: OAuth 2's error and error_description; the Graph API's
// error object, {"message", "type"}; Instagram's login's error_type and
// error_message.
func refusal(p Provider, body []byte, raw json.RawMessage, desc string) string {
	if len(raw) > 0 && string(raw) != "null" {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			if s != "" {
				return clip(s, 60) + " " + clip(desc, 200)
			}
		} else {
			var obj struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			}
			_ = json.Unmarshal(raw, &obj)
			return strings.TrimSpace(clip(obj.Type, 60) + " " + clip(cmp.Or(obj.Message, string(raw)), 200))
		}
	}
	if p.meta() {
		var ig struct {
			Type    string `json:"error_type"`
			Message string `json:"error_message"`
		}
		if json.Unmarshal(body, &ig) == nil && (ig.Type != "" || ig.Message != "") {
			return strings.TrimSpace(clip(ig.Type, 60) + " " + clip(ig.Message, 200))
		}
	}
	return ""
}

// permissions is Instagram's list of what was granted, which it sends as
// one string or as a list, as a scope.
func permissions(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return strings.Join(list, ",")
	}
	return ""
}

// Revoke asks the provider to forget a token (RFC 7009), where it offers
// that; a provider that does not is told nothing, and the token is only
// forgotten here.
func Revoke(ctx context.Context, post Poster, p Provider, secret, tok string) error {
	if p.RevokeURL == "" || tok == "" {
		return nil
	}
	form := url.Values{"token": {tok}, p.clientParam(): {p.ClientID}}
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
	return plaintext.Clip(s, n, "")
}
