// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package oauthas

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/auth"
)

// Grant is one person's consent for one app.
type Grant struct {
	ID         string    `json:"id"`
	Principal  string    `json:"principal"`
	Client     string    `json:"client"`
	ClientName string    `json:"client_name"`
	Scopes     []string  `json:"scopes"`
	Resource   string    `json:"resource"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	LastUsed   time.Time `json:"last_used,omitzero"`
	// Vouched says the person agreed in a session a passkey or single
	// sign-on proved, which is what a lockdown lets through.
	Vouched bool `json:"vouched,omitempty"`
	// Refresh is the hash of the refresh token in force; Spent are the
	// hashes of ones already rotated away, kept to recognise a copy.
	Refresh string   `json:"refresh"`
	Spent   []string `json:"spent,omitempty"`
	// Ended is when it was revoked or ended, why, and by whom.
	Ended    time.Time `json:"ended,omitzero"`
	EndedBy  string    `json:"ended_by,omitempty"`
	EndedWhy string    `json:"ended_why,omitempty"`
}

// Live reports whether the grant may still be used.
func (g Grant) Live(now time.Time) bool { return g.Ended.IsZero() && now.Before(g.Expires) }

// Store is the grants and registered clients, kept under root/oauth.
type Store struct {
	Dir string
	mu  sync.Mutex
}

type grantsFile struct {
	Grants []Grant `json:"grants"`
}

type clientsFile struct {
	Clients []Client `json:"clients"`
	// Hosts are the hosts whose apps may connect by metadata document.
	Hosts []string `json:"hosts,omitempty"`
}

const (
	maxGrants = 10000
	maxSpent  = 20
	keepEnded = 30 * 24 * time.Hour
)

func (s *Store) read(name string, v any) error {
	b, err := os.ReadFile(filepath.Join(s.Dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func (s *Store) write(name string, v any) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(s.Dir, name), b, 0o600)
}

// Grants lists them all.
func (s *Store) Grants() ([]Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f grantsFile
	err := s.read("grants.json", &f)
	return f.Grants, err
}

func (s *Store) changeGrants(now time.Time, fn func(*grantsFile) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f grantsFile
	if err := s.read("grants.json", &f); err != nil {
		return err
	}
	if err := fn(&f); err != nil {
		return err
	}
	kept := f.Grants[:0]
	for _, g := range f.Grants {
		end := g.Ended
		if end.IsZero() && now.After(g.Expires) {
			end = g.Expires
		}
		if !end.IsZero() && now.Sub(end) > keepEnded {
			continue // forgotten a month after it ended; the audit log keeps it
		}
		kept = append(kept, g)
	}
	f.Grants = kept
	return s.write("grants.json", &f)
}

// Clients lists the registered clients and the allowed hosts.
func (s *Store) Clients() ([]Client, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f clientsFile
	err := s.read("clients.json", &f)
	return f.Clients, f.Hosts, err
}

// ChangeClients changes the registered clients and allowed hosts.
func (s *Store) ChangeClients(fn func(clients *[]Client, hosts *[]string) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f clientsFile
	if err := s.read("clients.json", &f); err != nil {
		return err
	}
	if err := fn(&f.Clients, &f.Hosts); err != nil {
		return err
	}
	return s.write("clients.json", &f)
}

// CheckHost checks a host an administrator wants to allow.
func CheckHost(h string) error {
	if h == "*" {
		return nil
	}
	if h == "" || len(h) > 253 || strings.ToLower(h) != h || strings.ContainsAny(h, "/?#@ \t") {
		return fmt.Errorf("%q is not a host like claude.ai or app.example.com", h)
	}
	if _, err := url.Parse("https://" + h + "/x"); err != nil {
		return fmt.Errorf("%q is not a host", h)
	}
	return nil
}

// Tokens is where access tokens are issued and revoked.
type Tokens interface {
	Issue(g Grant, role auth.Role, ttl time.Duration, now time.Time) (string, error)
	RevokeGrant(id string) error
}

// Server is the authorization server.
type Server struct {
	Config    func() Config
	Store     *Store
	Directory *Directory
	Tokens    Tokens
	// Admit is asked before tokens are issued from a grant, so a lockdown
	// stops a connected app refreshing its way past it.
	Admit func(g Grant, now time.Time) error
	// Record writes to the audit log.
	Record func(action, principal string, detail map[string]string)
	Now    func() time.Time

	mu      sync.Mutex
	pending map[string]*Pending
	codes   map[string]*issuedCode
	used    map[string]usedCode
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) record(action, principal string, detail map[string]string) {
	if s.Record != nil {
		s.Record(action, principal, detail)
	}
}

// Request is a validated authorization request.
type Request struct {
	Client      Client
	RedirectURI string
	State       string
	Challenge   string
	Scopes      []string
	Resource    string
}

// Pending is a request a person is looking at.
type Pending struct {
	ID        string
	Request   Request
	Principal string
	Until     time.Time
}

type issuedCode struct {
	grant     Grant
	redirect  string
	challenge string
	until     time.Time
}

type usedCode struct {
	grant string
	until time.Time
}

// AuthError is a request that cannot be sent back to the app, because
// where to send it is the thing that failed. It is shown to the person.
type AuthError struct{ Why string }

func (e *AuthError) Error() string { return e.Why }

// RedirectError is one the app is told about at its redirect address.
type RedirectError struct {
	Redirect, State, Code, Description string
}

func (e *RedirectError) Error() string { return e.Description }

// Parse validates an authorization request, in the order that keeps a bad
// redirect address from ever receiving anything.
func (s *Server) Parse(ctx context.Context, q url.Values) (Request, error) {
	cfg := s.Config()
	for _, k := range []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "scope", "resource"} {
		if len(q[k]) > 1 {
			return Request{}, &AuthError{Why: fmt.Sprintf("%s was given more than once", k)}
		}
	}
	id := q.Get("client_id")
	if id == "" {
		return Request{}, &AuthError{Why: "the app did not say who it is (client_id)"}
	}
	client, err := s.Directory.Resolve(ctx, cfg, id, s.now())
	if err != nil {
		return Request{}, err
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" || !RedirectMatches(client.RedirectURIs, redirect) {
		return Request{}, &AuthError{Why: "the address the app asked to return to is not one it registered"}
	}
	state := q.Get("state")
	fail := func(code, why string) (Request, error) {
		return Request{}, &RedirectError{Redirect: redirect, State: state, Code: code, Description: why}
	}
	if len(state) > 512 {
		return fail("invalid_request", "state is longer than 512 characters")
	}
	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "only response_type=code is offered")
	}
	challenge := q.Get("code_challenge")
	if q.Get("code_challenge_method") != "S256" || !validChallenge(challenge) {
		return fail("invalid_request", "PKCE with S256 is required: code_challenge and code_challenge_method=S256")
	}
	resource := q.Get("resource")
	if resource == "" || !cfg.SameResource(resource) {
		return fail("invalid_target", "resource must name this server's agent interface, "+cfg.Resource())
	}
	scopes, err := normScopes(q.Get("scope"))
	if err != nil {
		return fail("invalid_scope", err.Error())
	}
	if len(scopes) == 0 {
		scopes = []string{DefaultScope}
	}
	return Request{Client: client, RedirectURI: redirect, State: state, Challenge: challenge,
		Scopes: scopes, Resource: cfg.Resource()}, nil
}

func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		ch := v[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || strings.IndexByte("-._~", ch) >= 0) {
			return false
		}
	}
	return true
}

// Hold keeps a validated request for the person deciding, bound to them.
func (s *Server) Hold(req Request, principal string) (*Pending, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = map[string]*Pending{}
	}
	for k, p := range s.pending {
		if now.After(p.Until) {
			delete(s.pending, k)
		}
	}
	if len(s.pending) >= 1000 {
		return nil, errors.New("too many sign-ins for apps are waiting; try again in a few minutes")
	}
	p := &Pending{ID: newID("ar_"), Request: req, Principal: principal, Until: now.Add(pendingTTL)}
	s.pending[p.ID] = p
	return p, nil
}

// Take returns a held request, once, to the person it was held for.
func (s *Server) Take(id, principal string) (*Pending, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok || now.After(p.Until) {
		delete(s.pending, id)
		return nil, &AuthError{Why: "that request has expired; start again from the app"}
	}
	// Used once, whoever uses it: a request that reaches somebody other
	// than the person it was shown to has been passed around, and is not
	// left for anybody to finish.
	delete(s.pending, id)
	if p.Principal != principal {
		return nil, &AuthError{Why: "that request was shown to somebody else"}
	}
	return p, nil
}

// Approve records the person's consent and returns where to send them: the
// app's redirect address with a code.
func (s *Server) Approve(p *Pending, scopes []string, vouched bool) (string, error) {
	now := s.now()
	cfg := s.Config()
	g := Grant{ID: newID("gr_"), Principal: p.Principal, Client: p.Request.Client.ID,
		ClientName: p.Request.Client.Name, Scopes: scopes, Resource: p.Request.Resource,
		Created: now, Expires: now.Add(cfg.grantTTL()), Vouched: vouched}
	code, err := newSecret("qzac_")
	if err != nil {
		return "", err
	}
	// The grant is written when the code is redeemed: a code never used
	// leaves nothing behind but this line.
	s.mu.Lock()
	if s.codes == nil {
		s.codes = map[string]*issuedCode{}
	}
	for k, c := range s.codes {
		if now.After(c.until) {
			delete(s.codes, k)
		}
	}
	if len(s.codes) >= 1000 {
		s.mu.Unlock()
		return "", errors.New("too many sign-ins for apps are in progress; try again in a minute")
	}
	s.codes[hashOf(code)] = &issuedCode{grant: g, redirect: p.Request.RedirectURI,
		challenge: p.Request.Challenge, until: now.Add(codeTTL)}
	s.mu.Unlock()
	s.record("oauth.consent", p.Principal, map[string]string{"client": g.Client, "app": g.ClientName,
		"scopes": strings.Join(scopes, " "), "redirect": p.Request.RedirectURI})
	return withParams(p.Request.RedirectURI, url.Values{"code": {code}, "state": nonEmpty(p.Request.State), "iss": {cfg.Issuer}}), nil
}

// Deny returns where to send a person who said no.
func (s *Server) Deny(p *Pending) string {
	s.record("oauth.declined", p.Principal, map[string]string{"client": p.Request.Client.ID, "app": p.Request.Client.Name})
	return ErrorRedirect(&RedirectError{Redirect: p.Request.RedirectURI, State: p.Request.State,
		Code: "access_denied", Description: "the person declined"}, s.Config().Issuer)
}

// ErrorRedirect is where an app is told a request failed.
func ErrorRedirect(e *RedirectError, issuer string) string {
	return withParams(e.Redirect, url.Values{"error": {e.Code}, "error_description": {e.Description},
		"state": nonEmpty(e.State), "iss": {issuer}})
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func withParams(base string, add url.Values) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for k, vs := range add {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// tokenError is an RFC 6749 error from the token endpoint.
type tokenError struct {
	status      int
	code, about string
}

func (e *tokenError) Error() string { return e.about }

func badRequest(code, about string) *tokenError {
	return &tokenError{status: http.StatusBadRequest, code: code, about: about}
}

// Token is the token endpoint.
func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	if r.Method != http.MethodPost {
		h.Set("Allow", "POST")
		writeTokenError(w, &tokenError{status: http.StatusMethodNotAllowed, code: "invalid_request", about: "POST only"})
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		writeTokenError(w, badRequest("invalid_request", "the body is application/x-www-form-urlencoded"))
		return
	}
	if r.Header.Get("Authorization") != "" {
		// No client here has a secret; one presented is a client
		// configured for another server.
		writeTokenError(w, &tokenError{status: http.StatusUnauthorized, code: "invalid_client", about: "clients here are public and present no credentials"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, badRequest("invalid_request", "the body could not be read"))
		return
	}
	if len(r.URL.RawQuery) > 0 {
		writeTokenError(w, badRequest("invalid_request", "parameters go in the body, not the address"))
		return
	}
	for k, v := range r.PostForm {
		if len(v) > 1 {
			writeTokenError(w, badRequest("invalid_request", k+" was given more than once"))
			return
		}
	}
	var resp map[string]any
	var err error
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		resp, err = s.redeem(r.PostForm)
	case "refresh_token":
		resp, err = s.refresh(r.PostForm)
	default:
		err = badRequest("unsupported_grant_type", "the grant types are authorization_code and refresh_token")
	}
	if err != nil {
		var te *tokenError
		if !errors.As(err, &te) {
			te = &tokenError{status: http.StatusInternalServerError, code: "server_error", about: err.Error()}
		}
		writeTokenError(w, te)
		return
	}
	h.Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeTokenError(w http.ResponseWriter, e *tokenError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e.code, "error_description": e.about})
}

func (s *Server) redeem(f url.Values) (map[string]any, error) {
	now := s.now()
	code := f.Get("code")
	key := hashOf(code)
	s.mu.Lock()
	c, ok := s.codes[key]
	delete(s.codes, key)
	if !ok {
		if u, seen := s.used[key]; seen && now.Before(u.until) {
			// A code redeemed twice: the second is a copy, and the tokens
			// the first got are no safer than the code was.
			s.mu.Unlock()
			s.end(u.grant, "", "an authorization code was used twice")
			return nil, badRequest("invalid_grant", "that code was already used")
		}
		s.mu.Unlock()
		return nil, badRequest("invalid_grant", "the code is unknown or has expired")
	}
	if s.used == nil {
		s.used = map[string]usedCode{}
	}
	for k, u := range s.used {
		if now.After(u.until) {
			delete(s.used, k)
		}
	}
	s.used[key] = usedCode{grant: c.grant.ID, until: now.Add(10 * time.Minute)}
	s.mu.Unlock()

	if now.After(c.until) {
		return nil, badRequest("invalid_grant", "the code has expired")
	}
	if f.Get("client_id") != c.grant.Client {
		return nil, badRequest("invalid_grant", "the code was issued to another app")
	}
	if f.Get("redirect_uri") != c.redirect {
		return nil, badRequest("invalid_grant", "redirect_uri is not the one the code was issued for")
	}
	if res := f.Get("resource"); res != "" && !s.Config().SameResource(res) {
		return nil, badRequest("invalid_target", "resource is not this server's agent interface")
	}
	verifier := f.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if !validVerifier(verifier) ||
		subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(c.challenge)) != 1 {
		return nil, badRequest("invalid_grant", "code_verifier does not match the code_challenge")
	}
	g := c.grant
	if s.Admit != nil {
		if err := s.Admit(g, now); err != nil {
			return nil, badRequest("invalid_grant", err.Error())
		}
	}
	refresh, err := newSecret("qzrt_")
	if err != nil {
		return nil, err
	}
	g.Refresh, g.LastUsed = hashOf(refresh), now
	err = s.Store.changeGrants(now, func(f *grantsFile) error {
		// A new consent replaces the person's earlier one for the app.
		for i := range f.Grants {
			old := &f.Grants[i]
			if old.Principal == g.Principal && old.Client == g.Client && old.Ended.IsZero() {
				old.Ended, old.EndedBy, old.EndedWhy = now, g.Principal, "replaced by a new consent"
				if s.Tokens != nil {
					_ = s.Tokens.RevokeGrant(old.ID)
				}
			}
		}
		live := 0
		for _, x := range f.Grants {
			if x.Live(now) {
				live++
			}
		}
		if live >= maxGrants {
			return &tokenError{status: http.StatusServiceUnavailable, code: "temporarily_unavailable", about: "too many apps are connected"}
		}
		f.Grants = append(f.Grants, g)
		return nil
	})
	if err != nil {
		return nil, err
	}
	access, err := s.issue(g, now)
	if err != nil {
		return nil, err
	}
	s.record("oauth.connected", g.Principal, map[string]string{"client": g.Client, "app": g.ClientName,
		"grant": g.ID, "scopes": strings.Join(g.Scopes, " ")})
	return s.tokenResponse(g, access, refresh), nil
}

func (s *Server) issue(g Grant, now time.Time) (string, error) {
	if s.Tokens == nil {
		return "", errors.New("no token store")
	}
	return s.Tokens.Issue(g, RoleFor(g.Scopes), s.Config().accessTTL(), now)
}

func (s *Server) tokenResponse(g Grant, access, refresh string) map[string]any {
	return map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(s.Config().accessTTL().Seconds()),
		"refresh_token": refresh,
		"scope":         strings.Join(g.Scopes, " "),
	}
}

func (s *Server) refresh(f url.Values) (map[string]any, error) {
	now := s.now()
	presented := hashOf(f.Get("refresh_token"))
	clientID := f.Get("client_id")
	var out Grant
	var refresh string
	var reused string
	err := s.Store.changeGrants(now, func(file *grantsFile) error {
		for i := range file.Grants {
			g := &file.Grants[i]
			for _, spent := range g.Spent {
				if subtle.ConstantTimeCompare([]byte(spent), []byte(presented)) == 1 && g.Ended.IsZero() {
					// A rotated refresh token used again: either the app or a
					// thief has a copy, and nobody can tell which. The grant
					// ends; the person connects the app again.
					g.Ended, g.EndedBy, g.EndedWhy = now, "", "a refresh token was used twice"
					reused = g.ID
					return nil
				}
			}
			if subtle.ConstantTimeCompare([]byte(g.Refresh), []byte(presented)) != 1 {
				continue
			}
			if !g.Live(now) {
				return badRequest("invalid_grant", "this connection has ended; connect the app again")
			}
			if clientID != g.Client {
				return badRequest("invalid_grant", "the refresh token was issued to another app")
			}
			if res := f.Get("resource"); res != "" && !s.Config().SameResource(res) {
				return badRequest("invalid_target", "resource is not this server's agent interface")
			}
			if sc := f.Get("scope"); sc != "" {
				asked, err := normScopes(sc)
				if err != nil {
					return badRequest("invalid_scope", err.Error())
				}
				for _, a := range asked {
					if !contains(g.Scopes, a) {
						return badRequest("invalid_scope", "a refresh cannot add "+a+"; the person has to agree to it")
					}
				}
				g.Scopes = asked
			}
			if s.Admit != nil {
				if err := s.Admit(*g, now); err != nil {
					return badRequest("invalid_grant", err.Error())
				}
			}
			next, err := newSecret("qzrt_")
			if err != nil {
				return err
			}
			g.Spent = append(g.Spent, g.Refresh)
			if len(g.Spent) > maxSpent {
				g.Spent = g.Spent[len(g.Spent)-maxSpent:]
			}
			g.Refresh, g.LastUsed = hashOf(next), now
			out, refresh = *g, next
			return nil
		}
		return badRequest("invalid_grant", "the refresh token is unknown")
	})
	if reused != "" {
		if s.Tokens != nil {
			_ = s.Tokens.RevokeGrant(reused)
		}
		s.record("oauth.refresh-reused", "", map[string]string{"grant": reused})
		return nil, badRequest("invalid_grant", "that refresh token was already used; connect the app again")
	}
	if err != nil {
		return nil, err
	}
	access, err := s.issue(out, now)
	if err != nil {
		return nil, err
	}
	return s.tokenResponse(out, access, refresh), nil
}

// Revoke is the revocation endpoint (RFC 7009): a refresh token ends its
// grant. It answers 200 whatever it was given, as the RFC asks, so it says
// nothing about which tokens exist.
func (s *Server) Revoke(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, badRequest("invalid_request", "the body could not be read"))
		return
	}
	presented := hashOf(r.PostForm.Get("token"))
	client := r.PostForm.Get("client_id")
	var grant Grant
	_ = s.Store.changeGrants(s.now(), func(f *grantsFile) error {
		for i := range f.Grants {
			g := &f.Grants[i]
			if g.Client == client && g.Ended.IsZero() && subtle.ConstantTimeCompare([]byte(g.Refresh), []byte(presented)) == 1 {
				g.Ended, g.EndedBy, g.EndedWhy = s.now(), "app", "the app disconnected"
				grant = *g
			}
		}
		return nil
	})
	if grant.ID != "" {
		if s.Tokens != nil {
			_ = s.Tokens.RevokeGrant(grant.ID)
		}
		s.record("oauth.disconnected", grant.Principal, map[string]string{"client": grant.Client, "grant": grant.ID, "by": "app"})
	}
	w.WriteHeader(http.StatusOK)
}

// End ends a grant: a person disconnecting an app, or an administrator.
func (s *Server) End(id, by, why string) error {
	if !s.end(id, by, why) {
		return fmt.Errorf("no connection %s is in force", id)
	}
	return nil
}

func (s *Server) end(id, by, why string) bool {
	now := s.now()
	var g Grant
	_ = s.Store.changeGrants(now, func(f *grantsFile) error {
		for i := range f.Grants {
			if f.Grants[i].ID == id && f.Grants[i].Ended.IsZero() {
				f.Grants[i].Ended, f.Grants[i].EndedBy, f.Grants[i].EndedWhy = now, by, why
				g = f.Grants[i]
			}
		}
		return nil
	})
	if g.ID == "" {
		return false
	}
	if s.Tokens != nil {
		_ = s.Tokens.RevokeGrant(g.ID)
	}
	s.record("oauth.disconnected", g.Principal, map[string]string{"client": g.Client, "grant": g.ID, "by": by, "why": why})
	return true
}

// EndWhere ends every grant in force that match chooses: an app removed
// from the register, or a host no longer allowed, takes its connections
// with it.
func (s *Server) EndWhere(match func(Grant) bool, by, why string) int {
	now := s.now()
	var ended []Grant
	_ = s.Store.changeGrants(now, func(f *grantsFile) error {
		for i := range f.Grants {
			g := &f.Grants[i]
			if g.Live(now) && match(*g) {
				g.Ended, g.EndedBy, g.EndedWhy = now, by, why
				ended = append(ended, *g)
			}
		}
		return nil
	})
	for _, g := range ended {
		if s.Tokens != nil {
			_ = s.Tokens.RevokeGrant(g.ID)
		}
		s.record("oauth.disconnected", g.Principal, map[string]string{"client": g.Client, "grant": g.ID, "by": by, "why": why})
	}
	return len(ended)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
