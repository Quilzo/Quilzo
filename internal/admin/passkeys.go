package admin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/webauthn"
)

// Passkeys in an admin that serves no script.
//
// # The tension, stated first
//
// This program's Content-Security-Policy is `default-src 'none'`, and a test
// asserts that nothing executes. WebAuthn is a JavaScript API: there is no way
// to reach an authenticator from a form post, and there will not be one. So
// either passkeys do not happen here, or the policy gains an exception.
//
// The exception is the one the API playground already established: a nonce,
// fresh per response, on one inline script. Not a host, not 'unsafe-inline',
// and not on any other page. An injected script has no nonce and cannot read
// this one, because it never runs to look.
//
// What the script is allowed to be is the other half. It calls
// navigator.credentials, posts the result back as JSON, and does nothing else:
// no library, no build step, no eval, no innerHTML. Every decision that
// matters is made by internal/webauthn on the server, where it can be tested
// without a browser.
//
// # Why bother
//
// The token this admin signs in with is a bearer string. Anybody who sees it
// is signed in — a shoulder, a shell history, a screen share, a pasted
// support ticket. A passkey cannot be read off a screen, cannot be sent to
// somebody by mistake, and cannot be phished onto another origin, because the
// browser will not offer it to another origin. That last property is the one
// no amount of care with a token buys.
//
// The token stays. A passkey needs a browser, and this program is also used
// from a terminal and from CI.

// Passkeys is the registered credential set.
type Passkeys struct {
	Credentials []StoredCredential `json:"credentials"`

	// Enrol is which authenticators may register. Zero constrains nothing.
	Enrol webauthn.Enrolment `json:"-"`

	// Save persists a change. Nil means passkeys are read-only, which is the
	// right behaviour for a deployment that mounts its state read-only rather
	// than a reason to fail a request.
	Save func(*Passkeys) error `json:"-"`

	mu         sync.Mutex
	challenges map[string]challenge
}

// StoredCredential is a passkey plus what this program needs to know about it.
type StoredCredential struct {
	webauthn.Credential
	// RelyingParty is the site identifier this was registered under, kept per
	// credential rather than read from the request at sign-in. A credential is
	// bound to one site, and deriving that binding from the request being
	// checked would let the request choose what it is checked against.
	RelyingParty string `json:"relying_party"`
}

// challenge is one outstanding ceremony.
type challenge struct {
	value     string
	principal string // empty for a sign-in, where nobody is known yet
	expires   time.Time
}

// issueChallenge mints one and remembers it.
//
// Server-side, single use, and expiring. A challenge kept in a cookie would be
// a challenge the client can replay at will, and the whole point of it is that
// the server chose it and has not seen the answer before.
func (p *Passkeys) issueChallenge(principal string, now time.Time) (string, error) {
	v, err := webauthn.NewChallenge()
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.challenges == nil {
		p.challenges = map[string]challenge{}
	}
	// Swept here rather than on a timer: the only thing that makes this map
	// grow is somebody starting ceremonies, so the work belongs to them.
	for k, c := range p.challenges {
		if now.After(c.expires) {
			delete(p.challenges, k)
		}
	}
	p.challenges[v] = challenge{
		value: v, principal: principal,
		expires: now.Add(webauthn.ChallengeLifetime),
	}
	return v, nil
}

// takeChallenge returns a challenge and removes it, so it answers once.
func (p *Passkeys) takeChallenge(v string, now time.Time) (challenge, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.challenges[v]
	if !ok {
		return challenge{}, false
	}
	delete(p.challenges, v)
	if now.After(c.expires) {
		return challenge{}, false
	}
	return c, true
}

// find returns the credential with this id.
func (p *Passkeys) find(id []byte) (int, bool) {
	for i, c := range p.Credentials {
		if len(c.ID) == len(id) && string(c.ID) == string(id) {
			return i, true
		}
	}
	return 0, false
}

// party describes this server as a relying party, derived from the request.
//
// Derived rather than configured because the admin does not otherwise know its
// own public address, and a wrong constant would be a passkey that registers
// and never works. It is safe to derive: the browser reports the origin it
// actually used, and an attacker who controls the Host header changes what
// this server expects without changing what the browser says, so the two stop
// matching and the ceremony is refused either way.
func partyFor(r *http.Request) (webauthn.Party, error) {
	host := r.Host
	if host == "" {
		return webauthn.Party{}, fmt.Errorf("this request names no host")
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// A browser will not run WebAuthn outside a secure context, and says so in
	// terms that do not mention the server. Caught here so the answer names
	// the actual reason.
	if scheme == "http" && !isLoopback(name) {
		return webauthn.Party{}, fmt.Errorf(
			"passkeys need HTTPS. This admin is served over plain HTTP at %s, "+
				"and a browser refuses the WebAuthn API outside a secure "+
				"context — localhost is the one exception, and this is not it",
			host)
	}
	// A relying party is a domain, and an address is not one.
	//
	// This is separate from the secure-context rule and catches what that rule
	// lets through: http://127.0.0.1 *is* a secure context, so the check above
	// is satisfied and everything looks fine — and then the browser answers
	// "This is an invalid domain" from inside navigator.credentials, where the
	// server never sees it and the page shows a button that does nothing.
	//
	// Found by driving a real browser at these routes. No amount of reading
	// the specification produced it, because the specification says a relying
	// party id is a valid domain string and does not say what a browser does
	// when you hand it an address instead.
	if net.ParseIP(name) != nil {
		return webauthn.Party{}, fmt.Errorf(
			"passkeys need a domain name and this admin is served at %s. A "+
				"browser refuses an address as a relying party, so the button "+
				"would fail silently — use http://localhost:%s instead, or a "+
				"hostname",
			host, portOf(host))
	}
	return webauthn.Party{ID: name, Origin: scheme + "://" + host}, nil
}

// portOf is the port from a host:port, for a message that suggests an
// alternative somebody can paste.
func portOf(host string) string {
	if _, port, err := net.SplitHostPort(host); err == nil {
		return port
	}
	return "8080"
}

func isLoopback(name string) bool {
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && ip.IsLoopback()
}

// -- routes -------------------------------------------------------------------

// handlePasskeys lists the registered keys and offers to add one.
func (s *Server) handlePasskeys(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if s.Passkeys == nil {
		s.passkeysUnavailable(w, r)
		return
	}

	n, err := nonce()
	if err != nil {
		http.Error(w, "no entropy", http.StatusInternalServerError)
		return
	}
	s.passkeyPolicy(w, n)

	var mine []StoredCredential
	for _, c := range s.Passkeys.Credentials {
		if c.Principal == who.Name {
			mine = append(mine, c)
		}
	}

	// Said on the page rather than discovered at the moment somebody presses
	// the button, because a browser's refusal here is silent and looks like
	// nothing happened.
	unavailable := ""
	if _, perr := partyFor(r); perr != nil {
		unavailable = perr.Error()
	}

	s.render(w, r, "passkeys.html", map[string]any{
		"Title": "Passkeys", "Nonce": n, "Keys": mine,
		"Unavailable": unavailable, "Who": who.Name,
	})
}

// passkeyPolicy sets the one policy in this program that permits a script.
func (s *Server) passkeyPolicy(w http.ResponseWriter, n string) {
	// manifest-src, because the shell links the web manifest on every screen
	// and this policy replaces the one that permitted it. Leaving it out
	// blocked the manifest on exactly these two pages -- the admin stayed
	// installable everywhere else and stopped being installable here, with a
	// console error nobody would see. Found by a browser, not by a test.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self'; img-src 'self' data:; "+
			"script-src 'nonce-"+n+"'; connect-src 'self'; "+
			"manifest-src 'self'; "+
			"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
}

// handlePasskeyChallenge starts a registration ceremony.
// enrolment is the deployment's policy on which authenticators may register.
//
// Nil is the default and constrains nothing, which is what most deployments
// want. A deployment at AAL3 sets it, and then a synced platform passkey --
// a key that exists in more than one place by design -- stops being enrolable.
func (s *Server) enrolment() webauthn.Enrolment {
	if s.Passkeys == nil {
		return webauthn.Enrolment{}
	}
	return s.Passkeys.Enrol
}

func (s *Server) handlePasskeyChallenge(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this is a ceremony endpoint and takes a POST",
			http.StatusMethodNotAllowed)
		return
	}
	if s.Passkeys == nil {
		writeJSONError(w, http.StatusServiceUnavailable, errNoPasskeyStore)
		return
	}
	party, err := partyFor(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	v, err := s.Passkeys.issueChallenge(who.Name, time.Now())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{
		"challenge": v,
		// What to ask the browser for. "none" unless a policy needs the
		// model, because the prompt about sharing information with the site
		// is one people learn to dismiss when it is shown for no reason.
		"attestation": s.enrolment().AttestationPreference(),
		"rp":          map[string]string{"id": party.ID, "name": s.SiteName},
		// The user handle is the principal, which is what this program calls
		// people everywhere else. It is not a secret and it is not an email.
		"user": map[string]string{
			"id":   base64.RawURLEncoding.EncodeToString([]byte(who.Name)),
			"name": who.Name, "displayName": who.Name,
		},
		"exclude": credentialIDs(s.Passkeys.Credentials, who.Name),
	})
}

// handlePasskeyRegister stores a new credential.
func (s *Server) handlePasskeyRegister(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this is a ceremony endpoint and takes a POST",
			http.StatusMethodNotAllowed)
		return
	}
	if s.Passkeys == nil {
		writeJSONError(w, http.StatusServiceUnavailable, errNoPasskeyStore)
		return
	}
	party, err := partyFor(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}

	var body struct {
		webauthn.Registration
		Challenge string `json:"challenge"`
		Label     string `json:"label"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}

	c, ok2 := s.Passkeys.takeChallenge(body.Challenge, time.Now())
	if !ok2 {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf(
			"this ceremony's challenge is unknown or has expired. Start again"))
		return
	}
	// The challenge was issued to somebody. Registering a key against a
	// challenge issued for another session would attach an attacker's
	// authenticator to somebody else's account.
	if c.principal != who.Name {
		writeJSONError(w, http.StatusForbidden, fmt.Errorf(
			"this challenge was issued to a different session"))
		return
	}

	party.Enrol = s.enrolment()
	cred, err := party.Register(c.value, body.Registration)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	cred.Principal = who.Name
	cred.Label = strings.TrimSpace(body.Label)
	if cred.Label == "" {
		cred.Label = "a passkey"
	}
	cred.CreatedAt = time.Now().Unix()

	if _, exists := s.Passkeys.find(cred.ID); exists {
		writeJSONError(w, http.StatusConflict, fmt.Errorf(
			"this key is already registered"))
		return
	}
	s.Passkeys.Credentials = append(s.Passkeys.Credentials,
		StoredCredential{Credential: cred, RelyingParty: party.ID})
	if err := s.savePasskeys(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// handlePasskeySignIn serves the sign-in page's script.
func (s *Server) handlePasskeySignIn(w http.ResponseWriter, r *http.Request) {
	if s.Passkeys == nil {
		s.passkeysUnavailable(w, r)
		return
	}
	n, err := nonce()
	if err != nil {
		http.Error(w, "no entropy", http.StatusInternalServerError)
		return
	}
	s.passkeyPolicy(w, n)

	unavailable := ""
	if _, perr := partyFor(r); perr != nil {
		unavailable = perr.Error()
	}
	s.render(w, r, "passkeysignin.html", map[string]any{
		"Title": "Sign in with a passkey", "Nonce": n,
		"Unavailable": unavailable,
	})
}

// handlePasskeySignInChallenge starts a sign-in ceremony.
//
// No principal, and no list of credentials to try. Naming which keys exist
// before anybody has proved anything tells a stranger who has an account here.
func (s *Server) handlePasskeySignInChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this is a ceremony endpoint and takes a POST",
			http.StatusMethodNotAllowed)
		return
	}
	if s.Passkeys == nil {
		writeJSONError(w, http.StatusServiceUnavailable, errNoPasskeyStore)
		return
	}
	party, err := partyFor(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	v, err := s.Passkeys.issueChallenge("", time.Now())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"challenge": v, "rpId": party.ID})
}

// handlePasskeyVerify completes a sign-in.
func (s *Server) handlePasskeyVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this is a ceremony endpoint and takes a POST",
			http.StatusMethodNotAllowed)
		return
	}
	if s.Passkeys == nil {
		writeJSONError(w, http.StatusServiceUnavailable, errNoPasskeyStore)
		return
	}
	party, err := partyFor(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}

	var body struct {
		webauthn.Assertion
		Challenge string `json:"challenge"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	c, ok := s.Passkeys.takeChallenge(body.Challenge, time.Now())
	if !ok {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf(
			"this challenge is unknown or has expired. Start again"))
		return
	}

	id, err := base64.RawURLEncoding.DecodeString(body.ID)
	if err != nil {
		if id, err = base64.URLEncoding.DecodeString(body.ID); err != nil {
			writeJSONError(w, http.StatusBadRequest,
				fmt.Errorf("the credential id is not base64url"))
			return
		}
	}
	idx, found := s.Passkeys.find(id)
	if !found {
		// The same answer as a bad signature, and deliberately: telling a
		// stranger that a credential is unknown is telling them which ones are
		// not.
		writeJSONError(w, http.StatusUnauthorized, errSignIn)
		return
	}
	cred := s.Passkeys.Credentials[idx]

	// Checked against the site this credential was registered for, not the one
	// this request claims to be.
	party.ID = cred.RelyingParty
	count, err := party.Verify(cred.Credential, c.value, body.Assertion)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, errSignIn)
		return
	}

	// The counter has to be written back, or the clone check compares against
	// a number that never moves and stops meaning anything.
	s.Passkeys.Credentials[idx].SignCount = count
	s.Passkeys.Credentials[idx].LastUsed = time.Now().Unix()
	if err := s.savePasskeys(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}

	if !s.knownPrincipal(cred.Principal) {
		writeJSONError(w, http.StatusForbidden, fmt.Errorf(
			"%s holds a passkey and no role. An administrator can grant one: "+
				"quilzo auth grant %s author", cred.Principal, cred.Principal))
		return
	}

	// A session token, exactly as the OIDC path mints one: the passkey
	// authenticated, and everything after this is local. The role is what the
	// policy already grants — a session, not a promotion.
	secret, tok, err := s.Tokens.Issue("passkey:"+cred.Principal, cred.Principal,
		s.roleFor(cred.Principal), "/", DefaultSessionTTL, auth.RoleAdmin)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	if s.SaveTokens != nil {
		if err := s.SaveTokens(s.Tokens); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if s.OnSignIn != nil {
		s.OnSignIn(cred.Principal, tok.ID)
	}

	http.SetCookie(w, &http.Cookie{
		Name: "quilzo_token", Value: secret, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil, MaxAge: int(DefaultSessionTTL.Seconds()),
	})
	writeJSON(w, map[string]any{"ok": true, "next": "/"})
}

// handlePasskeyRemove deletes one of the caller's own keys.
func (s *Server) handlePasskeyRemove(w http.ResponseWriter, r *http.Request) {
	who, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this is a ceremony endpoint and takes a POST",
			http.StatusMethodNotAllowed)
		return
	}
	if s.Passkeys == nil {
		writeJSONError(w, http.StatusServiceUnavailable, errNoPasskeyStore)
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(r.FormValue("id"))
	if err != nil {
		http.Error(w, "that is not a credential id", http.StatusBadRequest)
		return
	}
	idx, found := s.Passkeys.find(id)
	// Somebody may only remove their own. Without this, anybody who can sign
	// in can remove everybody else's second factor.
	if !found || s.Passkeys.Credentials[idx].Principal != who.Name {
		http.Error(w, "no such passkey", http.StatusNotFound)
		return
	}
	s.Passkeys.Credentials = append(s.Passkeys.Credentials[:idx],
		s.Passkeys.Credentials[idx+1:]...)
	if err := s.savePasskeys(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/passkeys", http.StatusSeeOther)
}

func (s *Server) savePasskeys() error {
	if s.Passkeys == nil || s.Passkeys.Save == nil {
		return nil
	}
	return s.Passkeys.Save(s.Passkeys)
}

// errNoPasskeyStore is what a build with no credential storage says. Not a
// 404: the route exists, and "not found" would send somebody looking for a
// typo rather than for the wiring.
var errNoPasskeyStore = fmt.Errorf(
	"this server was built without anywhere to keep passkeys, so none can be " +
		"registered or used. Sign in with a token")

// passkeysUnavailable answers a page request on a build with no storage.
func (s *Server) passkeysUnavailable(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusServiceUnavailable)
	s.render(w, r, "passkeys.html", map[string]any{
		"Title": "Passkeys", "Unavailable": errNoPasskeyStore.Error(),
	})
}

// errSignIn is the single answer to every sign-in failure. Which one it was is
// not information a stranger should be handed.
var errSignIn = fmt.Errorf("that passkey did not sign anybody in")

func credentialIDs(all []StoredCredential, principal string) []string {
	var out []string
	for _, c := range all {
		if c.Principal == principal {
			out = append(out, base64.RawURLEncoding.EncodeToString(c.ID))
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// readJSON caps the body. A ceremony's payload is a few kilobytes and an
// unbounded read is an allocation anybody can ask for.
func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("this request's body is not the expected JSON: %w", err)
	}
	return nil
}
