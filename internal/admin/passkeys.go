// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/throttle"
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

	// credMu is held for every read of Credentials and for every change,
	// with its save. Requests run at once: a removal cut the list at an
	// index found before another removal shifted it, and a sign-in wrote
	// its counter back through an index found before the signature was
	// checked, so either could land on somebody else's passkey. And a save
	// outside it could write an older list last, undoing a removal on disk.
	credMu sync.Mutex
}

// errPasskeyExists is a credential registered twice.
var errPasskeyExists = errors.New("this key is already registered")

// errPasskeyGone is a credential removed while it was being used.
var errPasskeyGone = errors.New("this passkey was removed")

// list is a copy of the credentials, for reading.
func (p *Passkeys) list() []StoredCredential {
	p.credMu.Lock()
	defer p.credMu.Unlock()
	return append([]StoredCredential(nil), p.Credentials...)
}

// lookup is the credential with this id, copied.
func (p *Passkeys) lookup(id []byte) (StoredCredential, bool) {
	p.credMu.Lock()
	defer p.credMu.Unlock()
	if i, ok := p.find(id); ok {
		return p.Credentials[i], true
	}
	return StoredCredential{}, false
}

// change applies fn to the credentials and saves the result, all under
// credMu, so each change is made to the list as it stands and the file
// holds the newest one.
func (p *Passkeys) change(fn func(creds *[]StoredCredential) error) error {
	p.credMu.Lock()
	defer p.credMu.Unlock()
	if err := fn(&p.Credentials); err != nil {
		return err
	}
	if p.Save == nil {
		return nil
	}
	return p.Save(p)
}

// add keeps a new credential, refusing one already kept.
func (p *Passkeys) add(sc StoredCredential) error {
	return p.change(func(creds *[]StoredCredential) error {
		if _, ok := p.find(sc.ID); ok {
			return errPasskeyExists
		}
		*creds = append(*creds, sc)
		return nil
	})
}

// remove takes away the credential with this id, if owner holds it, and
// returns its label.
func (p *Passkeys) remove(id []byte, owner string) (string, error) {
	label := ""
	err := p.change(func(creds *[]StoredCredential) error {
		i, ok := p.find(id)
		if !ok || (*creds)[i].Principal != owner {
			return errPasskeyGone
		}
		label = (*creds)[i].Label
		*creds = append((*creds)[:i], (*creds)[i+1:]...)
		return nil
	})
	return label, err
}

// noteUse writes back what a sign-in learnt about the credential with this
// id: its counter, which the clone check compares against, and its flags.
func (p *Passkeys) noteUse(id []byte, used webauthn.Credential, at time.Time) error {
	return p.change(func(creds *[]StoredCredential) error {
		i, ok := p.find(id)
		if !ok {
			return errPasskeyGone
		}
		c := &(*creds)[i]
		c.SignCount = used.SignCount
		c.UserVerified = used.UserVerified
		c.BackupEligible = used.BackupEligible
		c.BackupState = used.BackupState
		c.LastUsed = at.Unix()
		return nil
	})
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

// find returns the index of the credential with this id. credMu is held.
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
// Behind a proxy that terminates TLS the request arrives as plain HTTP while
// the browser is on HTTPS; admin.behind_tls_proxy says so, the same setting
// that marks the session cookie Secure, and without it passkeys would be
// refused in every deployment that is not on this machine.
//
// Derived rather than configured because the admin does not otherwise know its
// own public address, and a wrong constant would be a passkey that registers
// and never works. It is safe to derive: the browser reports the origin it
// actually used, and an attacker who controls the Host header changes what
// this server expects without changing what the browser says, so the two stop
// matching and the ceremony is refused either way.
func (s *Server) partyFor(r *http.Request) (webauthn.Party, error) {
	host := r.Host
	if host == "" {
		return webauthn.Party{}, fmt.Errorf("this request names no host")
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}

	scheme := "http"
	if r.TLS != nil || s.behindTLSProxy() {
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
		s.passkeysUnavailable(w, r, who)
		return
	}

	n, err := nonce()
	if err != nil {
		http.Error(w, "no entropy", http.StatusInternalServerError)
		return
	}
	s.passkeyPolicy(w, n)

	var mine []StoredCredential
	for _, c := range s.Passkeys.list() {
		if c.Principal == who.Name {
			mine = append(mine, c)
		}
	}

	// Said on the page rather than discovered at the moment somebody presses
	// the button, because a browser's refusal here is silent and looks like
	// nothing happened.
	unavailable := ""
	if _, perr := s.partyFor(r); perr != nil {
		unavailable = asNotice(perr.Error())
	}

	// Principal, or this screen renders with no navigation at all.
	//
	// render works out the menu from the caller's permissions, and reads the
	// caller out of this map. Without it the policy is asked about an empty
	// principal, every entry is denied, and the page comes back with no menu
	// and no "signed in as" — 3,475 bytes where the media screen is 10,053.
	//
	// It presented as "the highlight does not work on Passkeys like it does
	// everywhere else", which is how somebody notices a missing menu on a
	// screen they reached from the menu.
	// How many of these would not enrol under the policy in force now.
	//
	// webauthn.Credential.Identified is written at enrolment, with the
	// comment that "the useful question later is 'which of these are hardware
	// keys' and it cannot be answered retrospectively: the authenticator only
	// says at registration". It was written and never read, so the question
	// it exists to answer could not be asked on any surface.
	//
	// Which matters most at exactly the moment somebody turns
	// passkey.require_hardware on. From then, a new synced passkey is
	// refused — and the ones already enrolled keep working, invisibly, with
	// nothing to say which they are. The field that answers it is right
	// there on every record.
	requires := s.Passkeys != nil && s.Passkeys.Enrol.RequireIdentified
	unidentified := 0
	for _, c := range mine {
		if !c.Identified {
			unidentified++
		}
	}

	s.render(w, r, "passkeys.html", map[string]any{
		"Nav": "passkeys", "Principal": who,
		"Title": "Passkeys", "Nonce": n, "Keys": mine,
		"Unavailable": unavailable, "Who": who.Name,
		"RequiresHardware": requires, "Unidentified": unidentified,
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
			"font-src 'self'; "+
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

// mayEnrol says whether a session may add a passkey to its person.
//
// A passkey signs its person in with everything the policy grants them, so
// adding one is as strong an act as the person can perform, and only a
// session that already has all of that may do it: the person's own role,
// over the whole store, with no limits on the token. A session from a token
// narrowed to a part of the store, a lesser role or reading only could
// otherwise enrol a key of its own and sign in as the whole person — and
// keep that key after the token was revoked.
func (s *Server) mayEnrol(who principal) error {
	full := s.roleFor(who.Name)
	if who.Role != full || (who.Scope != "" && who.Scope != "/") || !who.Limits.Empty() {
		return fmt.Errorf("a passkey signs %s in with everything they hold, so it is added from a "+
			"session with all of it; this one carries less (%s on %s). Sign in with %s's own "+
			"credentials to add one", who.Name, who.Role, orRoot(who.Scope), who.Name)
	}
	// A new passkey is bound from a session already at the level it gives
	// (SP 800-63B-4 4.1): a token alone, which anybody holding a copy has,
	// would otherwise turn itself into two factors. Before two factors are
	// compulsory, a token's session may add the first one.
	if who.Level < 2 && s.mfaEnforced(time.Now()) {
		return fmt.Errorf("a passkey is added from a session signed in with two factors, and this one " +
			"was signed in with a token alone. An administrator can give you an enrolment link")
	}
	return nil
}

func orRoot(scope string) string {
	if scope == "" {
		return "/"
	}
	return scope
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
	if err := s.mayEnrol(who); err != nil {
		s.audit("passkey.enrol-refused", "/", map[string]string{"by": who.Name, "session": who.TokenID})
		writeJSONError(w, http.StatusForbidden, err)
		return
	}
	party, err := s.partyFor(r)
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
		"exclude": credentialIDs(s.Passkeys.list(), who.Name),
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
	if err := s.mayEnrol(who); err != nil {
		s.audit("passkey.enrol-refused", "/", map[string]string{"by": who.Name, "session": who.TokenID})
		writeJSONError(w, http.StatusForbidden, err)
		return
	}
	party, err := s.partyFor(r)
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

	if err := s.Passkeys.add(StoredCredential{Credential: cred, RelyingParty: party.ID}); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errPasskeyExists) {
			code = http.StatusConflict
		}
		writeJSONError(w, code, err)
		return
	}
	// Recorded with the session that added it, so a key added from a
	// session that should not have been trusted can be found again.
	s.audit("passkey.enrolled", "/", map[string]string{"by": who.Name, "session": who.TokenID,
		"label": cred.Label})
	writeJSON(w, map[string]any{"ok": true})
}

// handlePasskeySignIn serves the sign-in page's script.
func (s *Server) handlePasskeySignIn(w http.ResponseWriter, r *http.Request) {
	if s.Passkeys == nil {
		// Nobody is signed in on this page, so there is no menu to render.
		s.passkeysUnavailable(w, r, principal{})
		return
	}
	n, err := nonce()
	if err != nil {
		http.Error(w, "no entropy", http.StatusInternalServerError)
		return
	}
	s.passkeyPolicy(w, n)

	unavailable := ""
	if _, perr := s.partyFor(r); perr != nil {
		unavailable = asNotice(perr.Error())
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
	party, err := s.partyFor(r)
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
	// Slowed per source like every other way in, before anything is read.
	src := throttle.Subject{Source: sourceOf(r)}
	if s.Throttle != nil {
		if d := s.Throttle.Check(src); !d.Allowed {
			s.tooManyAttempts(w, r, d)
			return
		}
	}
	failed := func() {
		if s.Throttle != nil {
			if d, alert := s.Throttle.Fail(src); alert && s.OnAuthFailure != nil {
				s.OnAuthFailure(src.Source, d.Failures)
			}
		}
	}
	party, err := s.partyFor(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}

	var body struct {
		webauthn.Assertion
		Challenge string `json:"challenge"`
		// Expect names whose page this sign-in is made from, when it is made
		// in place after an idle sign-out: whatever that page holds is theirs,
		// and only they carry on with it.
		Expect string `json:"expect"`
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
	cred, found := s.Passkeys.lookup(id)
	if !found {
		// The same answer as a bad signature, and deliberately: telling a
		// stranger that a credential is unknown is telling them which ones are
		// not.
		if held := s.stepUpFailed(r); held != "" {
			s.lockoutFail(r, held)
		}
		failed()
		writeJSONError(w, http.StatusUnauthorized, errSignIn)
		return
	}
	// A credential the store knows names its account, so its failures count
	// against that account, from where they come (lockout.go).
	if !s.lockoutCheck(w, r, cred.Principal) {
		return
	}

	// Checked against the site this credential was registered for, not the one
	// this request claims to be.
	party.ID = cred.RelyingParty
	used, err := party.Verify(cred.Credential, c.value, body.Assertion)
	if errors.Is(err, webauthn.ErrUserNotVerified) {
		// The one failure that is said as itself: the signature verified,
		// so this is the key's own holder, and what they need is to know
		// the key has to ask for a PIN, fingerprint or face.
		writeJSONError(w, http.StatusUnauthorized, err)
		return
	}
	if err != nil {
		held := s.stepUpFailed(r)
		failed()
		s.lockoutFail(r, cred.Principal)
		if held != "" && !strings.EqualFold(held, cred.Principal) {
			s.lockoutFail(r, held)
		}
		writeJSONError(w, http.StatusUnauthorized, errSignIn)
		return
	}

	// The counter has to be written back, or the clone check compares against
	// a number that never moves and stops meaning anything; the flags, so
	// the record says whether the key is synced as of its last use.
	if err := s.Passkeys.noteUse(cred.ID, used, time.Now()); err != nil {
		if errors.Is(err, errPasskeyGone) {
			// Removed while this sign-in was being checked: it signs in
			// nobody, as it would have a moment later.
			failed()
			writeJSONError(w, http.StatusUnauthorized, errSignIn)
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}

	// Suspended by provisioning, or denied the whole site by hand: refused
	// here as single sign-on refuses it, before a session exists. Asked first
	// because a suspension is a deny binding, which also makes the person
	// known to the policy, and the session minted below would otherwise go
	// to somebody every screen then refuses, with their address exempted
	// from the shield on the way.
	if s.suspended(cred.Principal) {
		s.audit("session.refused", "/", map[string]string{"by": cred.Principal,
			"how": "passkey", "why": "suspended"})
		writeJSONError(w, http.StatusForbidden, fmt.Errorf(
			"%s is suspended here, so no passkey signs them in", cred.Principal))
		return
	}
	if !s.knownPrincipal(cred.Principal) {
		writeJSONError(w, http.StatusForbidden, fmt.Errorf(
			"%s holds a passkey and no role. An administrator can grant one: "+
				"quilzo auth grant %s author", cred.Principal, cred.Principal))
		return
	}
	if body.Expect != "" && !strings.EqualFold(body.Expect, cred.Principal) {
		writeJSONError(w, http.StatusConflict, fmt.Errorf(
			"that passkey is somebody else's, and this page is %s's. Sign in from the sign-in page", body.Expect))
		return
	}

	// Proving a stepped-up session's person: the same person, by passkey,
	// from a session marked as having to. That session is replaced by this
	// one, which is not judged again — this sign-in is the proof.
	var stepped *principal
	if prev, err := s.authenticate(r); err == nil && prev.StepUp != "" && strings.EqualFold(prev.Name, cred.Principal) {
		stepped = &prev
	}
	// Single sign-on required is the front door only: a passkey that proves
	// the person behind a held session is still how step-up is passed.
	if stepped == nil && s.ssoRequired(cred.Principal) != "" {
		writeJSONError(w, http.StatusForbidden, fmt.Errorf(
			"your organisation requires signing in through %s", s.ssoRequired(cred.Principal)))
		return
	}

	// A session token, exactly as the OIDC path mints one: the passkey
	// authenticated, and everything after this is local. The role is what the
	// policy already grants — a session, not a promotion.
	// How it was signed in to: a passkey, after whatever the session it
	// replaces had already proved, so a single sign-on session confirmed
	// with a passkey is still one that came through the identity provider.
	methods := []string{auth.MethodPasskey}
	if stepped != nil {
		methods = append(append([]string(nil), stepped.Methods...), auth.MethodPasskey)
	}
	secret, tok, err := s.Tokens.IssueSession("passkey:"+cred.Principal, cred.Principal,
		s.roleFor(cred.Principal), "/", s.sessionMax(), auth.RoleAdmin, methods...)
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
	// With what the authenticator said, so the log answers which sign-ins
	// came from a synced passkey and which from a key that exists once.
	s.audit("session.start", "/", map[string]string{"by": cred.Principal, "session": tok.ID,
		"how": "passkey", "aal": strconv.Itoa(tok.Level()), "label": cred.Label, "user_verified": strconv.FormatBool(used.UserVerified),
		"backup_eligible": strconv.FormatBool(used.BackupEligible),
		"backed_up":       strconv.FormatBool(used.BackupState)})
	if s.OnSignIn != nil {
		s.OnSignIn(cred.Principal, tok.ID)
	}
	next := startPath(r)
	s.signInDone(r, tok.ID)
	if stepped != nil {
		_, _ = s.Tokens.Revoke(stepped.TokenID)
		if s.SaveTokens != nil {
			_ = s.SaveTokens(s.Tokens)
		}
		s.audit("session.stepup-passed", "/", map[string]string{"by": cred.Principal, "session": stepped.TokenID, "how": "passkey"})
		_, _ = s.signInCheck(r, cred.Principal, tok.ID, "passkey", true)
	} else {
		up, serr := s.signInCheck(r, cred.Principal, tok.ID, "passkey", false)
		if serr != nil {
			writeJSONError(w, http.StatusServiceUnavailable, serr)
			return
		}
		if up {
			next = "/signin/verify"
		}
	}
	// The count starts again from a place now familiar, and the person is
	// told what came before, if anything did: on the page they land on, or
	// in place by a page that signed in without leaving.
	notice := s.lockoutNotice(r, cred.Principal)
	next = s.withNotice(next, notice)

	http.SetCookie(w, &http.Cookie{
		Name: "quilzo_token", Value: secret, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || s.behindTLSProxy(), MaxAge: int(s.sessionMax().Seconds()),
	})
	writeJSON(w, map[string]any{"ok": true, "next": next, "notice": notice})
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
	c, found := s.Passkeys.lookup(id)
	// Somebody may only remove their own. Without this, anybody who can sign
	// in can remove everybody else's second factor.
	if !found || c.Principal != who.Name {
		http.Error(w, "no such passkey", http.StatusNotFound)
		return
	}
	// Taking a key away is as strong an act as adding one: a narrowed
	// session that could remove its person's passkeys could leave them
	// locked out of the way they sign in.
	if err := s.mayEnrol(who); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	// Removed by id, as the list stands now, and only if it is still theirs.
	label, err := s.Passkeys.remove(id, who.Name)
	if errors.Is(err, errPasskeyGone) {
		http.Error(w, "no such passkey", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit("passkey.removed", "/", map[string]string{"by": who.Name, "session": who.TokenID, "label": label})
	http.Redirect(w, r, "/passkeys", http.StatusSeeOther)
}

// errNoPasskeyStore is what a build with no credential storage says. Not a
// 404: the route exists, and "not found" would send somebody looking for a
// typo rather than for the wiring.
var errNoPasskeyStore = fmt.Errorf(
	"this server was built without anywhere to keep passkeys, so none can be " +
		"registered or used. Sign in with a token")

// passkeysUnavailable answers a page request on a build with no storage.
// passkeysUnavailable explains that this build keeps no passkeys.
//
// Takes the caller rather than resolving one, because its two callers are in
// different states: the management screen has already authenticated somebody
// and a screen saying a feature is unavailable is still a screen they need to
// navigate away from, while the sign-in page has nobody yet and correctly
// renders no menu. A zero principal is the second case.
func (s *Server) passkeysUnavailable(w http.ResponseWriter, r *http.Request,
	who principal) {

	w.WriteHeader(http.StatusServiceUnavailable)
	data := map[string]any{
		"Nav":   "passkeys",
		"Title": "Passkeys", "Unavailable": asNotice(errNoPasskeyStore.Error()),
	}
	if who.Name != "" {
		data["Principal"] = who
	}
	s.render(w, r, "passkeys.html", data)
}

// asNotice is an error as a banner shows it: a capital first and a full stop
// last. An error is written lower case and unpunctuated so that it reads
// inside another sentence; a banner is a sentence of its own.
func asNotice(msg string) string {
	msg = sentenceCase(strings.TrimSpace(msg))
	if msg != "" && !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return msg
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
