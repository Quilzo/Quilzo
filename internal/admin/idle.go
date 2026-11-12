// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Signing out a session nobody is using (session.idle; NIST AC-2(5), the
// organisation's ac-02.05_odp).
//
// The hard part is "using". A person writing a long page sends nothing
// while they type, so a server that counted only requests would sign out
// the people working hardest and lose what they had typed. So use is what
// a person does: a page they open, a form they send, and — while a page is
// open — a key, a click or a scroll, which the page reports at most once a
// minute (admin.js, /session/alive). Requests a page makes on its own do
// not count.
//
// A sign-in session is idle however it is presented. Its value works in an
// Authorization header as well as in the cookie, and the clock was kept
// only for the cookie, so a passkey session copied into a header, which
// the bearer gate lets through at two factors, lasted the whole of
// session.max with nobody using it. A program's own long-lived token is not
// a session and is not signed out for idling; a program using a session
// keeps it alive by using it, as a person does, since a request with no
// fetch metadata counts as use.
//
// Kept in this process, not in the credential store: the store is reloaded
// from disk whenever another process writes it, and the last use of every
// session would go with it. After a restart every session starts a fresh
// idle period rather than being signed out for the restart's sake.

type idleClock struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// idleOver ends a sign-in session nobody has used for session.idle, in the
// cookie or in a header, and reports whether it did; otherwise it notes
// this request as use when a person made it.
func (s *Server) idleOver(w http.ResponseWriter, r *http.Request, p principal) bool {
	if !p.Session || p.TokenID == "" {
		return false
	}
	idle := s.idleFor(p.Name)
	if !s.idleSpent(r, p.TokenID, idle) {
		return false
	}
	s.endIdle(w, r, p, idle)
	return true
}

// idleSpent is the clock: whether the session id has gone unused for
// longer than idle, what its person may leave it. A request a person made
// is noted as use; a session not seen before starts its idle period now.
func (s *Server) idleSpent(r *http.Request, id string, idle time.Duration) bool {
	now := time.Now()
	s.idle.mu.Lock()
	defer s.idle.mu.Unlock()
	if s.idle.last == nil {
		s.idle.last = map[string]time.Time{}
	}
	last, seen := s.idle.last[id]
	switch {
	case !seen:
		s.idle.last[id] = now
		s.idle.sweep(now, s.sessionMax())
	case now.Sub(last) > idle:
		delete(s.idle.last, id)
		return true
	case personMade(r):
		s.idle.last[id] = now
	}
	return false
}

// IdleEnded is the same clock for a door that does not answer with the
// admin's screens: the agent interface, and the content API at /api/,
// which this server mounts and does not authenticate itself, and which
// takes the session cookie from the admin's own pages and a session in a
// header from anybody. It ends t, revoked as signing out revokes it, when
// t is a sign-in session nobody has used for session.idle, and reports
// whether it did; a long-lived token is nobody's session and is never
// ended here.
//
// Without it a session used only at /api/v1 was never idle: the admin's
// clock never saw it, and the API keeps none.
func (s *Server) IdleEnded(r *http.Request, t *auth.Token) bool {
	if t == nil || t.ID == "" || !t.IsSession() {
		return false
	}
	// The access rules and the credentials as they are stored now, as at
	// /mcp (storedTokens), and not s.Policy and s.Tokens: this door ran no
	// refresh, and those are the copies a screen's refresh puts in place.
	// The rules were read from s.Policy, so a call here while a screen
	// opened read the field the screen was replacing, and somebody made an
	// administrator elsewhere kept the whole of session.idle until a
	// screen was opened. Saving the token copy could likewise put back
	// what another process had changed since.
	pol, toks := s.storedRules()
	idle := s.idleUnder(pol, t.Principal)
	if !s.idleSpent(r, t.ID, idle) {
		return false
	}
	if toks != nil {
		if _, err := toks.Revoke(t.ID); err == nil && s.SaveTokens != nil {
			_ = s.SaveTokens(toks)
		}
	}
	s.audit("session.idle", "/", map[string]string{"by": t.Principal, "session": t.ID, "after": idle.String()})
	return true
}

// sweep forgets sessions that cannot still be alive. Held lock.
func (c *idleClock) sweep(now time.Time, max time.Duration) {
	if len(c.last) < 1024 {
		return
	}
	for id, t := range c.last {
		if now.Sub(t) > max {
			delete(c.last, id)
		}
	}
}

// endIdle revokes the session, as signing out does, and sends the person
// to sign in again with the reason.
func (s *Server) endIdle(w http.ResponseWriter, r *http.Request, p principal, idle time.Duration) {
	if _, err := s.Tokens.Revoke(p.TokenID); err == nil {
		_ = s.save()
	}
	s.audit("session.idle", "/", map[string]string{"by": p.Name, "session": p.TokenID, "after": idle.String()})
	http.SetCookie(w, &http.Cookie{
		Name: "quilzo_token", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || s.behindTLSProxy(),
	})
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		signInAgain(w, r, "idle")
		return
	}
	http.Error(w, "signed out after a while unused; sign in again", http.StatusUnauthorized)
}

// fromBrowser reports a request carrying the session cookie and no bearer
// header.
func fromBrowser(r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return false
	}
	_, err := r.Cookie("quilzo_token")
	return err == nil
}

// personMade reports a request a person made: a page they opened, a form
// they sent, or the page saying somebody is there. Fetch metadata tells
// them apart: a navigation a person started carries Sec-Fetch-User, and a
// screen refreshing itself, or a fetch a page makes on its own, does not.
// A browser that sends no fetch metadata at all is given the benefit of
// the doubt.
func personMade(r *http.Request) bool {
	if r.Method == http.MethodPost {
		return true
	}
	mode := r.Header.Get("Sec-Fetch-Mode")
	if mode == "" {
		return true
	}
	return mode == "navigate" && r.Header.Get("Sec-Fetch-User") == "?1"
}

// handleAlive is the page saying somebody is there. requireAuth has
// already counted it.
func (s *Server) handleAlive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
