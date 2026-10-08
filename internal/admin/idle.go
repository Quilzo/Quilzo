// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"sync"
	"time"
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
// not count, and neither does a credential sent in an Authorization header,
// which is a program, not a browser left open.
//
// Kept in this process, not in the credential store: the store is reloaded
// from disk whenever another process writes it, and the last use of every
// session would go with it. After a restart every session starts a fresh
// idle period rather than being signed out for the restart's sake.

type idleClock struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// idleOver ends a browser session nobody has used for session.idle and
// reports whether it did; otherwise it notes this request as use when a
// person made it.
func (s *Server) idleOver(w http.ResponseWriter, r *http.Request, p principal) bool {
	idle := s.sessionIdle()
	if idle <= 0 || !p.Session || p.TokenID == "" || !fromBrowser(r) {
		return false
	}
	now := time.Now()
	s.idle.mu.Lock()
	if s.idle.last == nil {
		s.idle.last = map[string]time.Time{}
	}
	last, seen := s.idle.last[p.TokenID]
	switch {
	case !seen:
		s.idle.last[p.TokenID] = now
		s.idle.sweep(now, s.sessionMax())
	case now.Sub(last) > idle:
		delete(s.idle.last, p.TokenID)
		s.idle.mu.Unlock()
		s.endIdle(w, r, p, idle)
		return true
	case personMade(r):
		s.idle.last[p.TokenID] = now
	}
	s.idle.mu.Unlock()
	return false
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
