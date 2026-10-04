// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Wrap refuses requests from blocked sources before anything else sees
// them. client is the requester's address as the deployment knows it (the
// one a trusted proxy forwards); nil means the connection's.
func (g *Guard) Wrap(where string, client func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := ""
		if client != nil {
			addr = client(r)
		}
		if addr == "" {
			addr = Connection(r)
		}
		now := time.Now()
		if p, blocked := g.Blocked(addr, where, now); blocked {
			Refuse(w, p, now)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Connection is the address a request's connection came from.
func Connection(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Refuse answers a blocked request: plainly, with when to try again, and
// without why, which is the one thing a blocked prober would want to know.
func Refuse(w http.ResponseWriter, p Protection, now time.Time) {
	h := w.Header()
	h.Set("Retry-After", strconv.Itoa(int(p.Until.Sub(now).Seconds())+1))
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "Requests from your address are refused until %s.\n"+
		"If this is a mistake, the people who run this site can lift it.\n",
		p.Until.UTC().Format("15:04 UTC on 2 January"))
}

// Find is a protection of one kind on one target in force, read straight
// from the store: for the places that act rarely and have no guard of
// their own, such as publishing and starting an agent.
func Find(root, kind, target string, now time.Time) (Protection, bool) {
	st, err := Load(root)
	if err != nil {
		return Protection{}, false
	}
	for _, p := range st.Active(now) {
		if p.Kind == kind && p.Target == target {
			return p, true
		}
	}
	return Protection{}, false
}

// FrozenError is publishing refused while it is frozen.
type FrozenError struct{ P Protection }

func (e *FrozenError) Error() string {
	return fmt.Sprintf("publishing is frozen until %s (%s). Rolling back still works; "+
		"an administrator can lift the freeze on the Shield screen or with quilzo shield lift",
		e.P.Until.UTC().Format("15:04 UTC on 2 January"), e.P.Reason)
}

// LockedOut reports whether a credential is refused during a lockdown:
// one issued before it began that no passkey or single sign-on vouched
// for. A stolen token predates the lockdown; a person signing in with
// their passkey, and a token made after it began, by somebody who did,
// or on the machine, are let through.
func LockedOut(p Protection, issued int64, vouched bool) bool {
	return !vouched && issued < p.At.Unix()
}
