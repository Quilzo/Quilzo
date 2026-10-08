// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Slowing: a source the shield is not sure enough about to block gets a
// small budget instead. Within it, requests are answered as usual; past it,
// they are refused at once with when to try again, as Cloudflare's throttle
// and AWS's rate-based rules do. Nothing is held open and nothing sleeps:
// a server that delays the requests it dislikes is a server whose own
// workers an attacker can tie up by being disliked.
//
// The budget is a GCRA (the generic cell rate algorithm): one request a
// second on average, twenty at once, with anything but a read costing ten,
// because a form, a chatbot question or an upload is what is expensive.

// Slow is a protection that gives its target a small budget.
const Slow = "slow"

// Slow budgets.
const (
	slowInterval = time.Second // one unit a second, on average
	slowBurst    = 20          // units at once
	slowWrite    = 10          // what anything but a read costs
	maxSlowKeys  = 65536
)

// limiter is a GCRA per key, bounded: past the bound it forgets keys whose
// budget is already whole again, which loses nothing, and then any.
type limiter struct {
	mu  sync.Mutex
	tat map[string]time.Time
}

// allow spends cost units for key, or says how long until it could.
func (l *limiter) allow(key string, cost int, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tat == nil {
		l.tat = map[string]time.Time{}
	}
	t, ok := l.tat[key]
	if !ok || t.Before(now) {
		t = now
	}
	next := t.Add(time.Duration(cost) * slowInterval)
	if at := next.Add(-slowBurst * slowInterval); at.After(now) {
		return false, at.Sub(now)
	}
	if !ok && len(l.tat) >= maxSlowKeys {
		for k, v := range l.tat {
			if !v.After(now) {
				delete(l.tat, k)
			}
		}
		for k := range l.tat {
			if len(l.tat) < maxSlowKeys {
				break
			}
			delete(l.tat, k)
		}
	}
	l.tat[key] = next
	return true, 0
}

// costOf is what a request spends of a slowed budget.
func costOf(r *http.Request) int {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return 1
	}
	return slowWrite
}

// speculative reports a browser fetching a page before anybody asked for
// it. A slowed source's speculation is not charged: it is refused, and
// the browser simply does not prefetch.
func speculative(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Sec-Purpose"), "prefetch")
}

// RefuseSlow answers a request past a slowed budget: at once, with the
// seconds until one would be allowed.
func RefuseSlow(w http.ResponseWriter, r *http.Request, wait time.Duration) {
	secs := int((wait + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	h := w.Header()
	h.Set("Retry-After", strconv.Itoa(secs))
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "close")
	h.Set("X-Content-Type-Options", "nosniff")
	switch {
	case wantsJSON(r):
		h.Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `{"type":"https://quilzo.github.io/shield/","title":"Too many requests from this address just now","status":429,"detail":"Try again in %d seconds."}`+"\n", secs)
	default:
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, "Too many requests from your address just now. Try again in %d seconds.\n", secs)
	}
}
