// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/clientip"
)

// Wrap refuses requests from blocked sources before anything else sees
// them. The client is the one the edge decided (internal/clientip), so it
// sits behind clientip.Middleware. A request whose client could not be told,
// or that came from inside, is never refused here: blocking the unknown is
// blocking whoever shares the proxy.
func (g *Guard) Wrap(where string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := clientip.FromRequest(r)
		if c.Known() && !c.Internal {
			now := time.Now()
			if p, blocked := g.Blocked(c.Addr.String(), where, now); blocked {
				Refuse(w, r, p, now)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Refuse answers a blocked request: at once, with when to come back and a
// reference a person can quote to have it lifted, and without why, which
// is the one thing a blocked prober would want to know.
//
// 429 rather than 403, as Cloudflare and Google's crawlers read them: this
// is temporary, and a crawler told 403 for a day drops the page, where one
// told 429 comes back. The body is small and needs nothing else (HTML for a
// browser, problem+json for a program, text for the rest), and the
// connection is closed, so a refused client holds nothing open.
func Refuse(w http.ResponseWriter, r *http.Request, p Protection, now time.Time) {
	back := roundUp(p.Until, 5*time.Minute)
	secs := int(back.Sub(now)/time.Second) + 1
	// A little later than the rounded time and never earlier, different
	// for each protection, so a crowd told the same minute does not all
	// come back in it.
	secs += jitter(p.ID, secs)
	h := w.Header()
	h.Set("Retry-After", strconv.Itoa(secs))
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "close")
	h.Set("X-Content-Type-Options", "nosniff")
	when := back.UTC().Format("15:04 UTC on 2 January")
	switch {
	case wantsJSON(r):
		h.Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `{"type":"https://quilzo.github.io/#shield","title":"Requests from this address are refused for now","status":429,"detail":"Try again after %s.","reference":%q}`+"\n",
			when, p.ID)
	case wantsHTML(r):
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", refusalCSP)
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, refusalPage, when, p.ID)
	default:
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, "Requests from your address are refused until about %s.\n"+
			"If this is a mistake, the people who run this site can lift it: quote %s.\n", when, p.ID)
	}
}

// jitter is up to a tenth more, at most two minutes, from the
// protection's id: the same answer every time it is asked.
func jitter(id string, secs int) int {
	h := fnv.New32a()
	h.Write([]byte(id))
	span := min(secs/10, 120)
	if span < 1 {
		return 0
	}
	return int(h.Sum32() % uint32(span+1))
}

func wantsJSON(r *http.Request) bool {
	if r == nil {
		return false
	}
	p := r.URL.Path
	if strings.HasPrefix(p, "/api/") || p == "/mcp" || strings.HasPrefix(p, "/mcp/") || strings.HasPrefix(p, "/scim/") || strings.HasPrefix(p, "/feeds/") {
		return true
	}
	a := r.Header.Get("Accept")
	return strings.Contains(a, "application/json") || strings.Contains(a, "+json")
}

func wantsHTML(r *http.Request) bool {
	return r != nil && strings.Contains(r.Header.Get("Accept"), "text/html")
}

// refusalStyle is the page's only style, allowed by its hash and nothing
// else: the refusal loads no font, no script and no picture.
const refusalStyle = `body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;background:#f8f9fc;color:#1f1f1f}main{max-width:32rem;margin:24px;padding:24px 28px;border-radius:24px;background:#fff}h1{font-size:1.375rem;font-weight:400;margin:0 0 8px}p{margin:8px 0}code{font:14px ui-monospace,monospace}@media(prefers-color-scheme:dark){body{background:#131314;color:#e3e3e3}main{background:#1e1f20}}`

var refusalCSP = func() string {
	sum := sha256.Sum256([]byte(refusalStyle))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

var refusalPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Not now</title><style>` +
	refusalStyle + `</style></head><body><main><h1>Not right now</h1><p>Requests from your address are refused until about %s.</p><p>If this is a mistake, the people who run this site can lift it. Quote <code>%s</code>.</p></main></body></html>
`

func roundUp(t time.Time, d time.Duration) time.Time {
	r := t.Truncate(d)
	if r.Before(t) {
		r = r.Add(d)
	}
	return r
}

// Unreadable is the reason given when the shield's own record cannot be
// read: what is contained stays contained until somebody repairs it.
const Unreadable = "the shield's record cannot be read; `quilzo shield repair` sets it aside"

// Find is a protection of one kind on one target in force, read straight
// from the store: for the places that act rarely and have no guard of
// their own, such as publishing and starting an agent.
//
// It fails closed. A record that cannot be read may be holding a freeze or
// a paused agent, and carrying on as though it were empty is the direction
// that silently undoes a containment; so an unreadable record is answered
// as a protection in force, which says what to do about it.
func Find(root, kind, target string, now time.Time) (Protection, bool) {
	st, err := Load(root)
	if err != nil {
		return Protection{Kind: kind, Target: target, Reason: Unreadable, By: "shield",
			At: now, Until: now.Add(time.Hour)}, true
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
