// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Somebody going after this Quilzo.
//
// The public site sees three things only an attacker of Quilzo in
// particular does, and this counts them per source:
//
//   - admin-hunt: asking the public site for the admin's or the API's
//     addresses. The admin is a separate server, normally on loopback, so
//     on the public site those paths do not exist; asking for them is
//     looking for a way in.
//   - conversation-guess: wrong secrets on a chatbot conversation's
//     address, which is how somebody would try to read another visitor's
//     conversation.
//   - chatbot-injection: a question to a chatbot carrying the phrases
//     prompt-injection attempts use. The chatbot is built so that nothing
//     a visitor writes can widen what it does; this records that somebody
//     tried.
//
// Each is recorded once per source per window, so a script sending a
// thousand requests is one line in the log, and the quilzo.* rules turn it
// into a finding. The visitor's answer is unchanged either way: an
// ordinary 404, an ordinary answer.
//
// These are OWASP AppSensor detection points: inside the application,
// where it is known which paths, secrets and questions are the suspicious
// ones for this program rather than for programs in general.

// Signal kinds.
const (
	AdminHunt         = "admin-hunt"
	ConversationGuess = "conversation-guess"
	ChatbotInjection  = "chatbot-injection"
	// FormSpam is a form refusing a submission as spam: the honeypot
	// filled, or answered faster than a person can read.
	FormSpam = "form-spam"
)

// adminPaths are the admin server's and API's own addresses, which the
// public site never serves.
var adminPaths = []string{
	"/signin", "/signout", "/api/", "/mcp", "/security", "/agents", "/inbox",
	"/settings", "/people", "/access", "/passkeys", "/playground",
	"/findings", "/tokens", "/admin.js", "/integrations", "/assistants",
}

// IsAdminPath reports whether a request on the public site was for an
// address only the admin has.
func IsAdminPath(path string) bool {
	// Whole segments: /settings and /settings/x are the admin's, and
	// /settings-guide is somebody's page.
	p := strings.ToLower(path)
	for _, a := range adminPaths {
		base := strings.TrimSuffix(a, "/")
		if p == base || strings.HasPrefix(p, base+"/") {
			return true
		}
	}
	return false
}

// injectionMarkers are phrases prompt-injection attempts use. Matching one
// is not proof; it is somebody worth knowing about.
var injectionMarkers = []string{
	"ignore previous instructions", "ignore all previous", "ignore the above",
	"ignore your instructions", "disregard previous", "disregard all prior",
	"disregard your instructions", "reveal your instructions",
	"print your instructions", "show your system prompt", "system prompt",
	"you are now", "developer mode", "jailbreak", "<|im_start|>", "[inst]",
	"begin untrusted content", "### instruction",
}

// LooksLikeInjection reports whether a question carries a prompt-injection
// phrase.
func LooksLikeInjection(q string) bool {
	q = strings.ToLower(strings.Join(strings.Fields(q), " "))
	for _, m := range injectionMarkers {
		if strings.Contains(q, m) {
			return true
		}
	}
	return false
}

// SignalWatch counts signals per kind and source, and reports a source the
// first time it reaches its kind's threshold within a window.
type SignalWatch struct {
	// After is how many of each kind from one source are worth recording.
	// A kind not listed is recorded at the first.
	After  map[string]int
	Window time.Duration
	// Report is told the kind, the source, how many it sent and how many
	// different things they were about (up to 16), so a history can tell
	// one admin address asked for again and again from several.
	Report func(kind, source string, n, distinct int)

	mu   sync.Mutex
	seen map[string]*signalCount
	now  func() time.Time
}

type signalCount struct {
	first    time.Time
	n        int
	about    map[string]bool
	reported bool
}

// Saw counts one signal.
func (sw *SignalWatch) Saw(kind, source, subject string) {
	if sw == nil || sw.Report == nil {
		return
	}
	now := time.Now()
	if sw.now != nil {
		now = sw.now()
	}
	after := sw.After[kind]
	if after < 1 {
		after = 1
	}
	key := kind + "\x00" + source
	sw.mu.Lock()
	if sw.seen == nil {
		sw.seen = map[string]*signalCount{}
	}
	// Forget what is old, so the map cannot grow without bound on a server
	// the internet's background scanning reaches all day.
	if len(sw.seen) > 10000 {
		for k, c := range sw.seen {
			if now.Sub(c.first) > sw.Window {
				delete(sw.seen, k)
			}
		}
	}
	c, ok := sw.seen[key]
	if !ok || now.Sub(c.first) > sw.Window {
		c = &signalCount{first: now}
		sw.seen[key] = c
	}
	c.n++
	if c.about == nil {
		c.about = map[string]bool{}
	}
	if len(c.about) < 16 {
		c.about[subject] = true
	}
	report := c.n >= after && !c.reported
	if report {
		c.reported = true
	}
	n, distinct := c.n, len(c.about)
	sw.mu.Unlock()
	if report {
		sw.Report(kind, source, n, distinct)
	}
}

// signal is one sighting: recorded once per window, and told to the shield
// every time. subject is what it was about: the chatbot or form by name, or
// for admin-hunt the address asked for, so asking for one address again
// and again can be told from looking for several.
func (st *Site) signal(kind, subject string, r *http.Request) {
	if st.Signals != nil {
		st.Signals.Saw(kind, sourceOf(r), subject)
	}
	if st.OnSignal != nil {
		st.OnSignal(kind, subject, r)
	}
}

// huntedPath is an admin address asked for, as a subject: its first two
// segments, lower case, so /security/x and /security/y are one address and
// a path cannot be made long to fill memory.
func huntedPath(path string) string {
	p := strings.ToLower(path)
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 3)
	if len(parts) > 2 {
		parts = parts[:2]
	}
	out := "/" + strings.Join(parts, "/")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// shielded reports whether the shield has turned a feature down.
func (st *Site) shielded(target string) (level string, until time.Time, on bool) {
	if st.Shield == nil {
		return "", time.Time{}, false
	}
	return st.Shield(target)
}

// resting answers a request for something the shield has turned off for a
// while: plainly, with when to come back, and nothing about why.
func (st *Site) resting(w http.ResponseWriter, r *http.Request, what string, until time.Time) {
	h := w.Header()
	if secs := int(time.Until(until).Seconds()) + 1; secs > 0 {
		h.Set("Retry-After", strconv.Itoa(secs))
	}
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusServiceUnavailable)
	if r.Method == http.MethodHead {
		return
	}
	fmt.Fprintf(w, "%s is not available for a while. Please try again later.\n", what)
}
