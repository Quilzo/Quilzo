// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shield

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/clientip"
)

func TestWrapRefusesBlockedSourcesFirst(t *testing.T) {
	g := guard(t)
	p := ok(Block, "source:"+audit.Pseudonym(testKey, "203.0.113.9"))
	p.Until, p.Where = time.Now().Add(time.Hour), Site
	p, _, err := Apply(g.Root, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reached := 0
	proxy := &clientip.Resolver{Proxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	edge := func(h http.Handler) http.Handler {
		return clientip.Middleware(func() *clientip.Resolver { return proxy }, h)
	}
	h := edge(g.Wrap(Site, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached++ })))
	get := func(remote string, xff string, h http.Handler) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := get("203.0.113.9:4000", "", h)
	if w.Code != http.StatusTooManyRequests || reached != 0 {
		t.Fatalf("blocked source reached the site: %d", w.Code)
	}
	// Never earlier than the real end; at most the five-minute rounding
	// and the jitter later.
	if secs, _ := strconv.Atoi(w.Header().Get("Retry-After")); secs < 3600 || secs > 3600+300+120+1 {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Connection") != "close" ||
		strings.Contains(w.Body.String(), "testing") || !strings.Contains(w.Body.String(), p.ID) {
		t.Fatalf("headers %v body %q", w.Header(), w.Body.String())
	}
	if w := get("203.0.113.10:4000", "", h); w.Code != http.StatusOK || reached != 1 {
		t.Fatal("another source was refused")
	}
	// Behind a named proxy, the address it forwards is the one judged.
	if w := get("10.0.0.2:4000", "203.0.113.9", h); w.Code != http.StatusTooManyRequests {
		t.Fatal("the forwarded address was not judged")
	}
	// The proxy's own request is judged by its own address, which nobody
	// blocked. One whose client cannot be told is not refused: refusing it
	// is refusing whoever shares the proxy.
	if w := get("10.0.0.2:4000", "", h); w.Code != http.StatusOK {
		t.Fatal("the proxy was refused for a block on somebody else")
	}
	if w := get("10.0.0.2:4000", "garbage", h); w.Code != http.StatusOK {
		t.Fatal("an unknown client was refused")
	}
	// A caller who is not the proxy cannot name somebody else, or escape.
	if w := get("203.0.113.9:4000", "198.51.100.1", h); w.Code != http.StatusTooManyRequests {
		t.Fatal("a blocked source escaped by writing a header")
	}
	// Being named as a proxy is not a pass. A request a named proxy makes
	// itself (a health check, or anybody's code running at a CDN's edge)
	// is the proxy's, and a block on its network holds; what it forwards
	// is judged by the address forwarded, so the block is not everybody's.
	cdn := &clientip.Resolver{Proxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	b := ok(Block, "net:192.0.2.0/24")
	b.Until, b.Where = time.Now().Add(time.Hour), Site
	if _, _, err := Apply(g.Root, b, time.Now()); err != nil {
		t.Fatal(err)
	}
	g.Refresh()
	viaCDN := clientip.Middleware(func() *clientip.Resolver { return cdn },
		g.Wrap(Site, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	if w := get("192.0.2.10:443", "", viaCDN); w.Code != http.StatusTooManyRequests {
		t.Fatal("a named proxy's own request passed a block on its network")
	}
	if w := get("192.0.2.10:443", "192.0.2.11", viaCDN); w.Code != http.StatusTooManyRequests {
		t.Fatal("a request through nothing but named proxies passed a block on them")
	}
	if w := get("192.0.2.10:443", "203.0.113.10", viaCDN); w.Code != http.StatusOK {
		t.Fatal("a client was refused for the block on the proxy it came through")
	}
	if w := get("192.0.2.10:443", "203.0.113.9", viaCDN); w.Code != http.StatusTooManyRequests {
		t.Fatal("a blocked client came through the proxy")
	}
	// The admin is a different surface.
	if w := get("203.0.113.9:4000", "", edge(g.Wrap(Admin, http.NotFoundHandler()))); w.Code != http.StatusNotFound {
		t.Fatal("a site block reached the admin")
	}
}

func TestANamedProxysOwnRequestIsSlowedLikeAnybodys(t *testing.T) {
	g := guard(t)
	p := ok(Slow, "source:"+audit.Pseudonym(testKey, "192.0.2.10"))
	p.Until, p.Where = time.Now().Add(time.Hour), Site
	if _, _, err := Apply(g.Root, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	g.Refresh()
	named := &clientip.Resolver{Proxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	h := clientip.Middleware(func() *clientip.Resolver { return named },
		g.Wrap(Site, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	// A prefetch from a slowed source is refused at once, so one request
	// says whether the slowing held.
	prefetch := func(xff string) int {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.10:443"
		r.Header.Set("Sec-Purpose", "prefetch")
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := prefetch(""); code != http.StatusServiceUnavailable {
		t.Fatalf("a named proxy's own request was not slowed: %d", code)
	}
	if code := prefetch("203.0.113.10"); code != http.StatusOK {
		t.Fatalf("a client was slowed for the proxy it came through: %d", code)
	}
}

func TestABlockTakenFromEitherLogHolds(t *testing.T) {
	g := guard(t)
	put(t, g, ok(Block, "source:"+audit.Pseudonym(testKey, "[2001:db8::7]")))
	if _, blocked := g.Blocked("2001:db8::7", Site, t0); !blocked {
		t.Fatal("the bracketed handle did not hold")
	}
	if _, blocked := g.Blocked("2001:db8::8", Site, t0); blocked {
		t.Fatal("blocked a neighbour")
	}
}

func TestFindFreezeAndLockdownRules(t *testing.T) {
	root := t.TempDir()
	if _, on := Find(root, Agent, "triage", t0); on {
		t.Fatal("found in an empty store")
	}
	Apply(root, ok(Agent, "triage"), t0)
	if _, on := Find(root, Agent, "triage", t0); !on {
		t.Fatal("not found")
	}
	if _, on := Find(root, Agent, "writer", t0); on {
		t.Fatal("found another agent")
	}
	err := &FrozenError{P: Protection{Until: t0.Add(time.Hour), Reason: "A decoy was touched"}}
	if !strings.Contains(err.Error(), "13:00 UTC") || !strings.Contains(err.Error(), "Rolling back still works") {
		t.Fatal(err)
	}
	lock := Protection{At: t0}
	if !LockedOut(lock, t0.Add(-time.Second).Unix(), false) {
		t.Fatal("a token from before was let in")
	}
	if LockedOut(lock, t0.Add(-time.Hour).Unix(), true) {
		t.Fatal("a passkey was refused")
	}
	if LockedOut(lock, t0.Unix(), false) {
		t.Fatal("a token made as it began was refused")
	}
}

func TestARefusalAnswersInTheRequestersOwnTerms(t *testing.T) {
	p := Protection{ID: "sh-1a2b3c4d", Until: t0.Add(47 * time.Minute)}
	ask := func(path, accept string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		w := httptest.NewRecorder()
		Refuse(w, r, p, t0)
		return w
	}
	html := ask("/", "text/html,application/xhtml+xml")
	if ct := html.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") ||
		!strings.Contains(html.Body.String(), "sh-1a2b3c4d") || !strings.Contains(html.Body.String(), "12:50 UTC") {
		t.Fatalf("html: %s %s", ct, html.Body.String())
	}
	// Its style is allowed by its hash and nothing else is allowed at all.
	csp := html.Header().Get("Content-Security-Policy")
	sum := sha256.Sum256([]byte(refusalStyle))
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, base64.StdEncoding.EncodeToString(sum[:])) ||
		!strings.Contains(html.Body.String(), "<style>"+refusalStyle+"</style>") {
		t.Fatalf("csp %q", csp)
	}
	for _, path := range []string{"/api/v1/pages", "/mcp", "/scim/v2/Users"} {
		j := ask(path, "")
		var doc map[string]any
		if j.Header().Get("Content-Type") != "application/problem+json" || json.Unmarshal(j.Body.Bytes(), &doc) != nil ||
			doc["status"] != float64(429) || doc["reference"] != "sh-1a2b3c4d" {
			t.Fatalf("%s: %s %s", path, j.Header().Get("Content-Type"), j.Body.String())
		}
	}
	if txt := ask("/x", "*/*"); !strings.HasPrefix(txt.Header().Get("Content-Type"), "text/plain") || txt.Body.Len() == 0 || txt.Body.Len() > 1024 {
		t.Fatalf("text: %q", txt.Body.String())
	}
	// The jitter is the same for the same protection, and never takes
	// the time earlier.
	a, b := ask("/", ""), ask("/", "")
	if a.Header().Get("Retry-After") != b.Header().Get("Retry-After") {
		t.Fatal("the jitter changes between asks")
	}
	if secs, _ := strconv.Atoi(a.Header().Get("Retry-After")); secs < 50*60 {
		t.Fatalf("earlier than the rounded end: %d", secs)
	}
}
