// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shield

import (
	"net/http"
	"net/netip"
	"net/http/httptest"
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
	if _, _, err := Apply(g.Root, p, time.Now()); err != nil {
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
	if w.Code != http.StatusForbidden || reached != 0 {
		t.Fatalf("blocked source reached the site: %d", w.Code)
	}
	if secs, _ := strconv.Atoi(w.Header().Get("Retry-After")); secs < 3500 || secs > 3601 {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "testing") {
		t.Fatalf("headers %v body %q", w.Header(), w.Body.String())
	}
	if w := get("203.0.113.10:4000", "", h); w.Code != http.StatusOK || reached != 1 {
		t.Fatal("another source was refused")
	}
	// Behind a named proxy, the address it forwards is the one judged.
	if w := get("10.0.0.2:4000", "203.0.113.9", h); w.Code != http.StatusForbidden {
		t.Fatal("the forwarded address was not judged")
	}
	// A request from inside, or whose client cannot be told, is not
	// refused: refusing it is refusing whoever shares the proxy.
	if w := get("10.0.0.2:4000", "", h); w.Code != http.StatusOK {
		t.Fatal("the proxy itself was refused")
	}
	if w := get("10.0.0.2:4000", "garbage", h); w.Code != http.StatusOK {
		t.Fatal("an unknown client was refused")
	}
	// A caller who is not the proxy cannot name somebody else, or escape.
	if w := get("203.0.113.9:4000", "198.51.100.1", h); w.Code != http.StatusForbidden {
		t.Fatal("a blocked source escaped by writing a header")
	}
	// A request from a named proxy itself (a CDN's health check), even one
	// on a network somebody blocked, is from inside, and passes.
	cdn := &clientip.Resolver{Proxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	b := ok(Block, "net:192.0.2.0/24")
	b.Until, b.Where = time.Now().Add(time.Hour), Site
	if _, _, err := Apply(g.Root, b, time.Now()); err != nil {
		t.Fatal(err)
	}
	g.Refresh()
	viaCDN := clientip.Middleware(func() *clientip.Resolver { return cdn },
		g.Wrap(Site, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	if w := get("192.0.2.10:443", "", viaCDN); w.Code != http.StatusOK {
		t.Fatal("the proxy's own request was refused")
	}
	if w := get("192.0.2.10:443", "203.0.113.9", viaCDN); w.Code != http.StatusForbidden {
		t.Fatal("a blocked client came through the proxy")
	}
	// The admin is a different surface.
	if w := get("203.0.113.9:4000", "", edge(g.Wrap(Admin, http.NotFoundHandler()))); w.Code != http.StatusNotFound {
		t.Fatal("a site block reached the admin")
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
