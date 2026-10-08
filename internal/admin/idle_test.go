// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/config"
)

func withSettings(t *testing.T, srv *Server, values map[string]string) {
	t.Helper()
	cfg := config.New()
	for k, v := range values {
		if err := cfg.Set(k, v, "test", "test"); err != nil {
			t.Fatal(err)
		}
	}
	srv.Settings = &Settings{Load: func() (*config.Config, error) { return cfg, nil },
		Save: func(*config.Config) error { return nil }}
}

func sessionCookie(t *testing.T, srv *Server, token string) *http.Cookie {
	t.Helper()
	w := signInPost(srv, token)
	for _, c := range w.Result().Cookies() {
		if c.Name == "quilzo_token" && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie: %d %s", w.Code, w.Header().Get("Location"))
	return nil
}

func browse(srv *Server, method, path string, c *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(c)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", "http://example.com")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// A sign-in lasts session.max, whatever signed somebody in — and never
// longer than the credential it came from, which in this test is an hour.
func TestASignInLastsWhatTheOrganisationSays(t *testing.T) {
	srv, token := setup(t)
	withSettings(t, srv, map[string]string{"session.max": "30m"})
	c := sessionCookie(t, srv, token)
	if c.MaxAge < 1790 || c.MaxAge > 1800 {
		t.Fatalf("the cookie lasts %ds, not thirty minutes", c.MaxAge)
	}
	srv2, token2 := setup(t)
	withSettings(t, srv2, map[string]string{"session.max": "8h"})
	if c := sessionCookie(t, srv2, token2); c.MaxAge > 3600 {
		t.Fatalf("a session outlived its credential: %ds", c.MaxAge)
	}
}

// Nobody using the page for session.idle ends the session; a person
// typing, or the page saying so, keeps it; a screen refreshing itself
// does not.
func TestASessionNobodyUsesEnds(t *testing.T) {
	srv, token := setup(t)
	withSettings(t, srv, map[string]string{"session.idle": "10m"})
	c := sessionCookie(t, srv, token)
	person := map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1"}
	itself := map[string]string{"Sec-Fetch-Mode": "navigate"}

	if w := browse(srv, http.MethodGet, "/", c, person); w.Code != http.StatusOK {
		t.Fatalf("first use: %d", w.Code)
	}
	if body := browse(srv, http.MethodGet, "/", c, person).Body.String(); !strings.Contains(body, `name="quilzo-idle" content="600"`) {
		t.Fatal("the page is not told the idle period, so it cannot warn")
	}

	// Nine minutes of a screen refreshing itself, then the page says
	// somebody is there: still signed in, and the clock restarts.
	srv.idle.mu.Lock()
	srv.idle.last[srv.idle.anyID()] = time.Now().Add(-9 * time.Minute)
	srv.idle.mu.Unlock()
	if w := browse(srv, http.MethodGet, "/", c, itself); w.Code != http.StatusOK {
		t.Fatalf("a refresh within the period: %d", w.Code)
	}
	if w := browse(srv, http.MethodPost, "/session/alive", c, nil); w.Code != http.StatusNoContent {
		t.Fatalf("alive: %d %s", w.Code, w.Body.String())
	}
	srv.idle.mu.Lock()
	fresh := time.Since(srv.idle.last[srv.idle.anyID()]) < time.Minute
	srv.idle.mu.Unlock()
	if !fresh {
		t.Fatal("the page saying somebody is there did not count")
	}

	// Eleven minutes: the next request ends it, says why, and the cookie
	// is no longer a credential.
	srv.idle.mu.Lock()
	srv.idle.last[srv.idle.anyID()] = time.Now().Add(-11 * time.Minute)
	srv.idle.mu.Unlock()
	w := browse(srv, http.MethodGet, "/", c, itself)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "e=idle") {
		t.Fatalf("an idle session was not ended: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := browse(srv, http.MethodGet, "/", c, person); w.Code == http.StatusOK {
		t.Fatal("the ended session still works")
	}

	// A program holding a token in a header is not a browser left open.
	if w := get(t, srv, "/", token); w.Code != http.StatusOK {
		t.Fatalf("a bearer token was signed out for idling: %d", w.Code)
	}
}

// anyID is the one session the test has.
func (c *idleClock) anyID() string {
	for id := range c.last {
		return id
	}
	return ""
}
