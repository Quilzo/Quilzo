// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
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
	srv, token := tokenSignIn(t)
	withSettings(t, srv, map[string]string{"session.max": "30m"})
	c := sessionCookie(t, srv, token)
	if c.MaxAge < 1790 || c.MaxAge > 1800 {
		t.Fatalf("the cookie lasts %ds, not thirty minutes", c.MaxAge)
	}
	srv2, token2 := tokenSignIn(t)
	withSettings(t, srv2, map[string]string{"session.max": "8h"})
	if c := sessionCookie(t, srv2, token2); c.MaxAge > 3600 {
		t.Fatalf("a session outlived its credential: %ds", c.MaxAge)
	}
}

// Nobody using the page for session.idle ends the session; a person
// typing, or the page saying so, keeps it; a screen refreshing itself
// does not.
func TestASessionNobodyUsesEnds(t *testing.T) {
	srv, token := tokenSignIn(t)
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

// Anybody who can grant access is signed out after fifteen minutes unused,
// whatever session.idle allows everybody else; and the idle sign-out is on
// with no settings at all.
func TestWhoCanGrantAccessIsSignedOutSooner(t *testing.T) {
	srv, token := tokenSignIn(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "pat", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	pat, _, err := srv.Tokens.Issue("p", "pat", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	person := map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1"}
	for _, c := range []struct {
		settings map[string]string
		token    string
		want     string
	}{
		{nil, token, `content="900"`},
		{nil, pat, `content="3600"`},
		{map[string]string{"session.idle": "20m"}, pat, `content="1200"`},
		{map[string]string{"session.idle": "10m"}, token, `content="600"`},
	} {
		srv.Settings = nil
		if c.settings != nil {
			withSettings(t, srv, c.settings)
		}
		body := browse(srv, http.MethodGet, "/", sessionCookie(t, srv, c.token), person).Body.String()
		if !strings.Contains(body, `name="quilzo-idle" `+c.want) || !strings.Contains(body, `name="quilzo-who"`) {
			t.Errorf("%v: wanted %s", c.settings, c.want)
		}
	}

	// And the server holds to it: sixteen minutes unused ends the
	// administrator's session and not the author's.
	srv.Settings = nil
	for _, c := range []struct {
		token string
		ends  bool
	}{{token, true}, {pat, false}} {
		cookie := sessionCookie(t, srv, c.token)
		browse(srv, http.MethodGet, "/", cookie, person)
		tok, _ := srv.Tokens.Authenticate(cookie.Value, time.Now())
		srv.idle.mu.Lock()
		srv.idle.last[tok.ID] = time.Now().Add(-16 * time.Minute)
		srv.idle.mu.Unlock()
		w := browse(srv, http.MethodGet, "/", cookie, person)
		if ended := strings.Contains(w.Header().Get("Location"), "e=idle"); ended != c.ends {
			t.Errorf("%s after sixteen minutes: %d %s", tok.Principal, w.Code, w.Header().Get("Location"))
		}
	}
}

// A sign-in session nobody uses ends after session.idle however it is
// presented: carried in an Authorization header to the admin's screens or
// to /mcp, and at the content API the admin mounts (IdleEnded), as well
// as in the cookie. A long-lived token is not a session, and a program
// holding one is not signed out for idling.
//
// The clock was kept only for a request with the cookie and no header. A
// passkey session's value sent as "Authorization: Bearer" is a session at
// two factors, which the bearer gate lets through, and it worked for the
// rest of session.max with nobody using it, while the same session in a
// browser was signed out after session.idle.
func TestASessionNobodyUsesEndsHoweverItIsPresented(t *testing.T) {
	r := newIfaceRig(t)
	r.oauth = false
	srv := r.srv
	withSettings(t, srv, map[string]string{"session.idle": "10m"})
	session := func() (string, auth.Token) {
		t.Helper()
		secret, tok, err := srv.Tokens.IssueSession("passkey:editor", "editor", auth.RoleAdmin, "/",
			time.Hour, auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		return secret, tok
	}
	unused := func(id string) {
		srv.idle.mu.Lock()
		if srv.idle.last == nil {
			srv.idle.last = map[string]time.Time{}
		}
		srv.idle.last[id] = time.Now().Add(-11 * time.Minute)
		srv.idle.mu.Unlock()
	}
	ended := func(secret string) bool {
		_, err := srv.Tokens.Authenticate(secret, time.Now())
		return err != nil
	}

	// The admin's screens.
	secret, tok := session()
	if w := get(t, srv, "/", secret); w.Code != http.StatusOK {
		t.Fatalf("first use in a header: %d", w.Code)
	}
	unused(tok.ID)
	if w := get(t, srv, "/", secret); w.Code == http.StatusOK || !ended(secret) {
		t.Errorf("a session in a header unused for eleven minutes still works at the screens: %d", w.Code)
	}

	// The agent interface.
	secret, tok = session()
	if w := r.mcpCall(t, secret); w.Code != http.StatusOK {
		t.Fatalf("first use at /mcp: %d %s", w.Code, w.Body)
	}
	unused(tok.ID)
	if w := r.mcpCall(t, secret); w.Code == http.StatusOK || !ended(secret) {
		t.Errorf("a session unused for eleven minutes still works at /mcp: %d", w.Code)
	}

	// The content API, which asks the admin's clock.
	secret, tok = session()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pages", nil)
	used, err := srv.Tokens.Authenticate(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if srv.IdleEnded(req, used) {
		t.Fatal("a session used a moment ago was ended")
	}
	unused(tok.ID)
	if !srv.IdleEnded(req, used) || !ended(secret) {
		t.Error("a session unused for eleven minutes still works at the content API")
	}

	// A program's long-lived token is nobody's session.
	program, ptok, err := srv.Tokens.Issue("ci", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	r.mcpCall(t, program)
	unused(ptok.ID)
	if w := r.mcpCall(t, program); w.Code != http.StatusOK || ended(program) {
		t.Errorf("a long-lived token in a header was signed out for idling: %d", w.Code)
	}
	if srv.IdleEnded(req, &ptok) {
		t.Error("the content API ended a long-lived token for idling")
	}
}

// A session at the agent interface is timed by the access rules as they
// are stored now, as its credentials are read there (storedTokens), and
// the clock reads nothing a screen's refresh puts in place while it runs.
// Run with -race.
//
// IdleEnded asked s.Policy, the copy the last screen anybody opened had
// read. So somebody made an administrator on the command line kept the
// whole of session.idle at /mcp, not the quarter of an hour anybody who
// can grant access has, until a screen was opened; and a call at /mcp
// made while a screen opened read the field that screen was replacing,
// which the race detector reported at the first call.
func TestASessionAtTheInterfaceIsTimedByTheRulesAsTheyAreStored(t *testing.T) {
	r := newIfaceRig(t)
	r.oauth = false
	srv := r.srv
	session := func() (string, auth.Token) {
		t.Helper()
		secret, tok, err := srv.Tokens.IssueSession("passkey:sam", "sam", auth.RoleReader, "/",
			time.Hour, auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		return secret, tok
	}
	idle, tok := session()
	busy, _ := session()
	// What this server was started with says sam reads; what is stored
	// now says sam administers the site.
	held := &auth.Policy{}
	stored := &auth.Policy{}
	for _, b := range []auth.Binding{{Principal: "editor", Role: auth.RoleAdmin, Resource: "/"},
		{Principal: "sam", Role: auth.RoleReader, Resource: "/"}} {
		if err := held.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range []auth.Binding{{Principal: "editor", Role: auth.RoleAdmin, Resource: "/"},
		{Principal: "sam", Role: auth.RoleAdmin, Resource: "/"}} {
		if err := stored.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	srv.Policy = held
	// Read under a reader's lock, which orders nothing between two
	// readers, so a race between the doors is not hidden by this.
	var mu sync.RWMutex
	tokens, _ := json.Marshal(srv.Tokens)
	rules, _ := json.Marshal(stored)
	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		mu.RLock()
		defer mu.RUnlock()
		pol, toks := &auth.Policy{}, &auth.TokenStore{}
		if err := json.Unmarshal(rules, pol); err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(tokens, toks); err != nil {
			return nil, nil, err
		}
		return pol, toks, nil
	}
	srv.SaveTokens = func(ts *auth.TokenStore) error {
		b, err := json.Marshal(ts)
		mu.Lock()
		defer mu.Unlock()
		tokens = b
		return err
	}

	// Twenty minutes unused is past what an administrator may leave it.
	if w := r.mcpCall(t, idle); w.Code != http.StatusOK {
		t.Fatalf("first use at /mcp: %d %s", w.Code, w.Body)
	}
	srv.idle.mu.Lock()
	srv.idle.last[tok.ID] = time.Now().Add(-20 * time.Minute)
	srv.idle.mu.Unlock()
	if w := r.mcpCall(t, idle); w.Code == http.StatusOK {
		t.Errorf("an administrator's session unused for twenty minutes still works at /mcp: %d", w.Code)
	}
	if _, toks, _ := srv.Reload(); toks != nil {
		if _, err := toks.Authenticate(idle, time.Now()); err == nil {
			t.Error("the session ended for idling is not revoked where the credentials are stored")
		}
	}

	// Calls at /mcp while a screen opens, each reading the rules for itself.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 20 {
			get(t, srv, "/", r.token)
		}
	}()
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				if w := r.mcpCall(t, busy); w.Code != http.StatusOK {
					t.Errorf("a session in use at /mcp: %d %s", w.Code, w.Body)
				}
			}
		}()
	}
	wg.Wait()
}
