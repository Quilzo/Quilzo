// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A passkey signs its person in with everything they hold, so a session
// narrowed to part of the store, a lesser role or reading only cannot add
// one — it would otherwise turn a leaked narrow token into the whole person,
// lasting past the token's revocation — nor take one away.
func TestOnlyAFullReachSessionManagesPasskeys(t *testing.T) {
	srv, full := fullyWired(t)
	narrow, _, err := srv.Tokens.Issue("ci", "editor", auth.RoleAuthor, "/blog", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if w := postJSON(t, srv, "/passkeys/challenge", narrow, nil); w.Code != http.StatusForbidden {
		t.Errorf("a session narrowed to /blog as an author was offered enrolment: %d %s", w.Code, w.Body)
	}
	if w := postJSON(t, srv, "/passkeys/register", narrow, map[string]any{"challenge": "x"}); w.Code != http.StatusForbidden {
		t.Errorf("a narrowed session reached registration: %d", w.Code)
	}
	limited, _, err := srv.Tokens.IssueScoped("types", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin,
		auth.Scope{Types: []string{"article"}})
	if err != nil {
		t.Fatal(err)
	}
	if w := postJSON(t, srv, "/passkeys/challenge", limited, nil); w.Code != http.StatusForbidden {
		t.Errorf("a session limited to one content type was offered enrolment: %d", w.Code)
	}
	// The person's own full session still can, and a key added there cannot
	// be removed from the narrow one.
	f := newFake(t, "credential-reach")
	f.register(t, srv, full)
	if len(srv.Passkeys.Credentials) != 1 {
		t.Fatalf("the full session could not enrol: %d keys", len(srv.Passkeys.Credentials))
	}
	req := httptest.NewRequest(http.MethodPost, "https://"+testHost+"/passkeys/remove",
		bytes.NewReader([]byte("id="+enc(f.id))))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+narrow)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if len(srv.Passkeys.Credentials) != 1 {
		t.Errorf("a narrowed session removed its person's passkey (%d)", w.Code)
	}
}

// Behind a proxy that terminates TLS, the request reaches the admin as plain
// HTTP; with admin.behind_tls_proxy set, passkeys work there, and without it
// they are refused as before.
func TestPasskeysWorkBehindATLSProxy(t *testing.T) {
	srv, token := fullyWired(t)
	plain := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://"+testHost+"/passkeys/challenge", nil)
		req.Host = testHost
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := plain(); w.Code != http.StatusBadRequest {
		t.Errorf("plain HTTP with no proxy declared was accepted: %d", w.Code)
	}
	withSettings(t, srv, map[string]string{"admin.behind_tls_proxy": "true"})
	if w := plain(); w.Code != http.StatusOK {
		t.Errorf("behind a declared TLS proxy, enrolment was refused: %d %s", w.Code, w.Body)
	}
}
