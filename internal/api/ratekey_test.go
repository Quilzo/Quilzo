// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A session spends the allowance of the token it was exchanged from, and
// the token spends its sessions'.
//
// The limit was kept by each token's own id. A token is exchanged for a
// session that lasts minutes as often as its holder likes (RFC 8693), and
// every session was a caller the limit had never seen, so one credential
// took a whole burst with each: the limit that says one credential is not
// to be the load held nobody who exchanged. Another person's token is not
// slowed by any of it.
func TestASessionSpendsItsTokensAllowance(t *testing.T) {
	s, tok, other := setup(t)
	at := time.Now()
	s.Now = func() time.Time { return at }
	s.Limits = Limits{PerMinute: 60, Burst: 3}

	get := func(bearer string) int {
		t.Helper()
		return req(t, s, "GET", "/api/v1/pages/index", bearer, nil, nil).Code
	}
	session := func() string {
		t.Helper()
		secret, _, err := s.Tokens.Exchange(tok, auth.RoleReader, "/", 5*time.Minute, at)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	for i := range 2 {
		if code := get(session()); code != http.StatusOK {
			t.Fatalf("session %d, inside the burst: %d", i+1, code)
		}
	}
	if code := get(tok); code != http.StatusOK {
		t.Fatalf("the token itself, third of a burst of three: %d", code)
	}
	if code := get(session()); code != http.StatusTooManyRequests {
		t.Errorf("a new session after the burst was spent was answered %d, a fresh allowance", code)
	}
	if code := get(tok); code != http.StatusTooManyRequests {
		t.Errorf("the token after its sessions spent the burst was answered %d", code)
	}
	if code := get(other); code != http.StatusOK {
		t.Errorf("another token was answered %d for the first one's requests", code)
	}
}
