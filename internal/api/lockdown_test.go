// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/throttle"
)

// A real token refused because the admin is locked down is told so, and
// what to do, from an address throttled or not, and is not counted as a
// failure.
//
// It was answered as if nothing had been sent: 401 "not authenticated",
// with "send a token: Authorization: Bearer qz_..." as the fix, to a client
// that had sent a valid one. The admin's own screens say it is the
// lockdown and when it ends; the program calling this was left to suspect
// its token.
func TestALockdownIsSaidAsItselfToAValidToken(t *testing.T) {
	s, tok, _ := setup(t)
	s.Throttle = throttle.New(throttle.Default())
	s.Tokens.Admit = func(auth.Credential) error {
		return fmt.Errorf("%w (until about 15:04 UTC)", auth.ErrLockedDown)
	}
	check := func(when string) {
		t.Helper()
		w := req(t, s, "GET", "/api/v1/pages/index", tok, nil, nil)
		var e Error
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
			t.Fatalf("not JSON: %s", w.Body)
		}
		if w.Code != http.StatusUnauthorized || strings.Contains(e.Fix, "Bearer qz_") || e.Error == "not authenticated" ||
			!strings.Contains(e.Error, "locked down") || !strings.Contains(e.Detail, "until about 15:04 UTC") ||
			!strings.Contains(e.Fix, "made since") {
			t.Errorf("%s, a valid token during a lockdown was answered %d %+v", when, w.Code, e)
		}
	}
	// Eleven times: counted as failures, the last would be throttled.
	for range 11 {
		check("from a quiet address")
	}
	for range 10 {
		req(t, s, "GET", "/api/v1/pages/index", "qz_"+strings.Repeat("x", 52), nil, nil)
	}
	check("from an address throttled for somebody else's guesses")
}
