// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/throttle"
)

// A token refused at /mcp because the admin is locked down is told so,
// with when it ends, from an address throttled or not, and is not counted
// as a failed attempt, as the content API answers it.
//
// It was counted. A client polling with a token made before the lockdown
// pushed its own address past the throttle in six calls, and from then on
// it, and every other client behind that address, was told "too many
// failed attempts from this address" where the lockdown and its end were
// what there was to know.
func TestALockdownIsSaidAsItselfAtTheInterface(t *testing.T) {
	r := newIfaceRig(t)
	r.oauth = false
	r.srv.Throttle = throttle.New(throttle.Default())
	r.srv.Tokens.Admit = func(auth.Credential) error {
		return fmt.Errorf("%w (until about 15:04 UTC)", auth.ErrLockedDown)
	}
	check := func(when string) {
		t.Helper()
		w := r.mcpCall(t, r.token)
		if b := w.Body.String(); w.Code != http.StatusUnauthorized || !strings.Contains(b, "until about 15:04 UTC") ||
			strings.Contains(b, "too many") {
			t.Fatalf("%s, a token from before the lockdown was answered %d %s", when, w.Code, b)
		}
	}
	for range 12 {
		check("polling from a quiet address")
	}
	if st := r.srv.Throttle.State(); len(st) != 0 {
		t.Fatalf("a lockdown's refusals were counted as failed attempts: %+v", st)
	}
	for range 10 {
		r.mcpCall(t, "qz_"+strings.Repeat("x", 52))
	}
	check("from an address throttled for somebody else's guesses")
}
