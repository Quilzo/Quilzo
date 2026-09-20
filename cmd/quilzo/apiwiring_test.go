// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"strings"
	"testing"
)

// The API mounted inside the admin is wired like the one that stands alone.
//
// It was not. `quilzo site` gave its API server a Throttle, a ReloadTokens and
// an OnAuthFailure; `quilzo serve` gave it none of the three, and every
// throttle call in internal/api is guarded by `if s.Throttle != nil`. So the
// bearer endpoint under `quilzo serve` had no failed-authentication limit at
// all — tokens spent against it at line rate, uncounted, undelayed, no alert —
// while the same guesses against the admin's own screens were refused after
// five. Measured against the running server: twelve bad bearer tokens, twelve
// 401s.
//
// With ReloadTokens nil a token revoked in another process also kept
// authenticating there until an admin request happened to reload the store.
//
// A source check rather than a request, because the wiring is the defect: the
// handler behaves correctly when it is given the parts, and the parts were not
// given.
func TestTheEmbeddedAPIIsWiredLikeTheStandaloneOne(t *testing.T) {
	body, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, "apiSrv := &api.Server{")
	if start < 0 {
		t.Fatal("no API server is constructed in serve.go")
	}
	block := src[start:]
	if end := strings.Index(block, "\n\tsrv.API = "); end > 0 {
		block = block[:end]
	}

	for _, want := range []struct{ field, why string }{
		{"Throttle:", "so a failed bearer authentication is counted and " +
			"delayed, the way one against the admin's own screens is"},
		{"ReloadTokens:", "so a token revoked in another process stops " +
			"working here without waiting for something else to reload"},
		{"OnAuthFailure", "so crossing the failure threshold is recorded " +
			"rather than reached in silence"},
	} {
		if !strings.Contains(block, want.field) &&
			!strings.Contains(src[start:], "apiSrv."+strings.TrimSuffix(want.field, ":")) {
			t.Errorf("the API mounted in the admin has no %s — %s",
				want.field, want.why)
		}
	}

	// And the limiter is the admin's own, not a second one: an attacker who
	// finds one door throttled must not get a fresh allowance at the other.
	if !strings.Contains(block, "Throttle:     srv.Throttle") &&
		!strings.Contains(block, "Throttle: srv.Throttle") {
		t.Error("the API has a limiter of its own rather than sharing the " +
			"admin's, so failures against the two surfaces are counted apart")
	}
}
