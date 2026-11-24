// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	"github.com/quilzo/quilzo/internal/auth"
)

// Routes a host serves beside the content API, behind the same door.
//
// The security record's routes (the profile, the public instance's
// attestations) are answered by the program that holds the store, not by
// this package, which knows nothing of where those files live. They are
// still the API, and a route under /api/v1 that skipped the token, the rate
// limit, the failed-authentication throttle, the shield and the refusal of
// cross-origin requests would be a second, weaker door to the same server.
// So a host puts its handler behind Guard, and the handler reads the token
// the request was authenticated with from TokenOf.

// Guard is next behind this API's middleware. Call it after Handler, so the
// two share one rate limit.
func (s *Server) Guard(next http.Handler) http.Handler {
	if s.limiter == nil {
		s.limiter = newLimiter(s.Limits)
	}
	return s.middleware(next)
}

// TokenOf is the token a request behind Guard was authenticated with, nil
// for a request that did not come through it.
func TokenOf(r *http.Request) *auth.Token { return tokenFrom(r) }
