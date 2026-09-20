// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Signing in is in the log.
//
// It was not. OnSignIn exists and is assigned only inside cmd/quilzo's OIDC
// block, so on the ordinary deployment — a token, or a passkey, and no
// identity provider — the audit log held content changes with no record of
// anybody ever signing in at all. AU-2 asks for the session, not only for what
// was done inside it, and "who was here" is the first question of every
// incident review.
func TestSigningInIsRecorded(t *testing.T) {
	srv, token := setup(t)
	var got []string
	srv.Audit = func(action, resource string, _ map[string]string) {
		got = append(got, action)
	}

	req := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("signing in answered %d", w.Code)
	}

	for _, a := range got {
		if a == "session.start" {
			return
		}
	}
	t.Errorf("signing in left no entry; the log records what somebody did "+
		"and not that they arrived: %v", got)
}
