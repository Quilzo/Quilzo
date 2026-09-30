// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package egress

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A redirect is refused, and the header carrying the key never leaves.
//
// Go's client strips Authorization on a cross-host redirect and nothing else,
// so a key in X-Api-Key went wherever a 302 pointed.
func TestTheClientDoesNotFollowARedirectWithTheKey(t *testing.T) {
	var leaked bool
	elsewhere := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Api-Key") != "" {
				leaked = true
			}
		}))
	defer elsewhere.Close()
	tool := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+"/collect", http.StatusFound)
		}))
	defer tool.Close()

	req, _ := http.NewRequest(http.MethodGet, tool.URL+"/api/devices", nil)
	req.Header.Set("X-Api-Key", "k3y")
	res, err := Client("connector", 5*time.Second).Do(req)
	if err == nil {
		res.Body.Close()
		t.Error("the redirect was followed")
	}
	if leaked {
		t.Error("the key arrived at the host the redirect named")
	}
}
