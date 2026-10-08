// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// TestTheLogNamesPeopleInDetailsItKnows. Details naming a person are stored
// pseudonymised; the screen names the ones this store can, and leaves a
// stranger opaque, exactly as it does for the principal.
func TestTheLogNamesPeopleInDetailsItKnows(t *testing.T) {
	srv, token := setup(t)
	srv.LoadAudit = func() ([]audit.Event, error) {
		return []audit.Event{{Seq: 1, At: "2026-09-29T10:00:00Z", Action: "grant",
			Resource: "/", Outcome: audit.Success, Principal: "p_service", Kind: audit.KindHuman,
			Detail: map[string]string{"by": "p_admin", "on_behalf_of": "p_stranger", "role": "author"}}}, nil
	}
	srv.ResolvePrincipal = func(p string) string {
		if p == "p_admin" {
			return "dana"
		}
		return ""
	}
	body := get(t, srv, "/logs", token).Body.String()
	if !strings.Contains(body, "dana") || !strings.Contains(body, "p_stranger") ||
		!strings.Contains(body, "author") {
		t.Fatalf("details were not resolved as expected:\n%s", firstLines(body, 80))
	}
}
