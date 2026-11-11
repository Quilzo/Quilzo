// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Find offers the screens the menu offers. It asked its own copy of the
// menu's question, about the whole site, so a screen shown for an area was
// in somebody's menu and missing from what they found: a reader who also
// administers the security area had Shield beside them and no Shield when
// they searched for it.
func TestFindOffersTheScreensTheMenuOffers(t *testing.T) {
	srv, _ := setup(t)
	for _, b := range []auth.Binding{
		{Principal: "sam", Role: auth.RoleReader, Resource: "/"},
		{Principal: "sam", Role: auth.RoleAdmin, Resource: auth.AreaSecurity},
	} {
		if err := srv.Policy.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	tok, _, err := srv.Tokens.IssueSession("passkey:sam", "sam", srv.roleFor("sam"), "/", time.Hour,
		auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	body := get(t, srv, "/find?q=shield", tok).Body.String()
	whole(t, body)
	if !strings.Contains(menuOf(t, body), `href="/security/shield"`) {
		t.Fatal("the menu does not offer Shield, so this proves nothing")
	}
	results := body[strings.Index(body, "<h1>Find</h1>"):]
	if !strings.Contains(results, `<a href="/security/shield">Shield</a>`) {
		t.Errorf("Find does not find Shield, which the menu beside it offers:\n%s", firstLines(results, 30))
	}
}
