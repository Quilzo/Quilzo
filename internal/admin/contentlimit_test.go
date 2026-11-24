// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// A credential limited to content types or locales is limited here, as on
// the content API.
//
// can and allows asked CheckCredential, which read the read-only dimension
// and nothing else of the scope, so an administrator's token issued `--types
// policy` saved the product page and wrote the products collection through
// this interface, and one issued `--locales fr` saved the English page.
func TestATokenLimitedToTypesOrLocalesIsLimitedInTheAdmin(t *testing.T) {
	srv, _ := setup(t)
	if _, err := site.SaveDraft(srv.Store, map[string]any{
		"index":   map[string]any{"title": "Home"},
		"pen":     map[string]any{"title": "Brass pen", "locale": "en"},
		"returns": map[string]any{"title": "Returns", "locale": "fr"},
	}, "typed", "test"); err != nil {
		t.Fatal(err)
	}
	types := &schema.Store{Registry: schema.NewRegistry(), Bound: map[string]string{
		"pen": "product", "returns": "policy"}}
	srv.Types = &Types{Load: func() (*schema.Store, error) { return types, nil }}
	srv.MFAFrom = time.Now().Add(time.Hour)

	byType := principal{Name: "editor", Role: auth.RoleAdmin, Scope: "/",
		Limits: auth.Scope{Types: []string{"policy"}}}
	byLocale := principal{Name: "editor", Role: auth.RoleAdmin, Scope: "/",
		Limits: auth.Scope{Locales: []string{"fr"}}}
	for _, tc := range []struct {
		who      principal
		resource string
		may      bool
	}{
		{byType, "/pen", false},
		{byType, "/returns", true},
		{byType, "/index", true},
		{byType, auth.DataResource("products"), false},
		{byType, auth.DataResource("policy"), true},
		{byLocale, "/pen", false},
		{byLocale, "/returns", true},
		{byLocale, "/index", true},
	} {
		if got := srv.allows(tc.who, auth.ActEditDraft, tc.resource); got != tc.may {
			t.Errorf("limited to %s, writing %s: allowed %v, want %v", tc.who.Limits, tc.resource, got, tc.may)
		}
	}

	secret, _, err := srv.Tokens.IssueScoped("types", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin,
		auth.Scope{Types: []string{"policy"}})
	if err != nil {
		t.Fatal(err)
	}
	if w := postForm(t, srv, "/save", secret, "__name=pen&title=Changed"); w.Code != http.StatusForbidden {
		t.Errorf("a token limited to policy saved the product page: %d", w.Code)
	}
}
