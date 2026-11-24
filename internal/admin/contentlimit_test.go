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

// A credential limited to some languages saves a page in those languages
// only, as the content API's PUT does: the page as the save leaves it is
// asked, and not only the page as it stands.
//
// can asks about the page before the form is read, so a token issued
// `--locales fr` saved the French page as English, and started an English
// page, through the editor.
func TestATokenLimitedToALanguageSavesNoOther(t *testing.T) {
	srv, _ := setup(t)
	if _, err := site.SaveDraft(srv.Store, map[string]any{
		"index":   map[string]any{"title": "Home"},
		"returns": map[string]any{"title": "Retours", "locale": "fr"},
	}, "typed", "test"); err != nil {
		t.Fatal(err)
	}
	srv.MFAFrom = time.Now().Add(time.Hour)
	secret, _, err := srv.Tokens.IssueScoped("fr", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin,
		auth.Scope{Locales: []string{"fr"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		form string
		want int
	}{
		{"__name=returns&title=Returns&locale=en", http.StatusForbidden},
		{"__name=fresh&title=Fresh&locale=en", http.StatusForbidden},
		{"__name=index&title=Home&locale=en", http.StatusForbidden},
		{"__name=returns&title=Retours+et+remboursements&locale=fr", http.StatusSeeOther},
		{"__name=index&title=Accueil&locale=fr", http.StatusSeeOther},
	} {
		if w := postForm(t, srv, "/save", secret, tc.form); w.Code != tc.want {
			t.Errorf("a token limited to French saving %s: %d, want %d", tc.form, w.Code, tc.want)
		}
	}
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pages["fresh"]; ok {
		t.Error("a token limited to French started a page in English")
	}
}

// A credential limited to content types takes no page out of its type, and
// so into its reach, on the Types screen: binding a page and unbinding one
// are asked about the page as well as about the whole site.
//
// Both were asked about the whole site and nothing else, which is no one
// type, so a token issued `--types policy` unbound the product page, or
// bound it to policy, and then saved it.
func TestATokenLimitedToTypesRebindsNoPageOfAnotherType(t *testing.T) {
	srv, _ := setup(t)
	if _, err := site.SaveDraft(srv.Store, map[string]any{
		"pen":     map[string]any{"title": "Brass pen"},
		"returns": map[string]any{"title": "Returns"},
	}, "typed", "test"); err != nil {
		t.Fatal(err)
	}
	reg := schema.NewRegistry()
	for _, name := range []string{"product", "policy"} {
		if err := reg.Add(schema.Type{Name: name, Fields: []schema.Field{{Name: "title", Kind: schema.Text}}}); err != nil {
			t.Fatal(err)
		}
	}
	types := &schema.Store{Registry: reg, Bound: map[string]string{"pen": "product", "returns": "policy"}}
	srv.Types = &Types{
		Load: func() (*schema.Store, error) { return types, nil },
		Save: func(st *schema.Store) error { types = st; return nil },
	}
	srv.MFAFrom = time.Now().Add(time.Hour)
	secret, _, err := srv.Tokens.IssueScoped("types", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin,
		auth.Scope{Types: []string{"policy"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{"page=pen&unbind=1", "page=pen&type=policy"} {
		if w := postForm(t, srv, "/types/bind", secret, form); w.Code != http.StatusForbidden {
			t.Errorf("a token limited to policy posted %s: %d %s", form, w.Code, w.Header().Get("Location"))
		}
		if types.Bound["pen"] != "product" {
			t.Fatalf("a token limited to policy left the product page bound to %q with %s", types.Bound["pen"], form)
		}
	}
	if w := postForm(t, srv, "/types/bind", secret, "page=returns&unbind=1"); w.Code != http.StatusSeeOther {
		t.Errorf("a token limited to policy could not unbind the policy page: %d", w.Code)
	}
	if _, bound := types.Bound["returns"]; bound {
		t.Error("the policy page is still bound after its unbinding was answered")
	}
}
