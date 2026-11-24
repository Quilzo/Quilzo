// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schema"
)

// A token limited to content types or locales writes the pages it may read
// and no others.
//
// A read was asked about the page's type and language (visibleTo), and a
// write was not: a token issued `--types policy` was answered 404 for the
// product page and replaced it with a PUT, and one issued `--locales fr`
// wrote a page as English.
func TestATokenLimitedToTypesOrLocalesWritesOnlyWhatItMayRead(t *testing.T) {
	s, _, writer := setup(t)
	s.Writable = true
	st, err := schema.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"product", "policy"} {
		if err := st.Registry.Add(schema.Type{Name: name, Fields: []schema.Field{
			{Name: "title", Kind: schema.Text}, {Name: "body", Kind: schema.Text},
			{Name: "locale", Kind: schema.Text}}}); err != nil {
			t.Fatal(err)
		}
	}
	st.Bound = map[string]string{"about": "product", "pricing": "policy"}
	s.Types = func() (*schema.Store, error) { return st, nil }
	limited := func(sc auth.Scope) string {
		secret, _, err := s.Tokens.IssueScoped("limited", "writer", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin, sc)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	put := func(tok, page string, body map[string]any) int {
		return req(t, s, "PUT", "/api/v1/pages/"+page, tok, body, map[string]string{"If-Match": "*"}).Code
	}

	byType := limited(auth.Scope{Types: []string{"policy"}})
	if code := put(byType, "about", map[string]any{"title": "Replaced"}); code < 400 {
		t.Errorf("a token limited to policy replaced the product page: %d", code)
	}
	if code := put(byType, "pricing", map[string]any{"title": "Changed"}); code >= 400 {
		t.Errorf("a token limited to policy may not write the policy page: %d", code)
	}

	byLocale := limited(auth.Scope{Locales: []string{"fr"}})
	if code := put(byLocale, "index", map[string]any{"title": "Home", "locale": "en"}); code < 400 {
		t.Errorf("a token limited to French wrote a page as English: %d", code)
	}
	if code := put(byLocale, "index", map[string]any{"title": "Accueil", "locale": "fr"}); code >= 400 {
		t.Errorf("a token limited to French may not write a page in French: %d", code)
	}
	// A page in English is not one it may read, and is answered as get
	// answers it, as though it were not there.
	if code := put(writer, "about", map[string]any{"title": "About", "locale": "en"}); code >= 400 {
		t.Fatalf("the writer could not write the page in English: %d", code)
	}
	if code := put(byLocale, "about", map[string]any{"title": "Qui", "locale": "fr"}); code != http.StatusNotFound {
		t.Errorf("a token limited to French was answered %d, not 404, for a page it may not read", code)
	}
}
