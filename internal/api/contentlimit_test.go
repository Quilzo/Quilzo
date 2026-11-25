// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/vector"
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

// Somebody granted part of the site, or holding a token confined to it, is
// listed and searched that part.
//
// The listing and the search by meaning asked for view on "/", which a grant
// on /blog does not cover and a token issued `--on /blog` does not reach, so
// both were refused 403 although each leaves out every page the caller may
// not read. They ask now whether the caller may read somewhere in the
// content, and still answer each page by itself.
func TestPartOfTheSiteIsListedOverTheAPI(t *testing.T) {
	s, _, _ := setup(t)
	pages, err := site.PagesAt(s.Store, site.RefLive)
	if err != nil {
		t.Fatal(err)
	}
	pages["blog/first"] = map[string]any{"title": "First", "body": "Hello from the blog."}
	if _, err := site.SaveDraft(s.Store, pages, "blog", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s.Store, ""); err != nil {
		t.Fatal(err)
	}
	idx := vector.Build(s.Store.GetRef(site.RefLive), pages, strings.Fields)
	s.Vectors = func() *vector.Index { return idx }
	s.Tokenise = strings.Fields
	if err := s.Policy.Grant(auth.Binding{Principal: "bea", Role: auth.RoleReader, Resource: "/blog"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Policy.Grant(auth.Binding{Principal: "sam", Role: auth.RoleAdmin, Resource: auth.AreaSecurity}); err != nil {
		t.Fatal(err)
	}
	issue := func(who, on string) string {
		secret, _, err := s.Tokens.Issue("t-"+who+on, who, auth.RoleReader, on, time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		return secret
	}
	for _, tc := range []struct{ who, on string }{{"bea", "/"}, {"reader", "/blog"}} {
		tok := issue(tc.who, tc.on)
		w := req(t, s, "GET", "/api/v1/pages", tok, nil, nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s on %s was refused the listing: %d %s", tc.who, tc.on, w.Code, w.Body)
			continue
		}
		var l Listing
		if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		if l.Total != 1 || len(l.Pages) != 1 || l.Pages[0].Name != "blog/first" {
			t.Errorf("%s on %s was listed %+v", tc.who, tc.on, l)
		}
		w = req(t, s, "GET", "/api/v1/search/vector?q=hello", tok, nil, nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s on %s was refused the search: %d %s", tc.who, tc.on, w.Code, w.Body)
		} else if strings.Contains(w.Body.String(), "pricing") || strings.Contains(w.Body.String(), "about") {
			t.Errorf("%s on %s was answered a page outside /blog: %s", tc.who, tc.on, w.Body)
		}
	}
	// Somebody with nothing in the content is refused, as before.
	if w := req(t, s, "GET", "/api/v1/pages", issue("sam", "/"), nil, nil); w.Code != http.StatusForbidden {
		t.Errorf("somebody with nothing in the content was listed: %d", w.Code)
	}
}

// A token limited to some languages is answered only pages in them by the
// search by meaning and by similar pages, as by the listing and a read.
//
// Both asked each neighbour's language of no fields at all, which gives no
// language, so a token issued `--locales fr` was named the English pages,
// with the words each shared with what it asked; and similar pages did not
// ask about the page it was given.
func TestATokenLimitedToALanguageFindsOnlyPagesInIt(t *testing.T) {
	s, _, _ := setup(t)
	pages := map[string]any{
		"index":   map[string]any{"title": "Home", "body": "hello copper kettle", "locale": "en"},
		"about":   map[string]any{"title": "About", "body": "hello copper kettle", "locale": "en"},
		"pricing": map[string]any{"title": "Tarifs", "body": "hello copper kettle", "locale": "fr"},
		"faq":     map[string]any{"title": "Questions", "body": "hello copper kettle", "locale": "fr"},
	}
	if _, err := site.SaveDraft(s.Store, pages, "languages", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s.Store, ""); err != nil {
		t.Fatal(err)
	}
	idx := vector.Build(s.Store.GetRef(site.RefLive), pages, strings.Fields)
	s.Vectors = func() *vector.Index { return idx }
	s.Tokenise = strings.Fields
	secret, _, err := s.Tokens.IssueScoped("fr", "reader", auth.RoleReader, "/", time.Hour, auth.RoleAdmin,
		auth.Scope{Locales: []string{"fr"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/search/vector?q=copper+kettle", "/api/v1/similar/pricing"} {
		w := req(t, s, "GET", path, secret, nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s answered %d %s", path, w.Code, w.Body)
		}
		var got struct {
			Results []vector.Neighbour `json:"results"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Results) == 0 {
			t.Errorf("%s answered a token limited to French no page at all", path)
		}
		for _, n := range got.Results {
			if l, _ := pages[n.Page].(map[string]any)["locale"].(string); l != "fr" {
				t.Errorf("%s answered a token limited to French %s, which is in %q", path, n.Page, l)
			}
		}
	}
	// And a page in English is not there to be compared with, as get
	// answers it.
	if w := req(t, s, "GET", "/api/v1/similar/about", secret, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("a token limited to French was answered %d for the pages like an English one", w.Code)
	}
}
