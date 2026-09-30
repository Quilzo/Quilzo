// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/site"
)

// TestALinkInAPreviewGoesToThePreview.
//
// A previewed page links /about, because that is where readers go. Inside
// the admin that address was a 404, so no link in any preview went anywhere.
func TestALinkInAPreviewGoesToThePreview(t *testing.T) {
	srv, token := setup(t)
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["about"] = map[string]any{"title": "About"}
	if _, err := site.SaveDraft(srv.Store, pages, "about", "test"); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]string{
		"/about":             "/preview/about",
		"/about?ref=nav&x=1": "/preview/about?ref=nav&x=1",
		"/about/some-record": "/preview/about/some-record",
	} {
		w := get(t, srv, path, token)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("%s: %d to %q, want 303 to %q", path, w.Code,
				w.Header().Get("Location"), want)
		}
	}
	// Not a page: still a 404.
	for _, path := range []string{"/no-such-page", "/catalogue.json"} {
		if w := get(t, srv, path, token); w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d to %q", path, w.Code,
				w.Header().Get("Location"))
		}
	}
	// Never off this origin. The router cleans //host to the path /host
	// before any handler runs; whatever answers, it is not another site.
	for _, path := range []string{"//evil.example", "/\\evil.example",
		"/%2F%2Fevil.example"} {
		loc := get(t, srv, path, token).Header().Get("Location")
		if strings.HasPrefix(loc, "//") || strings.HasPrefix(loc, "/\\") ||
			strings.Contains(loc, "://") {
			t.Errorf("%s redirected off this origin: %q", path, loc)
		}
	}
}

// TestPreviewLinksRevealNothingWithoutASignIn.
//
// The redirect says a page by that name exists, so it is only given to
// somebody signed in who may read that page.
func TestPreviewLinksRevealNothingWithoutASignIn(t *testing.T) {
	srv, _ := setup(t)
	if w := get(t, srv, "/index", ""); w.Code == http.StatusSeeOther {
		t.Fatal("an anonymous request learned that a page exists")
	}

	scoped, token := asRole(t, auth.RoleReader)
	_ = scoped
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{Principal: "someone",
		Role: auth.RoleReader, Resource: "/blog"}); err != nil {
		t.Fatal(err)
	}
	scoped.Policy = pol
	if w := get(t, scoped, "/index", token); w.Code == http.StatusSeeOther {
		t.Fatal("somebody scoped to /blog learned that /index exists")
	}
}

// TestADetailAddressThatCannotAnswerSaysSo.
func TestADetailAddressThatCannotAnswerSaysSo(t *testing.T) {
	srv, token := setup(t)
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	// A page with half a detail declaration.
	pages["product"] = map[string]any{"title": "Product", "detail": "catalogue"}
	if _, err := site.SaveDraft(srv.Store, pages, "product", "test"); err != nil {
		t.Fatal(err)
	}
	// No detail route at all: not found, as on the public site.
	if w := get(t, srv, "/preview/index/anything", token); w.Code != http.StatusNotFound {
		t.Errorf("a page with no detail route answered %d", w.Code)
	}
	if w := get(t, srv, "/preview/index/a/b", token); w.Code != http.StatusNotFound {
		t.Errorf("a three-segment address answered %d", w.Code)
	}
	// Half declared: said out loud rather than looking like a missing record.
	if w := get(t, srv, "/preview/product/pen", token); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("a half-declared detail route answered %d", w.Code)
	}
}
