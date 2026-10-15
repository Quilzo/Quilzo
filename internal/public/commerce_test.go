// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/commerce"
	"github.com/quilzo/quilzo/internal/store"
)

// The routes exist exactly when the service does, and not before: a site
// that sells nothing answers nothing at these paths, which is a different
// claim from an empty shop.
func TestTheCommerceRoutesFollowTheService(t *testing.T) {
	// With commerce off, no discovery document appears. The path falls to
	// the page handler, whose answer for an unpublished site is its own; the
	// property under test is that nothing commerce-shaped is served.
	off := testSite(t)
	if w := commerceGet(t, off, "/.well-known/ucp"); w.Code == 200 ||
		strings.Contains(w.Body.String(), "payment_handlers") {
		t.Errorf("discovery was served with commerce off: %d %s", w.Code, w.Body.String())
	}
	if w := commerceGet(t, off, "/ucp/catalog/search"); w.Code == 200 {
		t.Errorf("the UCP endpoint answered a GET with %d with commerce off", w.Code)
	}

	on := testSite(t)
	on.Commerce = &commerce.Service{PayeeName: "Test", PayeeWebsite: "https://t.test"}
	if err := on.Commerce.Init(); err != nil {
		t.Fatal(err)
	}
	if w := commerceGet(t, on, "/.well-known/ucp"); w.Code != 200 {
		t.Errorf("discovery answered %d with commerce on", w.Code)
	}
	// Identified by nobody: the endpoint exists and refuses.
	r := httptest.NewRequest("POST", "/ucp/catalog/search", nil)
	w := httptest.NewRecorder()
	on.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("an unsigned UCP request answered %d", w.Code)
	}
}

// testSite makes a Site over a real store, as the routes need.
func testSite(t *testing.T) *Site {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Site{Store: s, Name: "test", Index: "index"}
}

func commerceGet(t *testing.T, st *Site, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}
