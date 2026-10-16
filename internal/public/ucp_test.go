// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/ucp"
)

// The routes exist exactly when the catalogue is served over UCP: a site
// that has not turned it on answers nothing UCP-shaped, which is a
// different claim from an empty shop.
func TestTheUCPRoutesFollowTheSetting(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	off := &Site{Store: s, Name: "test", Index: "index"}
	for _, path := range []string{"/.well-known/ucp", "/ucp/catalog/search"} {
		w := httptest.NewRecorder()
		off.Handler().ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(`{"query":"x"}`)))
		if w.Code == 200 || strings.Contains(w.Body.String(), "dev.ucp") {
			t.Errorf("%s answered %d with UCP off: %s", path, w.Code, w.Body)
		}
	}
	on := &Site{Store: s, Name: "test", Index: "index", UCP: &ucp.Catalog{
		Base: "https://shop.example",
		Rows: func(int) ([]listing.Row, int, error) {
			return []listing.Row{{"slug": "pen", "name": "Pen", "price": float64(100), "currency": "GBP"}}, 1, nil
		}}}
	w := httptest.NewRecorder()
	on.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/.well-known/ucp", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "dev.ucp.shopping.catalog.search") {
		t.Errorf("the profile answered %d %s", w.Code, w.Body)
	}
	r := httptest.NewRequest("POST", "/ucp/catalog/search", strings.NewReader(`{"query":"pen"}`))
	r.Header.Set("Request-Id", "r1")
	r.Header.Set("UCP-Agent", `profile="https://p.example/.well-known/ucp"`)
	w = httptest.NewRecorder()
	on.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"pen"`) {
		t.Errorf("a search answered %d %s", w.Code, w.Body)
	}
	// The site's own headers still apply: a JSON answer is not exempt.
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("the site's security headers are missing: %v", w.Header())
	}
}
