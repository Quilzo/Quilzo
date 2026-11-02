// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The description is served without a token, parses, and describes every
// route the API serves: a route added without it is a test that fails.
func TestTheAPIDescribesItself(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Content-Type"))
	}
	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || doc.OpenAPI != "3.1.0" {
		t.Fatalf("%v %q", err, doc.OpenAPI)
	}
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`mux\.HandleFunc\("(/api/v1/[^"]*)"`)
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		route := m[1]
		if route == "/api/v1/" {
			continue
		}
		found := false
		for p := range doc.Paths {
			if p == route || (strings.HasSuffix(route, "/") && strings.HasPrefix(p, route)) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is served and not described", route)
		}
	}
	// Every write names If-Match: the API's rule, said where clients read it.
	for p, ops := range doc.Paths {
		for method, o := range ops {
			if method != "put" && method != "delete" {
				continue
			}
			b, _ := json.Marshal(o)
			if !strings.Contains(string(b), "If-Match") {
				t.Errorf("%s %s does not say it needs If-Match", method, p)
			}
		}
	}
	// And the rest still needs a token.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/pages", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a listing without a token: %d", w.Code)
	}
}
