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
)

// moduleExamples is, for each path a module's route describes, how to try
// it: a request that answers 200 on a test server, and a token that may
// make it. Each module fills it in from a test file of its own, so a route
// added without one fails TestEachServerDescribesWhatItServes and the test
// below with the route's name.
var moduleExamples = map[string]func(t *testing.T, s *Server) (path, token string){}

// officer is a token for somebody who holds the compliance officer's job on
// the compliance area, where the register is, and nothing on the site.
func officer(t *testing.T, s *Server) string {
	t.Helper()
	// Granted once per server; a second example on the same server asks
	// for a token of its own and finds the grant made.
	if err := s.Policy.Grant(auth.Binding{Principal: "olu", Role: auth.RoleAdmin, Resource: auth.AreaCompliance}); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		t.Fatal(err)
	}
	tok, _, err := s.Tokens.Issue("o", "olu", auth.RoleAdmin, auth.AreaCompliance, time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Every module's route keeps the API's rules: it is described, it answers
// GET in JSON and HEAD the same, it refuses every other method with Allow,
// it needs a token, and a token whose holder may not read it is refused.
func TestEveryModuleRouteKeepsTheAPIsRules(t *testing.T) {
	described := moduleDescriptions()
	if len(described) == 0 {
		t.Fatal("no module registers a route")
	}
	for tmpl := range described {
		ex, ok := moduleExamples[tmpl]
		if !ok {
			t.Errorf("%s is a module's and no test file of the module says how to try it", tmpl)
			continue
		}
		s, readTok, _ := setup(t)
		path, tok := ex(t, s)
		get := req(t, s, "GET", path, tok, nil, nil)
		if get.Code != http.StatusOK || !strings.HasPrefix(get.Header().Get("Content-Type"), "application/json") ||
			!json.Valid(get.Body.Bytes()) {
			t.Errorf("GET %s: %d %s %s", path, get.Code, get.Header().Get("Content-Type"), get.Body)
			continue
		}
		if head := req(t, s, "HEAD", path, tok, nil, nil); head.Code != http.StatusOK {
			t.Errorf("HEAD %s answered %d", path, head.Code)
		}
		// A route that writes answers POST as well, and says so in Allow;
		// what its POST does is its module's own tests' to show.
		_, writes := described[tmpl].(map[string]any)["post"]
		allow, refused := "GET, HEAD", []string{"POST", "PUT", "DELETE", "PATCH"}
		if writes {
			allow, refused = "GET, HEAD, POST", []string{"PUT", "DELETE", "PATCH"}
		}
		for _, method := range refused {
			w := req(t, s, method, path, tok, nil, nil)
			if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != allow {
				t.Errorf("%s %s answered %d with Allow %q", method, path, w.Code, w.Header().Get("Allow"))
			}
		}
		if w := req(t, s, "GET", path, "", nil, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token answered %d", path, w.Code)
		}
		if w := req(t, s, "GET", path, readTok, nil, nil); w.Code != http.StatusForbidden {
			t.Errorf("GET %s by a reader of the site answered %d", path, w.Code)
		}
	}
}

// What registerRoutes refuses, it refuses before anything is changed: a
// route of the API's own, one that does not describe itself, one that
// describes a method other than a read, or one served twice.
func TestRegisteringARouteIsHeldToTheAPI(t *testing.T) {
	handle := func(*Server, http.ResponseWriter, *http.Request) {}
	item := map[string]any{"get": map[string]any{"summary": "a read"}}
	good := apiModule{module: "example", routes: []apiRoute{{path: "/api/v1/example", handle: handle,
		describe: map[string]map[string]any{"/api/v1/example": item}}}}
	if err := checkRoutes(good); err != nil {
		t.Fatalf("a module declared rightly is refused: %v", err)
	}
	for what, r := range map[string]apiRoute{
		"the API's own route":      {path: "/api/v1/pages/x", handle: handle, describe: map[string]map[string]any{"/api/v1/pages/x": item}},
		"no description":           {path: "/api/v1/example", handle: handle},
		"a description of a write": {path: "/api/v1/example", handle: handle, describe: map[string]map[string]any{"/api/v1/example": {"put": map[string]any{}}}},
		"a path it does not serve": {path: "/api/v1/example", handle: handle, describe: map[string]map[string]any{"/api/v1/other": item}},
		"no handler":               {path: "/api/v1/example", describe: map[string]map[string]any{"/api/v1/example": item}},
		"a path outside the API":   {path: "/admin", handle: handle, describe: map[string]map[string]any{"/admin": item}},
		"a route a module serves":  {path: "/api/v1/register/kinds", handle: handle, describe: map[string]map[string]any{"/api/v1/register/kinds": item}},
	} {
		if err := checkRoutes(apiModule{module: "example", routes: []apiRoute{r}}); err == nil {
			t.Errorf("a module with %s is registered", what)
		}
	}
}
