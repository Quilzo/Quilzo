// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/register"
)

// A security module's routes, registered from the module's own file.
//
// A route has been three edits: a line in Handler, a branch of allow, and
// its paths in the description. The security modules are built side by
// side, so each brings its routes with it: a file of handlers that ends with
// one call to registerRoutes, in an init, and no line changed anywhere else.
//
// A module's routes are reads, answered to GET and HEAD and refused every
// other method with the Allow header that says so, behind the same
// middleware as every route here: a token, the rate limit, the shield, no
// cross-origin request. Each describes itself in OpenAPI, and the tests that
// hold the API to its description read the modules' routes with the rest.
//
// A route may also write, by declaring a handler for POST (post) and
// describing it. Its handler asks the policy and writes through the
// module's own write path, which records what it wrote, as the command
// line's does; nothing here writes for it. And a route may take a token
// bound to a key (proved): presented as DPoP with a fresh proof made by the
// key (RFC 9449), checked and spent before the handler runs, where every
// other route refuses such a token. That is how a pipeline's job, which
// holds no secret, presents the minutes-long token its platform's identity
// was exchanged for.

// apiModule is what a module adds to the content API.
type apiModule struct {
	// module is the module's name, under which its command and its screens
	// are registered too (internal/register's ledger).
	module string
	routes []apiRoute
}

// apiRoute is one address a module serves.
type apiRoute struct {
	// path is the pattern, as the mux takes it: "/api/v1/register/kinds"
	// for one address, "/api/v1/register/records/" for everything below.
	path string
	// handle answers a GET or a HEAD; any other method is refused before
	// it is called, unless post answers a POST.
	handle func(*Server, http.ResponseWriter, *http.Request)
	// post, when set, answers a POST: a write, which the handler asks of
	// the policy and makes through its module's one write path.
	post func(*Server, http.ResponseWriter, *http.Request)
	// proved says the route takes a token bound to a key, with the
	// request's proof made by that key.
	proved bool
	// describe is how the description says it: each OpenAPI path template
	// the route answers, with its path item.
	describe map[string]map[string]any
}

var (
	// apiModules is every module's routes, in the order of their names.
	apiModules []apiModule

	reAPIModule = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	reAPIRoute  = regexp.MustCompile(`^/api/v1/[a-z][a-z0-9/._-]*$`)
)

// builtIn are the routes Handler serves of its own, which no module may
// take.
var builtIn = []string{"/api/v1/pages", "/api/v1/collections", "/api/v1/records", "/api/v1/similar",
	"/api/v1/replica", "/api/v1/search", "/api/v1/openapi.json"}

// registerRoutes adds a module's routes. It is called from an init in the
// module's own file, and a module declared wrongly stops the program
// starting, with what is wrong.
func registerRoutes(m apiModule) {
	if err := checkRoutes(m); err != nil {
		panic("api: the module " + m.module + ": " + err.Error())
	}
	apiModules = append(apiModules, m)
	sort.SliceStable(apiModules, func(i, j int) bool { return apiModules[i].module < apiModules[j].module })
	var paths []string
	for _, r := range m.routes {
		paths = append(paths, r.path)
	}
	register.Offer(m.module, register.SurfaceAPI, paths...)
}

// checkRoutes is what registerRoutes refuses, without changing anything.
func checkRoutes(m apiModule) error {
	if !reAPIModule.MatchString(m.module) {
		return fmt.Errorf("%q is not a module's name", m.module)
	}
	if len(m.routes) == 0 {
		return fmt.Errorf("it serves nothing")
	}
	taken := map[string]bool{}
	for _, have := range apiModules {
		if have.module == m.module {
			return fmt.Errorf("it is registered twice")
		}
		for _, r := range have.routes {
			taken[r.path] = true
		}
	}
	for _, r := range m.routes {
		switch {
		case !reAPIRoute.MatchString(r.path):
			return fmt.Errorf("%q is not an address of the API", r.path)
		case r.handle == nil:
			return fmt.Errorf("%s has no handler", r.path)
		case taken[r.path]:
			return fmt.Errorf("%s is served twice", r.path)
		case len(r.describe) == 0:
			return fmt.Errorf("%s does not describe itself", r.path)
		}
		for _, b := range builtIn {
			if r.path == b || strings.HasPrefix(r.path, b+"/") {
				return fmt.Errorf("%s is the API's own", r.path)
			}
		}
		for tmpl, item := range r.describe {
			if !routeAnswers(r.path, tmpl) {
				return fmt.Errorf("%s describes %s, which it does not answer", r.path, tmpl)
			}
			_, writes := item["post"]
			if _, ok := item["get"]; !ok || len(item) != 1 && !(writes && len(item) == 2) {
				return fmt.Errorf("%s is described with methods other than get and post, and a module's route reads "+
					"or, with a handler for it, writes", tmpl)
			}
			if writes != (r.post != nil) {
				return fmt.Errorf("%s describes a post it does not answer, or answers one it does not describe", tmpl)
			}
		}
		taken[r.path] = true
	}
	return nil
}

// routeAnswers reports whether a mux pattern answers a path template.
func routeAnswers(pattern, tmpl string) bool {
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(tmpl, pattern) && len(tmpl) > len(pattern)
	}
	return pattern == tmpl
}

// mountModules adds every module's routes to the API's mux.
func (s *Server) mountModules(mux *http.ServeMux) {
	for _, m := range apiModules {
		for _, r := range m.routes {
			handle, post := r.handle, r.post
			mux.HandleFunc(r.path, func(w http.ResponseWriter, req *http.Request) {
				switch {
				case post != nil && req.Method == http.MethodPost:
					post(s, w, req)
				case !readMethod(req) && post != nil:
					w.Header().Set("Allow", "GET, HEAD, POST")
					writeError(w, http.StatusMethodNotAllowed, Error{Error: "GET or POST only"})
				case !readMethod(req):
					s.notAllowed(w, req, Error{Error: "GET only"})
				default:
					handle(s, w, req)
				}
			})
		}
	}
}

// moduleProved reports whether a path is a module's route that takes a
// token bound to a key.
func moduleProved(p string) bool {
	for _, m := range apiModules {
		for _, r := range m.routes {
			if r.proved && (p == r.path || strings.HasSuffix(r.path, "/") && strings.HasPrefix(p, r.path)) {
				return true
			}
		}
	}
	return false
}

// moduleRoute reports whether a path is a module's.
func moduleRoute(p string) bool {
	for _, m := range apiModules {
		for _, r := range m.routes {
			if p == r.path || strings.HasSuffix(r.path, "/") && strings.HasPrefix(p, r.path) {
				return true
			}
		}
	}
	return false
}

// moduleDescriptions is every module route's path items, for the
// description.
func moduleDescriptions() map[string]any {
	out := map[string]any{}
	for _, m := range apiModules {
		for _, r := range m.routes {
			for tmpl, item := range r.describe {
				out[tmpl] = item
			}
		}
	}
	return out
}
