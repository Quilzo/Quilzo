// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/render"
)

// registerSurfaceFiles are the files of the register's own surfaces: its
// command and operations, its screens, and its routes.
var registerSurfaceFiles = []string{
	"registercmd.go", "registergeneric.go",
	"../../internal/admin/registerscreen.go", "../../internal/admin/registerprivacy.go",
	"../../internal/api/registerapi.go", "../../internal/api/registergeneric.go",
}

// PLAN theme 28: every kind is on four surfaces, by one implementation
// over all of them. For each kind the register defines, today's and any
// added later, the command line lists and exports it, the agent interface
// lists and exports it, the admin shows and exports it and the API lists
// and exports it; and the ledger every module writes (the source-walking
// test's) says the register's module offers each of those, and none of
// its surface files names a kind in a case of a switch, so a kind added
// later needs no line of theirs.
func TestEveryKindHasFourSurfaces(t *testing.T) {
	root, tok := accessStore(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := toks.IssueSession("test", "owner", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	gui, err := admin.New(s, pol, toks, render.Layouts{})
	if err != nil {
		t.Fatal(err)
	}
	guiH := gui.Handler()
	// Two requests a kind, for every kind, are more than the default burst.
	apiSrv := &api.Server{Store: s, Policy: pol, Tokens: toks, Limits: api.Limits{PerMinute: 6000, Burst: 1000}}
	apiH := apiSrv.Handler()
	getAs := func(h http.Handler, path, bearer string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	mcpSrv := buildMCP(root, s, &Caller{Name: "owner", Role: auth.RoleAdmin, Scope: "/", Kind: audit.KindAI, Model: "mcp-client",
		Verified: true}, "templates")

	kinds := register.Kinds()
	if len(kinds) < 26 {
		t.Fatalf("the register defines %d kinds", len(kinds))
	}
	for _, k := range kinds {
		slug := strings.TrimPrefix(k.Collection, register.Prefix)
		for _, line := range [][]string{{"register", "list", string(k.Kind), "--json"},
			{"register", "export", string(k.Kind), "--json"}} {
			if _, e, code := cliRun(t, root, tok, line...); code != 0 {
				t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line, " "), code, firstLines(e, 2))
			}
		}
		for _, op := range []string{"register_list", "register_export"} {
			if _, rerr := callTool(t, mcpSrv, "quilzo_read", op, map[string]any{"kind": string(k.Kind)}); rerr != nil {
				t.Errorf("%s of %s: %s", op, k.Kind, rerr.Message)
			}
		}
		for _, path := range []string{"/register/kind/" + slug, "/register/export/" + slug + ".csv"} {
			if code := getAs(guiH, path, session); code != http.StatusOK {
				t.Errorf("the admin's %s answered %d", path, code)
			}
		}
		for _, path := range []string{"/api/v1/register/kinds/" + slug, "/api/v1/register/export/" + slug} {
			if code := getAs(apiH, path, tok); code != http.StatusOK {
				t.Errorf("the API's %s answered %d", path, code)
			}
		}
	}

	var mod register.Module
	for _, m := range register.Modules() {
		if m.Name == "register" {
			mod = m
		}
	}
	for on, want := range map[register.Surface][]string{
		register.SurfaceCLI:   {"quilzo register"},
		register.SurfaceMCP:   {"register_list", "register_show", "register_history", "register_export", "register_inventory"},
		register.SurfaceAdmin: {"/register/kind/", "/register/record/", "/register/export/", "/register/inventory", "/register/erase"},
		register.SurfaceAPI:   {"/api/v1/register/kinds/", "/api/v1/register/records/", "/api/v1/register/export/", "/api/v1/register/inventory"},
	} {
		for _, name := range want {
			if !slices.Contains(mod.Offers[on], name) {
				t.Errorf("the register's module does not offer %s on %s: %v", name, on, mod.Offers[on])
			}
		}
	}

	// One implementation: no surface file chooses what to do by kind.
	fset := token.NewFileSet()
	for _, path := range registerSurfaceFiles {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range c.List {
				if sel, ok := e.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "Kind") {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "register" {
						t.Errorf("%s: %s chooses by the kind %s", fset.Position(c.Pos()), path, sel.Sel.Name)
					}
				}
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, _ := strconv.Unquote(lit.Value); v != "" {
						if _, isKind := register.SpecOf(v); isKind && v == strings.ToUpper(v[:1])+v[1:] {
							t.Errorf("%s: %s chooses by the kind %q", fset.Position(c.Pos()), path, v)
						}
					}
				}
			}
			return true
		})
	}
}

// PLAN theme 28: the register's surfaces never read the site's records
// tree. They read the register through internal/register, from its own
// ref, and nothing else: no file of theirs imports the collection, site,
// schema or records packages the generic surfaces read the site through,
// names the site's refs, or reads a tree or a ref of the store directly.
func TestRegisterSurfacesNeverUseRecordsTree(t *testing.T) {
	forbidden := map[string]bool{
		"github.com/quilzo/quilzo/internal/collection": true,
		"github.com/quilzo/quilzo/internal/site":       true,
		"github.com/quilzo/quilzo/internal/schema":     true,
		"github.com/quilzo/quilzo/internal/importer":   true,
	}
	// What reads the site's records: its trees, its refs, the generic
	// record surfaces' own helpers.
	calls := map[string]bool{"GetTree": true, "PutNested": true, "SetRef": true, "draftTree": true,
		"commitTreeNoLock": true, "liveTree": true, "RefDraft": true, "RefLive": true}
	fset := token.NewFileSet()
	for _, path := range registerSurfaceFiles {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if forbidden[p] {
				t.Errorf("%s imports %s, which reads the site's records", path, p)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if calls[x.Sel.Name] {
					t.Errorf("%s: %s reads %s, which is the site's records", fset.Position(x.Pos()), path, x.Sel.Name)
				}
			case *ast.Ident:
				if calls[x.Name] && x.Obj == nil {
					t.Errorf("%s: %s calls %s", fset.Position(x.Pos()), path, x.Name)
				}
			case *ast.BasicLit:
				if v, _ := strconv.Unquote(x.Value); strings.HasPrefix(v, "/api/v1/records") {
					t.Errorf("%s: %s names the generic records route", fset.Position(x.Pos()), path)
				}
			}
			return true
		})
	}
}
