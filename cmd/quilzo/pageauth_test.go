// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/store"
)

// mcpAs calls one operation on the machine interface as a caller.
func mcpAs(t *testing.T, root string, c *Caller) func(tool, op string, args map[string]any) string {
	t.Helper()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, c, "templates")
	return func(tool, op string, args map[string]any) string {
		params, _ := json.Marshal(map[string]any{"name": tool,
			"arguments": map[string]any{"operation": op, "arguments": args}})
		b, _ := json.Marshal(srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("1"),
			Method: "tools/call", Params: params}))
		return string(b)
	}
}

// refused reports whether a machine interface answer is a refusal, which
// arrives either as a refused error or as a result marked as an error.
func refused(answer string) bool {
	return strings.Contains(answer, `"refused":true`) || strings.Contains(answer, `"isError":true`)
}

func withRole(name string, role auth.Role) *Caller {
	return &Caller{Name: name, Role: role, Kind: audit.KindHuman, Verified: true}
}

func grantAll(t *testing.T, root string, pol *auth.Policy, bs ...auth.Binding) {
	t.Helper()
	for _, b := range bs {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
}

// A deny on one page holds on the machine interface: the page is not
// listed, read, searched, compared, written or exported, while everything
// else the person may do still works.
func TestADenyOnPartOfTheSiteHoldsOverMCP(t *testing.T) {
	root, pol := identityStore(t)
	grantAll(t, root, pol,
		auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/"},
		auth.Binding{Principal: "pat", Role: auth.RoleReader, Resource: "/about", Deny: true})
	call := mcpAs(t, root, withRole("pat", auth.RolePublisher))

	if got := call("quilzo_read", "list_pages", nil); strings.Contains(got, "about") || !strings.Contains(got, "shop") {
		t.Errorf("list_pages: %s", got)
	}
	for _, c := range []struct{ tool, op string }{{"quilzo_read", "read_page"}, {"quilzo_read", "similar_pages"},
		{"quilzo_write", "write_page"}} {
		args := map[string]any{"page": "about", "fields": map[string]any{"title": "changed"}}
		if got := call(c.tool, c.op, args); !refused(got) {
			t.Errorf("%s on a denied page: %s", c.op, got)
		}
	}
	if got := call("quilzo_write", "write_page", map[string]any{"page": "shop",
		"fields": map[string]any{"title": "Shop"}}); refused(got) {
		t.Errorf("a write the person may make was refused: %s", got)
	}
	if got := call("quilzo_read", "search_pages", map[string]any{"query": "Marginalia"}); strings.Contains(got, "about\t") {
		t.Errorf("search_pages found the denied page: %s", got)
	}
	if got := call("quilzo_read", "diff", nil); strings.Contains(got, " about") {
		t.Errorf("diff named the denied page: %s", got)
	}
	if got := call("quilzo_read", "export_site", nil); !strings.Contains(got, "not pat's to read") {
		t.Errorf("export_site exported around a deny: %s", got)
	}
}

// A grant on part of the site reaches it over MCP, where it used to be
// refused everything because the first check asked about "/".
func TestAGrantOnPartOfTheSiteReachesItOverMCP(t *testing.T) {
	root, pol := identityStore(t)
	grantAll(t, root, pol, auth.Binding{Principal: "bea", Role: auth.RoleAuthor, Resource: "/about"})
	call := mcpAs(t, root, withRole("bea", auth.RoleAuthor))
	if got := call("quilzo_write", "write_page", map[string]any{"page": "about",
		"fields": map[string]any{"title": "About us"}}); refused(got) {
		t.Errorf("a grant on /about could not write about: %s", got)
	}
	if got := call("quilzo_read", "list_pages", nil); !strings.Contains(got, "about") || strings.Contains(got, "shop") {
		t.Errorf("list_pages: %s", got)
	}
	if got := call("quilzo_write", "write_page", map[string]any{"page": "shop",
		"fields": map[string]any{"title": "x"}}); !refused(got) {
		t.Errorf("a grant on /about wrote shop: %s", got)
	}
}

// Publishing asks about every page it would change, on every surface, so
// a deny of publishing on one page is not passed over by a check on "/".
func TestPublishingAsksAboutEachPageItWouldChange(t *testing.T) {
	root, pol := identityStore(t)
	grantAll(t, root, pol,
		auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/"},
		auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/about", Deny: true})
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := mayPublishChanges(root, s, withRole("pat", auth.RolePublisher), ""); err == nil ||
		!strings.Contains(err.Error(), "about") {
		t.Errorf("a publish changing a denied page was allowed: %v", err)
	}
	if err := mayPublishChanges(root, s, asAdmin("sam"), ""); err != nil {
		t.Errorf("an administrator could not publish: %v", err)
	}
	call := mcpAs(t, root, withRole("pat", auth.RolePublisher))
	if got := call("quilzo_publish", "publish", nil); !strings.Contains(got, "may not publish") {
		t.Errorf("publish over MCP went round the deny: %s", got)
	}
}

// An export holds every page and every collection, so it is refused to a
// person who may not read one of them, on the command line as over MCP.
func TestAnExportIsRefusedWhenSomethingInItIsNotTheReadersToRead(t *testing.T) {
	root, pol := identityStore(t)
	grantAll(t, root, pol,
		auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"},
		auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: auth.DataResource("products"), Deny: true})
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("rae", "rae", auth.RoleReader, "/", time.Hour, auth.RoleReader)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
	out := t.TempDir()
	if err := cmdExport(root, []string{"json", "--ref", "draft", "--to", out, "--force"}); err == nil ||
		!strings.Contains(err.Error(), "products") {
		t.Errorf("an export went round a deny on a collection: %v", err)
	}
}
