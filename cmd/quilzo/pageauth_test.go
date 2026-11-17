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
	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/note"
	"github.com/quilzo/quilzo/internal/site"
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
		args := map[string]any{"page": "about"}
		if c.op == "write_page" {
			args["fields"] = map[string]any{"title": "changed"}
		}
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
	if got := call("quilzo_read", "export_site", map[string]any{"ref": "draft"}); !strings.Contains(got, "not pat's to read") {
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
	// Refused, counting the collection and not naming it: the list of
	// collections leaves out one the caller may not read.
	if err := cmdExport(root, []string{"json", "--ref", "draft", "--to", out, "--force"}); err == nil ||
		!strings.Contains(err.Error(), "every collection, and one of them is not") || strings.Contains(err.Error(), "products") {
		t.Errorf("an export went round a deny on a collection: %v", err)
	}
	// Over MCP too: export_site left the collections out, and so never
	// asked whether they were the caller's to read.
	call := mcpAs(t, root, withRole("rae", auth.RoleReader))
	if got := call("quilzo_read", "export_site", map[string]any{"ref": "draft", "format": "json"}); !refused(got) ||
		!strings.Contains(got, "every collection") || strings.Contains(got, "products") {
		t.Errorf("an export over MCP went round a deny on a collection: %s", got)
	}
}

// A refusal over many pages counts the pages out of the caller's reach and
// does not name them. list_pages, find and search leave such a page out as
// though it were not there, and export_site, check_provenance,
// check_accessibility and a publish refused by naming it, so a reader
// denied a page learned its name: often what the page is about, and the
// one thing the deny was for.
func TestARefusalDoesNotNameAPageOutOfReach(t *testing.T) {
	root, pol := identityStore(t)
	if got := mcpAs(t, root, asAdmin("dana"))("quilzo_write", "write_page", map[string]any{
		"page": "redundancy-plan", "fields": map[string]any{"title": "Who goes"}}); refused(got) {
		t.Fatal(got)
	}
	grantAll(t, root, pol,
		auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"},
		auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/redundancy-plan", Deny: true},
		auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/"},
		auth.Binding{Principal: "pat", Role: auth.RoleReader, Resource: "/redundancy-plan", Deny: true})
	call := mcpAs(t, root, withRole("rae", auth.RoleReader))
	if got := call("quilzo_read", "list_pages", nil); strings.Contains(got, "redundancy") {
		t.Fatalf("list_pages named the denied page: %s", got)
	}
	for _, c := range []struct{ tool, op string }{{"quilzo_read", "export_site"},
		{"quilzo_check", "check_provenance"}, {"quilzo_check", "check_accessibility"}} {
		got := call(c.tool, c.op, map[string]any{"ref": "draft"})
		if !refused(got) || !strings.Contains(got, "one of them is not rae's to read") || strings.Contains(got, "redundancy") {
			t.Errorf("%s: %s", c.op, got)
		}
	}
	// The command line's export is the same check.
	if _, err := exportSite(root, withRole("rae", auth.RoleReader), exportOptions{Ref: "draft"}); err == nil ||
		strings.Contains(err.Error(), "redundancy") {
		t.Errorf("the command line's export: %v", err)
	}
	// A publish names the pages the publisher may read and counts the rest.
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := mayPublishChanges(root, s, withRole("pat", auth.RolePublisher), ""); err == nil ||
		strings.Contains(err.Error(), "redundancy") || !strings.Contains(err.Error(), "one page that is not pat's to read") {
		t.Errorf("a publish: %v", err)
	}
}

// The notes and the checks a reader lists on the command line are of the
// pages they may read, as list_notes and list_checked answer them over MCP.
// `note list`, `checked list` and `checked due` were opened to a reader so
// the command answered whom the operation does, and they listed every page:
// a reader denied redundancy-plan was shown its name, and what colleagues
// had written about it, by the command its deny was meant to hold against.
func TestAReadersNotesAndChecksAreOfThePagesTheyMayRead(t *testing.T) {
	root, secrets := storeWithTokenFor(t, auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"})
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/redundancy-plan", Deny: true})
	}); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index":           map[string]any{"title": "Home"},
		"redundancy-plan": map[string]any{"title": "Who goes"},
	}, "test", "dana"); err != nil {
		t.Fatal(err)
	}
	st, err := openNotes(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []note.Note{{Page: "index", Author: "dana", Text: "The welcome is warm"},
		{Page: "redundancy-plan", Author: "dana", Text: "Tell the night shift last"}} {
		if _, err := st.Add(n, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("QUILZO_TOKEN", secrets["rae"])
	for _, args := range [][]string{{"note", "list"}, {"notes", "list"}, {"checked", "list"}, {"checked", "due"}} {
		if err := authoriseCommand(root, args[0], args[1:]); err != nil {
			t.Fatalf("a reader may not run %v: %v", args, err)
		}
		got, err := humanOutput(t, func() error {
			if args[0] == "checked" {
				return cmdChecked(root, args[1:])
			}
			return cmdNote(root, args[1:])
		})
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if strings.Contains(got, "redundancy") || strings.Contains(got, "night shift") {
			t.Errorf("%v named the page out of reach: %s", args, got)
		}
		if !strings.Contains(got, "index") {
			t.Errorf("%v left out the page the reader may read: %s", args, got)
		}
	}
}

// The check of translations names only the pages the caller may read. It
// named every page missing a translation, so a reader denied a page that
// list_pages leaves out was told its name by asking which pages want
// translating.
func TestTheTranslationsCheckDoesNotNameAPageOutOfReach(t *testing.T) {
	root, pol := identityStore(t)
	if got := mcpAs(t, root, asAdmin("dana"))("quilzo_write", "write_page", map[string]any{
		"page": "redundancy-plan", "fields": map[string]any{"title": "Who goes"}}); refused(got) {
		t.Fatal(got)
	}
	grantAll(t, root, pol,
		auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/"},
		auth.Binding{Principal: "rae", Role: auth.RoleReader, Resource: "/redundancy-plan", Deny: true})
	if err := saveJSON(localesPath(root), i18n.Config{Default: "en", Locales: []i18n.Locale{"en", "fr"}}); err != nil {
		t.Fatal(err)
	}
	if got := mcpAs(t, root, asAdmin("dana"))("quilzo_read", "check_translations", nil); !strings.Contains(got, "redundancy-plan") {
		t.Fatalf("an administrator was not told the page wants translating: %s", got)
	}
	got := mcpAs(t, root, withRole("rae", auth.RoleReader))("quilzo_read", "check_translations", nil)
	if strings.Contains(got, "redundancy") || !strings.Contains(got, "missing index fr") {
		t.Errorf("check_translations: %s", got)
	}
}
