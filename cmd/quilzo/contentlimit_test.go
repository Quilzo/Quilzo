// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// limitedAs presents a token for who, limited by scope, as the caller.
func limitedAs(t *testing.T, root, who string, scope auth.Scope) *Caller {
	t.Helper()
	ts, _ := loadTokens(root)
	secret, _, err := ts.IssueScoped("limited", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
	return resolveCaller(root, "")
}

// A token limited to content types or locales is limited on the command
// line, and through it on the machine interface, which asks the same
// functions.
//
// The limit was read by the content API and by an agent run and by nothing
// else: CheckCredential consulted only the read-only dimension, and authorise
// and pageCheck asked it and nothing more. So an administrator's token issued
// `--types policy` wrote the products collection and the product pages, and
// one issued `--locales fr` the English pages, from a terminal or over /mcp,
// while the content API refused the same token the same content.
func TestATokenLimitedToTypesOrLocalesIsLimitedOnTheCommandLine(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := typedStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "boss")
	for _, c := range []string{"products", "policy"} {
		if err := cmdRecords(root, []string{"add", c, "name=one"}); err != nil {
			t.Fatal(err)
		}
	}

	// pen is a product in English, returns a policy in French, and index
	// has neither a type nor a language.
	c := limitedAs(t, root, "boss", auth.Scope{Types: []string{"policy"}})
	for _, tc := range []struct {
		cmd  string
		args []string
		may  bool
	}{
		{"records", []string{"add", "products", "name=x"}, false},
		{"records", []string{"list", "products"}, false},
		{"records", []string{"add", "policy", "name=x"}, true},
		{"section", []string{"set", "pen", "0", "body=x"}, false},
		{"section", []string{"set", "returns", "0", "body=x"}, true},
		{"section", []string{"set", "index", "0", "body=x"}, true},
	} {
		err := authoriseCommand(root, tc.cmd, tc.args)
		if tc.may && err != nil {
			t.Errorf("a token limited to policy was refused %s %v: %v", tc.cmd, tc.args, err)
		}
		if !tc.may && err == nil {
			t.Errorf("a token limited to policy may run %s %v", tc.cmd, tc.args)
		}
	}
	pages, err := visiblePages(root, c, map[string]any{
		"pen": map[string]any{"locale": "en"}, "returns": map[string]any{"locale": "fr"}, "index": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pages["pen"]; ok || len(pages) != 2 {
		t.Errorf("a token limited to policy is listed %v", pages)
	}
	listed, err := humanOutput(t, func() error { return recordsCollections(root) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(listed, "products") || !strings.Contains(listed, "policy") {
		t.Errorf("a token limited to policy is listed the collections:\n%s", listed)
	}

	limitedAs(t, root, "boss", auth.Scope{Locales: []string{"fr"}})
	for _, tc := range []struct {
		page string
		may  bool
	}{{"pen", false}, {"returns", true}, {"index", true}} {
		err := authoriseCommand(root, "section", []string{"set", tc.page, "0", "body=x"})
		if tc.may && err != nil {
			t.Errorf("a token limited to French was refused %s: %v", tc.page, err)
		}
		if !tc.may && err == nil {
			t.Errorf("a token limited to French may write %s, which is in English", tc.page)
		}
	}
}

// A token issued with a credential limited to some content types or
// languages carries those limits too, as one exchanged for a session does.
//
// `token issue` narrowed what it issued by the flags and nothing else, so an
// administrator's token issued `--types policy` issued a publisher's token
// with no limit at all, and the limit was one command deep.
func TestATokenIssuedWithALimitedTokenIsLimitedToo(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := typedStore(t)
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "boss")
	limitedAs(t, root, "boss", auth.Scope{Types: []string{"policy"}, Locales: []string{"fr"}})
	if _, err := humanOutput(t, func() error {
		return cmdToken(root, []string{"issue", "ci", "--principal", "boss", "--role", "publisher"})
	}); err != nil {
		t.Fatal(err)
	}
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tok := range ts.Tokens {
		if tok.Name != "ci" {
			continue
		}
		found = true
		if strings.Join(tok.Scope.Types, ",") != "policy" || strings.Join(tok.Scope.Locales, ",") != "fr" {
			t.Errorf("a token issued with one limited to policy in French is limited to %s", tok.Scope)
		}
	}
	if !found {
		t.Fatal("no token was issued")
	}
}

// A token limited to content types or languages is held to them by what a
// command writes, as well as by what its command line names.
//
// The gate asks about the names on a command line, before the command has
// read what it is to write. So `quilzo import`, asked about the whole site,
// wrote a collections file into the products collection for a token issued
// `--types policy`; and `quilzo add`, `quilzo import` and write_page stored
// a page as English for one issued `--locales fr`, over the French page or
// as a new one, which the content API's PUT refuses the same token.
func TestATokenLimitedToTypesOrLocalesIsHeldToWhatItWrites(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := typedStore(t)
	// Both types with a language, so the pages in typedStore are valid
	// and a write is refused for its language or not at all.
	reg := schema.NewRegistry()
	for _, name := range []string{"product", "policy"} {
		if err := reg.Add(schema.Type{Name: name, Fields: []schema.Field{
			{Name: "title", Kind: schema.Text, Required: true}, {Name: "locale", Kind: schema.Text}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(filepath.Join(root, "types.json"), &schema.Store{Registry: reg,
		Bound: map[string]string{"pen": "product", "returns": "policy"}}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "boss")
	run := func(cmd string, args []string, do func() error) error {
		if err := authoriseCommand(root, cmd, args); err != nil {
			return err
		}
		return do()
	}

	limitedAs(t, root, "boss", auth.Scope{Types: []string{"policy"}})
	for _, tc := range []struct {
		collection string
		may        bool
	}{{"products", false}, {"policy", true}} {
		args := []string{fileOf(t, tc.collection+".json", `{"collection":"`+tc.collection+
			`","records":[{"id":"0123456789abcdef0123456789abcdef","fields":{"name":"x"}}]}`)}
		err := run("import", args, func() error { return cmdImport(root, args) })
		if tc.may && err != nil {
			t.Errorf("a token limited to policy could not import into %s: %v", tc.collection, err)
		}
		if !tc.may && (err == nil || !strings.Contains(err.Error(), "limited to the content types policy")) {
			t.Errorf("a token limited to policy imported records into %s: %v", tc.collection, err)
		}
	}

	// faq is a second page in French, for write_page to be asked about
	// apart from what quilzo add has written.
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["faq"] = map[string]any{"title": "FAQ", "locale": "fr"}
	if _, err := site.SaveDraft(s, pages, "faq", "test"); err != nil {
		t.Fatal(err)
	}
	limitedAs(t, root, "boss", auth.Scope{Locales: []string{"fr"}})
	srv := buildMCP(root, s, resolveCaller(root, ""), t.TempDir())
	in := func(locale string) string {
		return fileOf(t, "page.json", `{"title":"T","locale":"`+locale+`"}`)
	}
	for _, tc := range []struct {
		add, mcp, locale string
		may              bool
	}{
		{"returns", "faq", "en", false}, {"about", "fresh", "en", false},
		{"returns", "faq", "fr", true}, {"about", "fresh", "fr", true},
	} {
		args := []string{tc.add + "=" + in(tc.locale)}
		err := run("add", args, func() error { return cmdAdd(root, args) })
		_, refused := callTool(t, srv, "quilzo_write", "write_page", map[string]any{"page": tc.mcp,
			"fields": map[string]any{"title": "T", "locale": tc.locale}})
		if tc.may && (err != nil || refused != nil) {
			t.Errorf("a token limited to French could not write %s and %s in French: %v %+v",
				tc.add, tc.mcp, err, refused)
		}
		if !tc.may && (err == nil || !strings.Contains(err.Error(), "scoped to fr")) {
			t.Errorf("a token limited to French wrote %s as English with quilzo add: %v", tc.add, err)
		}
		if !tc.may && (refused == nil || !strings.Contains(refused.Message, "scoped to fr")) {
			t.Errorf("a token limited to French wrote %s as English with write_page: %+v", tc.mcp, refused)
		}
	}
	for _, tc := range []struct {
		slug, locale string
		may          bool
	}{{"contact", "en", false}, {"contact", "fr", true}} {
		md := fileOf(t, "export.md", "---\ntitle: Contact\nslug: "+tc.slug+"\nlocale: "+tc.locale+"\n---\nhello\n")
		args := []string{md, "--redirects-out", filepath.Join(t.TempDir(), "r.json")}
		err := run("import", args, func() error { return cmdImport(root, args) })
		if tc.may && err != nil {
			t.Errorf("a token limited to French could not import a page in French: %v", err)
		}
		if !tc.may && (err == nil || !strings.Contains(err.Error(), "scoped to fr")) {
			t.Errorf("a token limited to French imported a page in English: %v", err)
		}
	}
}
