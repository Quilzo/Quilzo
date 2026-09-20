// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A binding scoped to part of the site has to mean the same thing on the
// command line as it does in the browser.
//
// Both halves of this were broken by the same line, and only one of them was
// visible. `--on /path` narrowed a grant into uselessness, which somebody
// would eventually report as a bug; it also narrowed a deny into nothing,
// which nobody reports, because the symptom is that the thing you forbade
// keeps working and the policy file still says you forbade it.

// scopedStore is a store with access control on and one token for alice.
func scopedStore(t *testing.T, bindings ...auth.Binding) string {
	t.Helper()
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	for _, b := range bindings {
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.Issue("cli", "alice", auth.RoleAdmin, "/", time.Hour,
		auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
	return root
}

// The hole. A deny on one page did not stop the command that edits that page.
func TestADenyOnOnePageBindsOnTheCommandLine(t *testing.T) {
	root := scopedStore(t,
		auth.Binding{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"},
		auth.Binding{Principal: "alice", Role: auth.RoleAuthor,
			Resource: "/legal", Deny: true},
	)

	if err := authoriseCommand(root, "section",
		[]string{"add", "legal", "this is wrong"}); err == nil {
		t.Error("alice is denied author on /legal and still edited it from " +
			"the command line. The browser enforces this deny and the CLI did " +
			"not, which is worse than not having the feature: somebody reads " +
			"the policy, sees the deny, and believes it")
	}
	if err := authoriseCommand(root, "section",
		[]string{"add", "index", "a remark"}); err != nil {
		t.Errorf("the deny on /legal also stopped /index, which is "+
			"over-denial and the reason people turn deny off: %v", err)
	}
}

// The visible half. A grant narrowed to a path was a way to lock somebody out
// of every command, including the ones inside their own scope.
func TestAGrantScopedToAPathReachesThatPath(t *testing.T) {
	root := scopedStore(t, auth.Binding{
		Principal: "alice", Role: auth.RoleAuthor, Resource: "/blog",
	})

	if err := authoriseCommand(root, "section",
		[]string{"add", "blog/first", "nearly"}); err != nil {
		t.Errorf("an author scoped to /blog could not act on /blog, so --on "+
			"is a way to lock somebody out rather than to narrow them: %v", err)
	}
	if err := authoriseCommand(root, "section",
		[]string{"add", "legal/notice", "nearly"}); err == nil {
		t.Error("an author scoped to /blog acted on /legal")
	}
}

// Every page a command names, not the first one.
//
// Stopping at the first would let a denied page be written by naming a
// permitted one alongside it — `add allowed=a.json denied=b.json`.
func TestEveryPageACommandNamesIsChecked(t *testing.T) {
	root := scopedStore(t,
		auth.Binding{Principal: "alice", Role: auth.RoleAdmin, Resource: "/"},
		auth.Binding{Principal: "alice", Role: auth.RoleAuthor,
			Resource: "/legal", Deny: true},
	)

	if err := authoriseCommand(root, "add",
		[]string{"index=a.json", "legal=b.json"}); err == nil {
		t.Error("a denied page was written by naming a permitted page first")
	}
}

// What the gate reads out of a command's arguments.
func TestWhatTheGateReadsAsThePage(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		args []string
		want []string
	}{
		// The ordinary shapes.
		{"section", []string{"add", "blog/first", "hero"}, []string{"/blog/first"}},
		{"section", []string{"add", "index", "hero"}, []string{"/index"}},
		{"section", []string{"set", "about", "0", "body=x"}, []string{"/about"}},
		{"section", []string{"item", "add", "about", "0", "links"},
			[]string{"/about"}},
		{"lock", []string{"about"}, []string{"/about"}},
		{"type", []string{"bind", "about", "page"}, []string{"/about"}},

		// A subcommand that names no page must not read its own name as one.
		{"section", []string{"kinds"}, []string{"/"}},
		{"lock", []string{"release", "about"}, []string{"/about"}},
		{"section", []string{"kinds"}, []string{"/"}},
		{"section", []string{"kinds"}, []string{"/"}},

		// Nothing this can be sure of falls back to the whole store, which is
		// the strict direction: only a binding on "/" covers "/".
		{"publish", nil, []string{"/"}},
		{"serve", []string{"--addr", ":8080"}, []string{"/"}},
		{"section", []string{"add"}, []string{"/"}},
		{"section", []string{"add", "../escape", "hero"}, []string{"/"}},
		{"section", []string{"add", "a//b", "hero"}, []string{"/"}},

		// add reads its arguments with the same flag table it parses with, so
		// a flag in the middle does not turn a page into a flag value.
		{"add", []string{"index=a.json"}, []string{"/index"}},
		{"add", []string{"index=a.json", "-m", "why", "about=b.json"},
			[]string{"/about", "/index"}},
		{"add", []string{"index=a.json", "--remove", "old,older"},
			[]string{"/index", "/old", "/older"}},
		{"add", []string{"--remove=gone"}, []string{"/gone"}},
		// A word it cannot read is not silently dropped: the whole command
		// falls back, because checking the pages it understood and letting the
		// one it did not through unexamined is the worst of both.
		{"add", []string{"index=a.json", "nonsense"}, []string{"/"}},
		{"add", []string{"index=a.json", "--remove"}, []string{"/"}},
		{"add", nil, []string{"/"}},
	} {
		got := commandResources(tc.cmd, tc.args)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %v acts on %v, want %v", tc.cmd, tc.args, got, tc.want)
		}
	}
}

// Every subcommand `lock` recognises has a row.
//
// lock is the one command here whose dispatch treats an unrecognised first
// word as a page name, which is what makes the bare row correct — and also
// what makes a new subcommand dangerous: without a row saying otherwise,
// `quilzo lock steal` would be authorised against a page called "steal".
//
// A source walk rather than a list, for the reason the privilege table's own
// test gives: a list needs updating by the same person who forgot.
func TestEverySubcommandOfLockHasARow(t *testing.T) {
	for _, name := range switchCases(t, "collabcmd.go", "cmdLock") {
		for _, parent := range []string{"lock", "locks"} {
			if _, ok := pageArgs[parent+" "+name]; !ok {
				t.Errorf("%s %s has no row in pageArgs, so the gate reads %q "+
					"as the name of a page. Add a row: 0 if it takes a page, "+
					"wholeStore if it does not", parent, name, name)
			}
		}
	}
}

// switchCases returns the case literals of the first switch in a function.
func switchCases(t *testing.T, file, fn string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn {
			continue
		}
		ast.Inspect(fd, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					out = append(out, strings.Trim(lit.Value, `"`))
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		t.Fatalf("found no case labels in %s; the walk is wrong and a test "+
			"that inspects nothing passes", fn)
	}
	return out
}

// A row is a claim that the command touches that page and nothing else, so a
// row for a command with no page argument at all would narrow a check away
// from where it was needed. Every key must name a command that exists.
func TestEveryPageRowNamesACommandThatExists(t *testing.T) {
	for key := range pageArgs {
		cmd, _, _ := strings.Cut(key, " ")
		if _, ok := commandNeeds[cmd]; !ok {
			t.Errorf("pageArgs has %q and there is no %q command", key, cmd)
		}
	}
	for cmd := range pageResolvers {
		if _, ok := commandNeeds[cmd]; !ok {
			t.Errorf("pageResolvers has %q and there is no such command", cmd)
		}
	}
}
