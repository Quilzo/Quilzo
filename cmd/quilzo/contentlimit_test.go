// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
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
