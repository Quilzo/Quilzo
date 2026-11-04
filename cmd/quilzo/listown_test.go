// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// A reader listing grants and tokens is shown their own; whoever may grant,
// or manage tokens, is shown everybody's.
//
// A reader was shown everybody's. `auth list` and `token list` ask only to
// view, so that somebody refused something can find out why, and they
// printed every binding in the store and every token's id, name, role and
// last use: on the reference stack, 127 lines to a reader whose browser was
// refused People and Security. The commands still answer a reader, with
// what is theirs.
func TestAReaderListsTheirOwnGrantsAndTokens(t *testing.T) {
	isolateToken(t)
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	for _, who := range [][2]string{{"alice", "admin"}, {"rae", "reader"}} {
		if err := cmdAuth(root, []string{"grant", who[0], who[1]}); err != nil {
			t.Fatal(err)
		}
	}
	ts, _ := loadTokens(root)
	secrets := map[string]string{}
	for _, who := range []string{"alice", "rae"} {
		secret, _, err := ts.Issue(who+"-laptop", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
		if err != nil {
			t.Fatal(err)
		}
		secrets[who] = secret
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	list := func(as string, args ...string) string {
		t.Helper()
		t.Setenv("QUILZO_TOKEN", secrets[as])
		if err := authoriseCommand(root, args[0], args[1:]); err != nil {
			t.Fatalf("%s may not run %v: %v", as, args, err)
		}
		_, read := captureStdout(t)
		var err error
		if args[0] == "auth" {
			err = cmdAuth(root, args[1:])
		} else {
			err = cmdToken(root, args[1:])
		}
		out := read()
		if err != nil {
			t.Fatalf("%s %v: %v", as, args, err)
		}
		return out
	}

	if out := list("rae", "auth", "list"); !strings.Contains(out, "rae") || strings.Contains(out, "alice") {
		t.Errorf("a reader's grant list:\n%s", out)
	}
	if out := list("rae", "token", "list"); !strings.Contains(out, "rae-laptop") || strings.Contains(out, "alice-laptop") {
		t.Errorf("a reader's token list:\n%s", out)
	}
	if out := list("rae", "auth", "explain", "rae"); !strings.Contains(out, "rae on /") {
		t.Errorf("a reader could not explain their own access:\n%s", out)
	}
	t.Setenv("QUILZO_TOKEN", secrets["rae"])
	if err := cmdAuth(root, []string{"explain", "alice"}); err == nil {
		t.Error("a reader was told what somebody else may do")
	}
	if out := list("alice", "auth", "explain", "rae"); !strings.Contains(out, "rae on /") {
		t.Errorf("an administrator could not explain somebody's access:\n%s", out)
	}
	if out := list("alice", "auth", "list"); !strings.Contains(out, "rae") || !strings.Contains(out, "alice") {
		t.Errorf("an administrator's grant list:\n%s", out)
	}
	if out := list("alice", "token", "list"); !strings.Contains(out, "rae-laptop") || !strings.Contains(out, "alice-laptop") {
		t.Errorf("an administrator's token list:\n%s", out)
	}
}
