// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

// A session says how it was signed in to, and that is the level a request
// with it is made at: a passkey or single sign-on is two factors, a token
// alone one; a long-lived token, and a session that does not say, are one.
func TestASessionIsAtTheLevelItWasSignedInTo(t *testing.T) {
	ts := &TokenStore{}
	for _, c := range []struct {
		methods []string
		level   int
	}{
		{[]string{MethodPasskey}, 2},
		{[]string{MethodSSO}, 2},
		{[]string{MethodToken}, 1},
		{[]string{MethodToken, MethodPasskey}, 2},
		{nil, 1},
	} {
		_, tok, err := ts.IssueSession("s", "dana", RoleAdmin, "/", time.Hour, RoleAdmin, c.methods...)
		if err != nil {
			t.Fatal(err)
		}
		if tok.Level() != c.level {
			t.Errorf("%v: level %d, want %d", c.methods, tok.Level(), c.level)
		}
		if len(c.methods) > 0 && (tok.AuthAt == 0 || !tok.HasMethod(c.methods[0])) {
			t.Errorf("%v: the session does not record how or when: %+v", c.methods, tok)
		}
	}
	long, lt, err := ts.Issue("cli", "dana", RoleAdmin, "/", time.Hour, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if lt.Level() != 1 {
		t.Errorf("a long-lived token is level %d", lt.Level())
	}
	_, ex, err := ts.Exchange(long, RoleNone, "", 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ex.Level() != 1 || !ex.HasMethod(MethodToken) {
		t.Errorf("a session exchanged from a token says %v, level %d", ex.Methods, ex.Level())
	}
}
