// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/lockout"
)

// The operator lets a locked-out administrator in again from the command
// line, which is how a store whose only administrator is locked out gets
// them back; somebody without the right to grant cannot.
func TestAuthUnlockLetsALockedOutAccountIn(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	for _, g := range [][]string{{"grant", "boss", "admin"}, {"grant", "pat", "author"}} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	for i := 0; i < lockout.Ceiling; i++ {
		if _, _, err := lockoutStore(root).Fail("boss", "192.0.2.10", now); err != nil {
			t.Fatal(err)
		}
	}
	ts, _ := loadTokens(root)
	pat, _, err := ts.Issue("p", "pat", auth.RoleAuthor, "/", time.Hour, auth.RoleAuthor)
	if err != nil {
		t.Fatal(err)
	}
	boss, _, err := ts.Issue("b", "boss", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", pat)
	if err := cmdAuth(root, []string{"unlock", "boss"}); err == nil {
		t.Error("an author unlocked an administrator")
	}
	t.Setenv("QUILZO_TOKEN", boss)
	if err := cmdAuth(root, []string{"unlock", "boss"}); err != nil {
		t.Fatal(err)
	}
	if held, _ := lockoutStore(root).Held(now); len(held) != 0 {
		t.Fatalf("still held: %+v", held)
	}
	body, _ := os.ReadFile(auditPath(root))
	if !strings.Contains(string(body), "account.unlocked") {
		t.Error("the unlock was not recorded")
	}
}
