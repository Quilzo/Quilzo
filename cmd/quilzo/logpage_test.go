// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
)

// The log page names the people this store knows from one table a view.
// Asked per pseudonym, resolving opened the log each time, reading the key,
// the host name and the end of the file, and it created a key where there
// was none: a read that wrote, and a view of a log visitors had written to
// that took seconds. The table is built from the key once and then answers
// without touching the file.
func TestTheLogPageNamesPeopleFromOneTable(t *testing.T) {
	root := shownLog(t, published("/a"))
	key, err := os.ReadFile(auditKeyPath(root))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := toks.Issue("ci", "builder", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	srv := &admin.Server{}
	logPageHooks(srv, root, pol, toks)

	resolve := srv.Resolver()
	if got := resolve(audit.Pseudonym(key, "dana")); got != "dana" {
		t.Errorf("a person the policy knows resolved to %q", got)
	}
	if got := resolve(audit.Pseudonym(key, "builder")); got != "builder" {
		t.Errorf("a token's principal resolved to %q", got)
	}
	if got := resolve(audit.Pseudonym(key, "stranger")); got != "" {
		t.Errorf("somebody the store does not know was named %q", got)
	}
	if got := srv.ResolvePrincipal(audit.Pseudonym(key, "dana")); got != "dana" {
		t.Errorf("ResolvePrincipal answers %q", got)
	}

	// The table answers without the file, and nothing a view does makes a
	// key.
	if err := os.Remove(auditKeyPath(root)); err != nil {
		t.Fatal(err)
	}
	if got := resolve(audit.Pseudonym(key, "dana")); got != "dana" {
		t.Errorf("a view's table went back to the file: %q", got)
	}
	if got := srv.ResolvePrincipal(audit.Pseudonym(key, "dana")); got != "" {
		t.Errorf("a pseudonym was resolved without a key: %q", got)
	}
	if _, err := os.Stat(auditKeyPath(root)); !os.IsNotExist(err) {
		t.Errorf("resolving a pseudonym created the log's key: %v", err)
	}
}

// The page's index is the log where it is now: one per place, and kept, so
// a view reads what was appended since the last one.
func TestTheLogPageFollowsTheLog(t *testing.T) {
	root := shownLog(t, published("/a"))
	pol, _ := loadPolicy(root)
	toks, _ := loadTokens(root)
	srv := &admin.Server{}
	logPageHooks(srv, root, pol, toks)

	first := srv.AuditIndex()
	if srv.AuditIndex() != first {
		t.Error("each view made a new index, and read the whole log again")
	}
	if s, err := first.Look(); err != nil || s.Len() != 1 {
		t.Fatalf("the index does not hold the log: %v", err)
	}
	moved := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(moved, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "auditlog.dir"), []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := srv.AuditIndex().Look(); err != nil || s.Len() != 0 {
		t.Errorf("the page still reads the log from where it was: %v", err)
	}
}
