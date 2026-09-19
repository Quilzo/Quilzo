// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
)

// The flag wins, because an operator scripting a migration may legitimately be
// recording somebody else's decision.
func TestAnExplicitGranterIsKept(t *testing.T) {
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if got := grantedBy(root, "the migration script"); got != "the migration script" {
		t.Errorf("the flag became %q", got)
	}
	if got := grantedBy(root, "  spaced  "); got != "  spaced  " {
		t.Errorf("the flag was trimmed to %q", got)
	}
}

// With no access control there is genuinely no identity to record, and "cli"
// is the honest answer there rather than a made-up name.
func TestAStoreWithNoIdentityRecordsTheSurface(t *testing.T) {
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if got := grantedBy(root, ""); got != "cli" {
		t.Errorf("an unauthenticated grant recorded %q", got)
	}
}

// Binding.GrantedBy is written on both surfaces and was read by neither, so
// "who gave this principal admin?" lived in policy.json and nowhere a person
// looks. Both now show it, and a binding from before it was recorded says so
// rather than showing an empty cell — empty reads as nobody.
func TestBothSurfacesShowWhoGranted(t *testing.T) {
	cli, err := readSource(t, "auth.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cli, "granted by") {
		t.Error("`quilzo auth list` does not print who granted a binding")
	}
	if !strings.Contains(cli, "unrecorded") {
		t.Error("`quilzo auth list` does not distinguish an unrecorded granter")
	}

	screen, err := readSource(t, "../../internal/admin/assets/access.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(screen, ".GrantedBy") {
		t.Error("the access screen does not show who granted a binding")
	}
	if !strings.Contains(screen, "Granted by") {
		t.Error("the access screen has no column heading for it")
	}
}

func readSource(t *testing.T, path string) (string, error) {
	t.Helper()
	b, err := os.ReadFile(path)
	return string(b), err
}
