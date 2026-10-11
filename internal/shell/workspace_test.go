// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func workspace(t *testing.T) (*Workspace, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ws")
	w, err := OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w, dir
}

// Nothing a name says leads out of the workspace: not "..", not an
// absolute path, not a link to somewhere else, not a link's folder.
func TestNoNameLeadsOutOfTheWorkspace(t *testing.T) {
	w, dir := workspace(t)
	outside := filepath.Join(filepath.Dir(dir), "secret.txt")
	if err := os.WriteFile(outside, []byte("not yours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(dir), filepath.Join(dir, "up")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../secret.txt", "a/../../secret.txt", outside, "/etc/passwd", "link.txt", "up/secret.txt"} {
		if s, err := w.Read(name); err == nil {
			t.Errorf("read %s: %q", name, s)
		}
		// Writing over the link replaces the link, in the workspace; it
		// never writes where the link pointed.
		if err := w.Write(name, "x"); err == nil && name != "link.txt" {
			t.Errorf("wrote %s", name)
		}
	}
	if b, _ := os.ReadFile(outside); string(b) != "not yours" {
		t.Fatalf("the file outside was changed: %q", b)
	}
	if _, _, err := w.List("up"); err == nil {
		t.Error("listed a folder outside through a link")
	}
}

// Files are read and written whole, within the bounds, and a folder is
// listed with what each thing is.
func TestTheWorkspacesFilesAreReadAndWritten(t *testing.T) {
	w, dir := workspace(t)
	if err := w.Write("docs/notes.md", "# Notes\n"); err != nil {
		t.Fatal(err)
	}
	if s, err := w.Read("docs/notes.md"); err != nil || s != "# Notes\n" {
		t.Fatalf("%q %v", s, err)
	}
	items, more, err := w.List(".")
	if err != nil || more || len(items) != 1 || items[0].Name != "docs" || items[0].Kind != "folder" {
		t.Fatalf("%+v %v %v", items, more, err)
	}
	if err := w.Write("big.txt", strings.Repeat("x", MaxWrite+1)); err == nil {
		t.Error("wrote more than a write may be")
	}
	if err := os.WriteFile(filepath.Join(dir, "bin"), []byte{0, 1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read("bin"); err == nil || !strings.Contains(err.Error(), "not text") {
		t.Errorf("a binary file was read as text: %v", err)
	}
	if _, err := w.Read("docs"); err == nil {
		t.Error("a folder was read as a file")
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "docs")); len(entries) != 1 {
		t.Errorf("a write left something beside the file: %v", entries)
	}
}

// What a step changed is told apart from what was there: added, changed
// and removed, git's own folder left out.
func TestWhatChangedIsSeen(t *testing.T) {
	w, dir := workspace(t)
	_ = w.Write("a.go", "package a")
	_ = w.Write("b.go", "package b")
	_ = w.Write(".git/HEAD", "ref: main")
	before := w.Scan()
	time.Sleep(10 * time.Millisecond)
	_ = w.Write("a.go", "package a // changed")
	_ = os.Remove(filepath.Join(dir, "b.go"))
	_ = w.Write("c.go", "package c")
	_ = w.Write(".git/HEAD", "ref: other")
	c := w.Scan().Since(before)
	if strings.Join(c.Added, ",") != "c.go" || strings.Join(c.Changed, ",") != "a.go" || strings.Join(c.Removed, ",") != "b.go" {
		t.Errorf("%+v", c)
	}
	if !strings.Contains(c.String(), "added c.go") {
		t.Errorf("%s", c)
	}
}

// A workspace is worked on by one run at a time; a claim left by a run
// that is gone is taken over.
func TestOneRunWorksOnAWorkspaceAtATime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "claims", "ws.claim")
	a, err := ClaimWorkspace(p, "run-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimWorkspace(p, "run-b"); err == nil || !strings.Contains(err.Error(), "run-a") {
		t.Errorf("a second run claimed it: %v", err)
	}
	a.Release()
	b, err := ClaimWorkspace(p, "run-b")
	if err != nil {
		t.Fatal(err)
	}
	// Gone, as far as anybody can tell.
	old := time.Now().Add(-2 * ClaimStale)
	_ = os.WriteFile(p, []byte(`{"run":"run-b","beat":"`+old.UTC().Format(time.RFC3339)+`"}`), 0o600)
	if _, err := ClaimWorkspace(p, "run-c"); err != nil {
		t.Errorf("a stale claim was not taken over: %v", err)
	}
	b.Release() // not run-b's any more: left alone
	if _, err := os.Stat(p); err != nil {
		t.Error("a run let go of a claim it no longer held")
	}
}
