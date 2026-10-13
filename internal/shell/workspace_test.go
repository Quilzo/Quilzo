// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// A workspace is worked on by one run at a time: of many claiming at
// once exactly one has it, it is free again once let go, and a run that
// dies lets go without anybody deciding it is gone.
func TestOneRunWorksOnAWorkspaceAtATime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "claims", "ws.claim")
	var mu sync.Mutex
	var won []*Claim
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if c, err := ClaimWorkspace(p, fmt.Sprintf("run-%d", i)); err == nil {
				mu.Lock()
				won = append(won, c)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(won) != 1 {
		t.Fatalf("%d runs hold the workspace at once", len(won))
	}
	if _, err := ClaimWorkspace(p, "run-late"); err == nil || !strings.Contains(err.Error(), "in use by run") {
		t.Errorf("claimed while held: %v", err)
	}
	won[0].Release()
	b, err := ClaimWorkspace(p, "run-b")
	if err != nil {
		t.Fatal(err)
	}
	// Gone without letting go: the kernel lets go for it.
	b.f.Close()
	if _, err := ClaimWorkspace(p, "run-c"); err != nil {
		t.Errorf("a dead run's claim was kept: %v", err)
	}
}

// Writing is never redirected: not by a link or a named pipe left at the
// file's temporary name, not through a linked folder, and git's own folder
// is not written by hand.
func TestAWriteGoesWhereItSays(t *testing.T) {
	w, dir := workspace(t)
	_ = os.MkdirAll(filepath.Join(dir, "scripts"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "scripts", "test.sh"), []byte("echo ok"), 0o755)
	if err := os.Symlink("scripts/test.sh", filepath.Join(dir, "n.quilzo-writing")); err != nil {
		t.Fatal(err)
	}
	if err := w.Write("n", "planted"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "scripts", "test.sh")); string(b) != "echo ok" {
		t.Errorf("the write went through a link to another file: %q", b)
	}
	if err := os.Symlink("scripts", filepath.Join(dir, "docs")); err != nil {
		t.Fatal(err)
	}
	if err := w.Write("docs/new.md", "x"); err == nil || !strings.Contains(err.Error(), "through a link") {
		t.Errorf("wrote through a linked folder: %v", err)
	}
	for _, name := range []string{".git/config", ".GIT/hooks/pre-commit", "sub/.git/config"} {
		if err := w.Write(name, "[core]\n\tfsmonitor = sh -c x\n"); err == nil {
			t.Errorf("wrote %s", name)
		}
	}
}

// A scan that cannot see a folder, or stops at its bound, says so, and a
// changed mode is a change.
func TestAScanSaysWhatItCouldNotSee(t *testing.T) {
	w, dir := workspace(t)
	_ = w.Write("build.sh", "echo")
	before := w.Scan()
	if before.Cut {
		t.Fatal("an ordinary workspace was cut")
	}
	_ = os.Chmod(filepath.Join(dir, "build.sh"), 0o755)
	if c := w.Scan().Since(before); strings.Join(c.Changed, ",") != "build.sh" {
		t.Errorf("a changed mode was not seen: %+v", c)
	}
	_ = os.MkdirAll(filepath.Join(dir, "locked"), 0o755)
	_ = w.Write("locked/big.bin", strings.Repeat("x", 1000))
	_ = os.Chmod(filepath.Join(dir, "locked"), 0)
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "locked"), 0o755) })
	if os.Getuid() != 0 && !w.Scan().Cut {
		t.Error("a folder it could not read was taken as empty")
	}
}
