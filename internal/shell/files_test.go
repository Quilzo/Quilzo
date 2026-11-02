// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustWrite(t *testing.T, w *Workspace, name, text string) {
	t.Helper()
	if err := w.Write(name, text); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, w *Workspace, name string) string {
	t.Helper()
	s, err := w.Read(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// An edit replaces text that is there once, or every time when it says so,
// and refuses one it cannot place; lines go in where they are asked for.
func TestAFileIsEditedInPlace(t *testing.T) {
	w, _ := workspace(t)
	mustWrite(t, w, "main.go", "package main\n\nfunc main() {\n\tprintln(\"hi\")\n\tprintln(\"hi\")\n}\n")
	if _, err := w.Edit("main.go", "println(\"hi\")", "println(\"hello\")", false); err == nil ||
		!strings.Contains(err.Error(), "2 times") {
		t.Fatalf("an edit that could go in two places: %v", err)
	}
	if n, err := w.Edit("main.go", "println(\"hi\")", "println(\"hello\")", true); err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := w.Edit("main.go", "println(\"bye\")", "x", false); err == nil || !strings.Contains(err.Error(), "does not contain") {
		t.Fatalf("an edit of text that is not there: %v", err)
	}
	if n, err := w.Edit("main.go", "package main\n", "// Package main greets.\npackage main\n", false); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	if err := w.Insert("main.go", 0, "//go:build ignore\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Insert("main.go", 3, "import \"os\""); err != nil {
		t.Fatal(err)
	}
	want := "//go:build ignore\n// Package main greets.\npackage main\nimport \"os\"\n\nfunc main() {\n\tprintln(\"hello\")\n\tprintln(\"hello\")\n}\n"
	if got := mustRead(t, w, "main.go"); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if err := w.Insert("main.go", 99, "x"); err == nil {
		t.Error("lines went in after a line the file does not have")
	}
	// Onto the end of a file with no last newline.
	mustWrite(t, w, "list.txt", "a\nb")
	if err := w.Insert("list.txt", 2, "c"); err != nil || mustRead(t, w, "list.txt") != "a\nb\nc\n" {
		t.Fatalf("%q %v", mustRead(t, w, "list.txt"), err)
	}
	// Not git's own folder, not a picture, not the workspace.
	mustWrite(t, w, "x.txt", "x")
	if err := os.MkdirAll(filepath.Join(w.Dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Dir, ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Edit(".git/config", "[core]", "[core]\n\thooksPath = /tmp", false); err == nil {
		t.Error("git's own folder was edited by hand")
	}
	if err := os.WriteFile(filepath.Join(w.Dir, "pic.png"), []byte("\x89PNG\x00\x01"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Edit("pic.png", "PNG", "JPG", false); err == nil {
		t.Error("a file that is not text was edited")
	}
	if _, err := w.Edit(".", "a", "b", false); err == nil {
		t.Error("the workspace itself was edited")
	}
}

// A deletion goes to the bin, from where a move brings it back; deleting
// from the bin is for good; and what has been there a week goes.
func TestADeletionCanBeTakenBack(t *testing.T) {
	w, dir := workspace(t)
	mustWrite(t, w, "docs/plan.md", "the plan")
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	where, err := w.Delete("docs/plan.md", now)
	if err != nil || !strings.HasPrefix(where, Bin+"/20261102T100000Z-") || !strings.HasSuffix(where, "/docs/plan.md") {
		t.Fatalf("%q %v", where, err)
	}
	if _, err := w.Read("docs/plan.md"); err == nil {
		t.Fatal("still there after it was deleted")
	}
	if _, err := w.Move(where, "docs/plan.md", now); err != nil || mustRead(t, w, "docs/plan.md") != "the plan" {
		t.Fatalf("not brought back: %v", err)
	}
	// A folder, whole.
	mustWrite(t, w, "old/a.txt", "a")
	mustWrite(t, w, "old/b/c.txt", "c")
	where, err = w.Delete("old", now)
	if err != nil || !IsInBin(where) {
		t.Fatalf("%q %v", where, err)
	}
	if got := mustRead(t, w, where+"/b/c.txt"); got != "c" {
		t.Fatalf("%q", got)
	}
	// From the bin, for good.
	if gone, err := w.Delete(where, now); err != nil || gone != "" {
		t.Fatalf("%q %v", gone, err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(where))); !os.IsNotExist(err) {
		t.Fatal("deleting from the bin left it there")
	}
	// A week on, what was in the bin goes when something else is deleted.
	mustWrite(t, w, "tmp.txt", "t")
	first, _ := w.Delete("tmp.txt", now)
	mustWrite(t, w, "tmp2.txt", "t")
	if _, err := w.Delete("tmp2.txt", now.Add(BinKeep+time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(first))); !os.IsNotExist(err) {
		t.Fatal("a week on, the bin still held it")
	}
	for _, name := range []string{".", "", "../x", "/etc/passwd", ".git", ".git/HEAD", "missing.txt"} {
		if _, err := w.Delete(name, now); err == nil {
			t.Errorf("deleted %q", name)
		}
	}
}

// A move renames within the workspace; what was at the new name goes to
// the bin rather than being lost; nothing moves into git's own folder, the
// bin, itself, or out.
func TestMovingNeverLosesWhatWasThere(t *testing.T) {
	w, dir := workspace(t)
	mustWrite(t, w, "draft.md", "new")
	mustWrite(t, w, "docs/final.md", "old")
	said, err := w.Move("draft.md", "docs/final.md", time.Now())
	if err != nil || !strings.Contains(said, "is in the bin") {
		t.Fatalf("%q %v", said, err)
	}
	if mustRead(t, w, "docs/final.md") != "new" {
		t.Fatal("not moved")
	}
	_, kept, _ := strings.Cut(said, " is in the bin as ")
	if mustRead(t, w, kept) != "old" {
		t.Fatal("what was there was lost")
	}
	mustWrite(t, w, "a/b.txt", "b")
	if _, err := w.Move("a/b.txt", "deep/er/b.txt", time.Now()); err != nil || mustRead(t, w, "deep/er/b.txt") != "b" {
		t.Fatalf("folders on the way were not made: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, "hook.sh", "#!/bin/sh\n")
	if err := os.MkdirAll(filepath.Join(filepath.Dir(dir), "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(dir), "elsewhere"), filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"hook.sh", ".git/hooks/pre-commit"}, {"hook.sh", Bin + "/x"}, {"deep", "deep/inside"},
		{"hook.sh", "../hook.sh"}, {"hook.sh", "out/hook.sh"}, {"hook.sh", "hook.sh"}, {"missing", "x"}, {".", "x"}} {
		if _, err := w.Move(c[0], c[1], time.Now()); err == nil {
			t.Errorf("moved %s to %s", c[0], c[1])
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "elsewhere", "hook.sh")); err == nil {
		t.Fatal("moved out of the workspace through a link")
	}
}

// A search finds files by name, lines by text or pattern, and neither in
// git's own folder nor the bin nor through a link.
func TestASearchFindsNamesAndLines(t *testing.T) {
	w, dir := workspace(t)
	mustWrite(t, w, "src/a.go", "package a\n// TODO: tidy\nfunc A() {}\n")
	mustWrite(t, w, "src/b.go", "package b\n// todo later\n")
	mustWrite(t, w, "README.md", "TODO list\n")
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "notes.go"), []byte("TODO in git\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, "gone.go", "// TODO gone\n")
	if _, err := w.Delete("gone.go", time.Now()); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(dir), "secret")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "s.go"), []byte("TODO secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	found, cut, err := w.Search(".", "*.go", "", false, false)
	if err != nil || cut || len(found) != 2 || found[0].File != "src/a.go" || found[1].File != "src/b.go" {
		t.Fatalf("by name: %+v %v %v", found, cut, err)
	}
	found, _, err = w.Search(".", "", "TODO", false, false)
	if err != nil || len(found) != 2 || found[0] != (Found{File: "README.md", Line: 1, Text: "TODO list"}) ||
		found[1] != (Found{File: "src/a.go", Line: 2, Text: "// TODO: tidy"}) {
		t.Fatalf("by text: %+v %v", found, err)
	}
	found, _, _ = w.Search("src", "*.go", "todo", false, true)
	if len(found) != 2 {
		t.Fatalf("ignoring case: %+v", found)
	}
	found, _, _ = w.Search(".", "", `^func [A-Z]\w*\(`, true, false)
	if len(found) != 1 || found[0].Line != 3 {
		t.Fatalf("by pattern: %+v", found)
	}
	// What the bin holds is found when the bin is where it looks.
	if found, _, _ := w.Search(Bin, "", "TODO", false, false); len(found) != 1 {
		t.Fatalf("in the bin: %+v", found)
	}
	for _, bad := range [][3]string{{".", "", ""}, {".", "[", ""}, {".", "", "(("}, {"../", "", "x"}} {
		if _, _, err := w.Search(bad[0], bad[1], bad[2], true, false); err == nil {
			t.Errorf("searched %q", bad)
		}
	}
	// Bounded: no more than MaxFound lines, and it says it stopped.
	var many strings.Builder
	for i := 0; i < MaxFound+50; i++ {
		fmt.Fprintf(&many, "match %d\n", i)
	}
	mustWrite(t, w, "many.txt", many.String())
	if found, cut, _ := w.Search(".", "many.txt", "match", false, false); len(found) != MaxFound || !cut {
		t.Fatalf("%d found, cut %v", len(found), cut)
	}
}

// A file too large to read whole is read part by part, by its lines.
func TestPartOfALargeFileIsRead(t *testing.T) {
	w, dir := workspace(t)
	var b strings.Builder
	for i := 1; i <= 40000; i++ {
		fmt.Fprintf(&b, "line %d of the log\n", i)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.log"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Read("big.log"); err == nil {
		t.Fatal("a file over the bound was read whole")
	}
	text, total, err := w.ReadLines("big.log", 39999, 10)
	if err != nil || total != 40000 || text != "line 39999 of the log\nline 40000 of the log\n" {
		t.Fatalf("%q %d %v", text, total, err)
	}
	if _, _, err := w.ReadLines("big.log", 40001, 1); err == nil {
		t.Error("read a line past the end")
	}
	// A part is bounded too.
	text, _, _ = w.ReadLines("big.log", 1, 40000)
	if len(text) > MaxRead {
		t.Fatalf("%d bytes from one read", len(text))
	}
	if _, _, err := w.ReadLines(path.Join("..", "x"), 1, 1); err == nil {
		t.Error("read outside the workspace")
	}
}
