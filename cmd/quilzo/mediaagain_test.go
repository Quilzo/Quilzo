// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/out"
)

// Adding a picture the library already holds keeps its description, as the
// browser's upload does, and says so; replacing the description is asked
// for with --replace-alt. And a picture can be marked decorative from the
// command line, as it can in the browser: the refusal used to say to pass
// --alt "" "once that is supported", and it never was.
func TestAddingAPictureAgainKeepsItsDescription(t *testing.T) {
	root := storeFolder(t)
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pic := filepath.Join(t.TempDir(), "red.png")
	if err := os.WriteFile(pic, tinyPNG(t), 0o600); err != nil {
		t.Fatal(err)
	}
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf

	stored := func() media.File {
		t.Helper()
		lib, err := medialib.Open(filepath.Join(root, "media"))
		if err != nil {
			t.Fatal(err)
		}
		files, err := lib.List()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if f.Name == "red.png" {
				return f
			}
		}
		t.Fatal("red.png is not in the library")
		return media.File{}
	}

	if err := cmdMedia(root, []string{"add", pic, "--alt", "A red square"}); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := cmdMedia(root, []string{"add", pic, "--alt", "Something else entirely"}); err != nil {
		t.Fatal(err)
	}
	if got := stored().Alt; got != "A red square" {
		t.Errorf("a second add replaced the description with %q", got)
	}
	if !strings.Contains(buf.String(), "already in the library") {
		t.Errorf("the second add did not say the file was there: %q", buf.String())
	}
	if err := cmdMedia(root, []string{"add", pic, "--decorative"}); err != nil {
		t.Fatal(err)
	}
	if got := stored().Alt; got != "A red square" {
		t.Errorf("a decorative add erased the description: %q", got)
	}
	if err := cmdMedia(root, []string{"add", pic, "--alt", "A small red square", "--replace-alt"}); err != nil {
		t.Fatal(err)
	}
	if got := stored().Alt; got != "A small red square" {
		t.Errorf("--replace-alt did not replace the description: %q", got)
	}

	// Decorative, for a picture the library does not have yet.
	blue := filepath.Join(t.TempDir(), "rule.png")
	if err := os.WriteFile(blue, picture(t, 40), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdMedia(root, []string{"add", blue, "--decorative"}); err != nil {
		t.Errorf("a decorative picture could not be added: %v", err)
	}
	if err := cmdMedia(root, []string{"add", blue, "--decorative", "--alt", "words"}); err == nil {
		t.Error("a picture was both decorative and described")
	}
}

// Adding a picture whose bytes the library has lost puts them back. The
// record was still there, so the add took the file for one already in the
// library, stored nothing and said it was kept as it was, while every page
// showing it showed a broken picture: the one thing somebody does about a
// broken picture is add it again.
func TestAddingAPictureAgainPutsBackBytesThatWereLost(t *testing.T) {
	root := storeFolder(t)
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pic := filepath.Join(t.TempDir(), "red.png")
	if err := os.WriteFile(pic, tinyPNG(t), 0o600); err != nil {
		t.Fatal(err)
	}
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(false)
	w.Out = &buf
	if err := cmdMedia(root, []string{"add", pic, "--alt", "A red square"}); err != nil {
		t.Fatal(err)
	}
	lib, err := medialib.Open(filepath.Join(root, "media"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := lib.List()
	if err != nil || len(files) == 0 {
		t.Fatalf("nothing in the library: %v", err)
	}
	id := files[0].ID
	if err := os.Remove(filepath.Join(root, "media", id[0:2], id[2:4], id)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lib.Get(id); err == nil {
		t.Fatal("the bytes are still there")
	}

	buf.Reset()
	if err := cmdMedia(root, []string{"add", pic, "--alt", "A red square"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lib.Get(id); err != nil {
		t.Errorf("adding the picture again did not put its bytes back: %v (%q)", err, buf.String())
	}
}
