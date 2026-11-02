// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sources(files map[string]string) []Source {
	var out []Source
	for p, body := range files {
		b := body
		out = append(out, Source{Path: p, Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(b)), nil }})
	}
	return out
}

// A backup restores what it was made of, file for file, and nothing of
// it is readable without its key.
func TestABackupRestoresWhatItHolds(t *testing.T) {
	key, _ := NewKey()
	big := strings.Repeat("ink ", 50_000) // several chunks
	files := map[string]string{"store/config.json": `{"site":"Marginalia"}`, "store/objects/ab/cdef": big,
		"templates/page.html": "<main>{{.Title}}</main>", "store/empty": ""}
	var buf bytes.Buffer
	m, err := Write(&buf, key, sources(files), "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 4 || m.Bytes != int64(len(big)+len(`{"site":"Marginalia"}`)+len("<main>{{.Title}}</main>")) {
		t.Fatalf("%+v", m)
	}
	if bytes.Contains(buf.Bytes(), []byte("Marginalia")) || bytes.Contains(buf.Bytes(), []byte("ink ink")) {
		t.Fatal("the backup can be read without its key")
	}
	if _, err := Verify(bytes.NewReader(buf.Bytes()), key); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "restored")
	got, err := Restore(bytes.NewReader(buf.Bytes()), key, dir)
	if err != nil || len(got.Files) != 4 {
		t.Fatalf("%+v %v", got, err)
	}
	for p, body := range files {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil || string(b) != body {
			t.Fatalf("%s: %d bytes, %v", p, len(b), err)
		}
	}
	if _, err := Restore(bytes.NewReader(buf.Bytes()), key, dir); err == nil {
		t.Fatal("restored over what is there")
	}
}

// A backup changed anywhere, cut short, put together from another's
// parts, or read with the wrong key is refused: a backup that checks is
// one that restores.
func TestADamagedBackupIsRefused(t *testing.T) {
	key, _ := NewKey()
	other, _ := NewKey()
	files := map[string]string{"store/a": strings.Repeat("a", 200_000), "store/b": "b"}
	var buf bytes.Buffer
	if _, err := Write(&buf, key, sources(files), "", time.Now()); err != nil {
		t.Fatal(err)
	}
	good := buf.Bytes()
	if _, err := Verify(bytes.NewReader(good), other); err == nil {
		t.Error("read with another key")
	}
	flipped := append([]byte{}, good...)
	flipped[len(Magic)+saltSize+100] ^= 1
	if _, err := Verify(bytes.NewReader(flipped), key); err == nil {
		t.Error("a changed byte")
	}
	salt := append([]byte{}, good...)
	salt[len(Magic)+3] ^= 1
	if _, err := Verify(bytes.NewReader(salt), key); err == nil {
		t.Error("a changed header")
	}
	// Cut at the end of the first chunk: what is left looks whole, and its
	// last chunk was not sealed as the last.
	first := len(Magic) + saltSize + 4 + chunkSize + overhead
	if _, err := Verify(bytes.NewReader(good[:first]), key); err == nil {
		t.Error("cut short at a chunk's end")
	}
	if _, err := Verify(bytes.NewReader(good[:len(good)-10]), key); err == nil {
		t.Error("cut short")
	}
	if _, err := Verify(strings.NewReader("not a backup at all"), key); err == nil || !strings.Contains(err.Error(), "not a Quilzo backup") {
		t.Errorf("%v", err)
	}
	if _, err := Write(io.Discard, key, sources(map[string]string{"../escape": "x"}), "", time.Now()); err == nil {
		t.Error("a path outside the backup")
	}
	if _, err := Write(io.Discard, key, sources(map[string]string{"/etc/passwd": "x"}), "", time.Now()); err == nil {
		t.Error("an absolute path")
	}
}

// Collect takes every regular file but locks and what is skipped, and puts
// the named directories last: history's objects after the pointers to them.
func TestCollectTakesTheStoreInOrder(t *testing.T) {
	dir := t.TempDir()
	for p, body := range map[string]string{"refs/live": "x", "objects/ab/cd": "y", "config.json": "z", "refs.lock": "",
		"tmp/scratch": "t", "media/a.png": "m"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o700)
		os.WriteFile(full, []byte(body), 0o600)
	}
	srcs, err := Collect(dir, "store", func(rel string) bool { return rel == "tmp" }, "objects")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, s := range srcs {
		paths = append(paths, s.Path)
	}
	if got := strings.Join(paths, " "); got != "store/config.json store/media/a.png store/refs/live store/objects/ab/cd" {
		t.Fatalf("%s", got)
	}
	if _, err := DecodeKey(EncodeKey([]byte("short"))); err == nil {
		t.Error("a short key")
	}
}
