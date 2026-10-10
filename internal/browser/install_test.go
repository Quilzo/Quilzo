// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package browser

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0o755)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	zw.Close()
	return b.Bytes()
}

func pinOf(body []byte, exe string) Pin {
	sum := sha256.Sum256(body)
	d := Download{URL: "https://example.test/hs.zip", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)), Exe: exe}
	return Pin{Version: "1.2.3", Builds: map[string]Download{"linux/amd64": d, "linux/arm64": d}}
}

// The pinned archive is installed once, where Installed then finds it.
func TestThePinnedBrowserIsInstalledOnce(t *testing.T) {
	body := archive(t, map[string]string{"hs/chrome-headless-shell": "#!/bin/sh\n", "hs/resources.pak": "x"})
	pin := pinOf(body, "hs/chrome-headless-shell")
	dir := t.TempDir()
	gets := 0
	get := func(context.Context, string, int64) ([]byte, error) { gets++; return body, nil }
	exe, err := pin.Install(context.Background(), dir, get)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(exe); err != nil || fi.Mode()&0o111 == 0 {
		t.Fatalf("%s: %v", exe, err)
	}
	if _, err := pin.Install(context.Background(), dir, get); err != nil || gets != 1 {
		t.Errorf("installed again (%d downloads, %v)", gets, err)
	}
}

// An archive that is not the pinned one installs nothing.
func TestABrowserThatIsNotThePinnedOneIsRefused(t *testing.T) {
	body := archive(t, map[string]string{"hs/chrome-headless-shell": "#!/bin/sh\n"})
	pin := pinOf(body, "hs/chrome-headless-shell")
	other := archive(t, map[string]string{"hs/chrome-headless-shell": "#!/bin/sh\necho owned\n"})
	dir := t.TempDir()
	_, err := pin.Install(context.Background(), dir, func(context.Context, string, int64) ([]byte, error) { return other, nil })
	if err == nil || !strings.Contains(err.Error(), "not the one this release pins") {
		t.Fatalf("%v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("something was left: %v", entries)
	}
}

// An entry that climbs out of the directory is refused, even in an archive
// whose hash matches.
func TestAnArchiveCannotWriteOutsideItsDirectory(t *testing.T) {
	body := archive(t, map[string]string{"../../escaped": "x", "hs/chrome-headless-shell": "x"})
	pin := pinOf(body, "hs/chrome-headless-shell")
	dir := t.TempDir()
	if _, err := pin.Install(context.Background(), dir, func(context.Context, string, int64) ([]byte, error) { return body, nil }); err == nil {
		t.Fatal("an archive climbing out of its directory was installed")
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "..", "escaped")); err == nil {
		t.Error("the climbing entry was written")
	}
}
