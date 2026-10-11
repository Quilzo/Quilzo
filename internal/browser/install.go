// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package browser

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The browser this release drives.
//
// Pinned, not whatever Chromium a machine happens to have: the DevTools
// protocol changes between releases, and a browser nobody chose is one
// nobody can say what it does. Chrome for Testing is Google's build for
// exactly this, published with no auto-update, and its headless shell is
// the smallest of them, with nothing in it but what renders a page.
//
// Fetched on first use from Google's storage and refused unless it matches
// the SHA-256 written here, which was taken from the same files when this
// release was made. An offline deployment points browser.path at a copy of
// its own instead.

// Download is one platform's build.
type Download struct {
	URL    string
	SHA256 string
	Size   int64
	// Exe is the browser inside the archive.
	Exe string
}

// Pin is the pinned version and its builds by platform.
type Pin struct {
	Version string
	Builds  map[string]Download
}

// Pinned is the browser this release of Quilzo drives.
var Pinned = Pin{
	Version: "155.0.8059.39",
	Builds: map[string]Download{
		"linux/amd64": {
			URL:    "https://storage.googleapis.com/chrome-for-testing-public/155.0.8059.39/linux64/chrome-headless-shell-linux64.zip",
			SHA256: "39dcb8c46550632a3d911850ab3b8af840b4e3f6d8622faa2018eb8756278786",
			Size:   124203329,
			Exe:    "chrome-headless-shell-linux64/chrome-headless-shell",
		},
		"linux/arm64": {
			URL:    "https://storage.googleapis.com/chrome-for-testing-public/155.0.8059.39/linux-arm64/chrome-headless-shell-linux-arm64.zip",
			SHA256: "9fb86f7c0b2734c5febc0bbb4e85f37da43553f3f8a7970949828c5713e87e94",
			Size:   124553121,
			Exe:    "chrome-headless-shell-linux-arm64/chrome-headless-shell",
		},
	},
}

// ForThisMachine is the pinned build for the platform this runs on.
func (p Pin) ForThisMachine() (Download, error) {
	d, ok := p.Builds[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return Download{}, fmt.Errorf("no pinned browser for %s/%s; an agent's browser runs in the "+
			"agent box, which is Linux on amd64 or arm64", runtime.GOOS, runtime.GOARCH)
	}
	return d, nil
}

// Installed is the pinned browser under dir, when it is there and was
// checked when it was put there.
func (p Pin) Installed(dir string) (string, bool) {
	d, err := p.ForThisMachine()
	if err != nil {
		return "", false
	}
	base := filepath.Join(dir, p.Version)
	mark, err := os.ReadFile(filepath.Join(base, "SHA256"))
	if err != nil || strings.TrimSpace(string(mark)) != d.SHA256 {
		return "", false
	}
	exe := filepath.Join(base, filepath.FromSlash(d.Exe))
	if fi, err := os.Stat(exe); err != nil || fi.Mode()&0o111 == 0 {
		return "", false
	}
	return exe, true
}

// Install puts the pinned browser under dir, unless it is there already,
// and says where it is. get fetches a URL (through internal/fetch, which
// checks every address it connects to).
func (p Pin) Install(ctx context.Context, dir string, get func(ctx context.Context, url string, max int64) ([]byte, error)) (string, error) {
	if exe, ok := p.Installed(dir); ok {
		return exe, nil
	}
	d, err := p.ForThisMachine()
	if err != nil {
		return "", err
	}
	body, err := get(ctx, d.URL, d.Size+1)
	if err != nil {
		return "", fmt.Errorf("cannot download the browser: %w", err)
	}
	return p.unpack(dir, d, body)
}

func (p Pin) unpack(dir string, d Download, body []byte) (string, error) {
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != d.SHA256 {
		return "", fmt.Errorf("the browser downloaded is not the one this release pins (SHA-256 %s, "+
			"not %s); nothing was installed", got, d.SHA256)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(dir, ".installing-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	if err := extract(body, tmp); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(tmp, "SHA256"), []byte(d.SHA256+"\n"), 0o600); err != nil {
		return "", err
	}
	final := filepath.Join(dir, p.Version)
	_ = os.RemoveAll(final)
	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	exe, ok := p.Installed(dir)
	if !ok {
		return "", errors.New("the browser was unpacked and is not where the pin says it is")
	}
	return exe, nil
}

// extract unpacks a zip under dir. An entry that would land outside dir, a
// link, or a device is refused: the archive was checked against its hash,
// and this is the second line, not the first.
func extract(body []byte, dir string) error {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("the browser's archive cannot be read: %w", err)
	}
	for _, f := range zr.File {
		// Refused outright: an absolute name, or any ".." at all, which the
		// pinned archive never has. Then the place it would land is checked
		// to be under dir, whatever the name turned out to mean.
		if strings.Contains(f.Name, "..") || filepath.IsAbs(filepath.FromSlash(f.Name)) {
			return fmt.Errorf("the archive names %q, outside where it is unpacked", f.Name)
		}
		target := filepath.Join(dir, filepath.FromSlash(f.Name))
		if rel, err := filepath.Rel(dir, target); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("the archive names %q, outside where it is unpacked", f.Name)
		}
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		case !mode.IsRegular():
			return fmt.Errorf("the archive holds %q, which is not a plain file", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		perm := os.FileMode(0o644)
		if mode&0o111 != 0 {
			perm = 0o755
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		w, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
		if err != nil {
			r.Close()
			return err
		}
		_, err = io.Copy(w, io.LimitReader(r, int64(f.UncompressedSize64)+1))
		r.Close()
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}
