// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Chrome, Chromium and the rest are found by their programs: a launcher
// on the path is followed to the program it links to, a script is named
// as one, a program that does not say it is a Chromium is refused, and
// nothing is listed twice.
func TestTheBrowsersAMachineHasAreFound(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	chrome := write("opt/google/chrome/chrome", "\x7fELF chrome")
	chromium := write("usr/lib/chromium/chromium", "\x7fELF chromium")
	script := write("bin/edge-launcher", "#!/bin/sh\nexec /opt/microsoft/msedge/msedge \"$@\"\n")
	other := write("opt/other/chrome", "\x7fELF something else")
	bin := filepath.Join(dir, "usr/bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(chromium, filepath.Join(bin, "chromium")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(script, filepath.Join(bin, "microsoft-edge")); err != nil {
		t.Fatal(err)
	}
	cache := write("cache/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell", "\x7fELF shell")

	old := browserVersion
	browserVersion = func(p string) (string, error) {
		switch p {
		case chrome:
			return "Google Chrome 155.0.8059.39", nil
		case chromium:
			return "Chromium 154.0.8001.12", nil
		case cache:
			return "Google Chrome for Testing 155.0.8059.39", nil
		}
		return old(p)
	}
	t.Cleanup(func() { browserVersion = old })

	found := findBrowsers([]string{chrome, filepath.Join(dir, "missing/chrome"), other},
		[]string{"chromium", "microsoft-edge"},
		[]string{filepath.Join(dir, "cache", "chromium_headless_shell-*", "chrome-headless-shell-linux*", "chrome-headless-shell")},
		[]string{bin})
	byPath := map[string]foundBrowser{}
	for _, f := range found {
		if _, twice := byPath[f.Path]; twice {
			t.Errorf("%s listed twice", f.Path)
		}
		byPath[f.Path] = f
	}
	if byPath[chrome].Version != "Google Chrome 155.0.8059.39" || byPath[chromium].Version != "Chromium 154.0.8001.12" ||
		byPath[cache].Version != "Google Chrome for Testing 155.0.8059.39" {
		t.Errorf("%+v", found)
	}
	if f := byPath[script]; !strings.Contains(f.Problem, "a script") {
		t.Errorf("a launcher script was taken for the browser: %+v", f)
	}
	if f := byPath[other]; f.Version != "" || f.Problem == "" {
		t.Errorf("a program that is not a Chromium was taken for one: %+v", f)
	}
	if len(found) != 5 {
		t.Errorf("%d found: %+v", len(found), found)
	}
}
