// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/out"
)

// Finding the Chrome or Chromium a machine already has, for a deployment
// that would rather drive it than fetch the pinned build: Google Chrome
// (stable, beta or dev), Chromium as the distributions package it,
// Microsoft Edge and Brave, which are Chromium too, and Chrome for Testing
// or its headless shell where a test tool left one.
//
// Each is named by the program itself, not the launcher script a
// distribution puts on the path: the browser runs in the agent box, which
// lets it read the folder it is in and the system's libraries, and a
// script that starts it from somewhere else would not run there. A snap
// is refused for the same reason: it starts through snapd, which the box
// does not have.

// browserCandidates are where a Chromium is, by the program itself.
var browserCandidates = []string{
	"/opt/google/chrome/chrome",
	"/opt/google/chrome-beta/chrome",
	"/opt/google/chrome-unstable/chrome",
	"/usr/lib/chromium/chromium",
	"/usr/lib/chromium-browser/chromium-browser",
	"/usr/lib64/chromium-browser/chromium-browser",
	"/usr/lib/chromium/chrome",
	"/opt/microsoft/msedge/msedge",
	"/opt/microsoft/msedge-beta/msedge",
	"/opt/brave.com/brave/brave",
}

// browserLaunchers are launchers on the path, followed to the program
// when they are links to it.
var browserLaunchers = []string{"google-chrome-stable", "google-chrome", "chromium", "chromium-browser",
	"microsoft-edge", "brave-browser"}

// browserCaches are where test tools keep Chrome for Testing builds.
func browserCaches() []string {
	home, _ := os.UserHomeDir()
	var globs []string
	for _, base := range []string{filepath.Join(home, ".cache", "ms-playwright"), "/opt/pw-browsers",
		filepath.Join(home, ".cache", "puppeteer")} {
		globs = append(globs,
			filepath.Join(base, "chromium-*", "chrome-linux*", "chrome"),
			filepath.Join(base, "chromium_headless_shell-*", "chrome-headless-shell-linux*", "chrome-headless-shell"),
			filepath.Join(base, "chrome", "linux*", "chrome-linux*", "chrome"),
			filepath.Join(base, "chrome-headless-shell", "linux*", "chrome-headless-shell-linux*", "chrome-headless-shell"))
	}
	return globs
}

// foundBrowser is one Chromium on this machine.
type foundBrowser struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	Problem string `json:"problem,omitempty"`
	InUse   bool   `json:"in_use,omitempty"`
}

var reBrowserVersion = regexp.MustCompile(`(?i)(chrom|edge|brave)[^\n]*?\d+\.\d+\.\d+\.\d+`)

// browserVersion is what a browser says it is, from --version.
var browserVersion = func(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.TempDir()}
	var outb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outb, &outb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("it did not say its version: %v", err)
	}
	v := reBrowserVersion.FindString(outb.String())
	if v == "" {
		return "", fmt.Errorf("it does not say it is a Chromium (%q)", clip(strings.TrimSpace(outb.String()), 80))
	}
	return strings.TrimSpace(v), nil
}

// findBrowsers is every Chromium on this machine, by its program.
func findBrowsers(candidates, launchers, globs []string, pathDirs []string) []foundBrowser {
	seen := map[string]bool{}
	var found []foundBrowser
	add := func(p string) {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return
		}
		if seen[real] {
			return
		}
		fi, err := os.Stat(real)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			return
		}
		seen[real] = true
		f := foundBrowser{Path: real}
		switch {
		case strings.HasPrefix(real, "/snap/"):
			f.Problem = "a snap, which starts through snapd and does not run in the agent box"
		case isScript(real):
			f.Problem = "a script that starts the browser from elsewhere; name the program it starts"
		default:
			if v, err := browserVersion(real); err != nil {
				f.Problem = err.Error()
			} else {
				f.Version = v
			}
		}
		found = append(found, f)
	}
	for _, c := range candidates {
		add(c)
	}
	for _, l := range launchers {
		for _, dir := range pathDirs {
			if p := filepath.Join(dir, l); fileExists(p) {
				add(p)
			}
		}
	}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		sort.Strings(matches)
		for _, m := range matches {
			add(m)
		}
	}
	return found
}

// isScript reports whether a program is a script rather than the browser.
func isScript(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 2)
	n, _ := f.Read(head)
	return n == 2 && string(head) == "#!"
}

// cmdBrowserFind lists the Chromiums on this machine and says how to use
// one.
func cmdBrowserFind(root string) error {
	inUse, _, _ := browserPath(root)
	found := findBrowsers(browserCandidates, browserLaunchers, browserCaches(), filepath.SplitList(os.Getenv("PATH")))
	for i := range found {
		found[i].InUse = found[i].Path == inUse
	}
	if w.Mode == out.JSON {
		w.JSON(map[string]any{"browsers": found, "in_use": inUse})
		return nil
	}
	if len(found) == 0 {
		fmt.Printf("  %sno Chrome or Chromium here; quilzo browser install fetches the pinned Chrome for Testing%s\n", dim, reset)
		return nil
	}
	for _, f := range found {
		switch {
		case f.Problem != "":
			fmt.Printf("  %s%s%s\n    %s%s%s\n", dim, f.Path, reset, yellow, f.Problem, reset)
		case f.InUse:
			fmt.Printf("  %s%s%s  %s\n    %sagents use this one%s\n", bold, f.Version, reset, f.Path, green, reset)
		default:
			fmt.Printf("  %s%s%s  %s\n", bold, f.Version, reset, f.Path)
		}
	}
	fmt.Printf("\n  %sto use one: quilzo config set browser.path PATH --accept-risk \"why\". The pinned build is what this release is\n"+
		"  tested with; another speaks the same DevTools protocol, and may differ in what a newer page needs.%s\n", dim, reset)
	return nil
}
