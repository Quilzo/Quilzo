// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/render"
)

// Finding STACK-F11. The reference compose gives the site
// --base-url https://DOMAIN:PORT, the port being the one Caddy is published
// on, so the sitemap and canonical links are right on any port; on 443 they
// named :443. The site's address leaves out the scheme's own port.
func TestTheSiteBaseURLLeavesOutTheSchemesOwnPort(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	w = out.New(false)
	root := filepath.Join(t.TempDir(), "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	design := &Design{Layouts: render.OneLayout(`<!doctype html><title>x</title>`)}
	for flag, want := range map[string]string{
		"https://localhost:443":   "https://localhost",
		"https://localhost:18543": "https://localhost:18543",
	} {
		st, err := siteFor(root, design, siteOpts{BaseURL: flag})
		if err != nil {
			t.Fatal(err)
		}
		if st.BaseURL != want {
			t.Errorf("--base-url %s: the site is at %s, want %s", flag, st.BaseURL, want)
		}
	}
}

// An export given the site's address with its scheme's own port names the
// site without it, as the site and site.base_url do (config.SiteBase).
// `quilzo export wxr --base-url https://example.org:443` wrote
// https://example.org:443/... into the channel and every item's link.
func TestAnExportLeavesOutTheSchemesOwnPort(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	w = out.New(false)
	root := filepath.Join(t.TempDir(), "st")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	putDraftPage(t, root, "about-us", map[string]any{"title": "About us"})
	dir := filepath.Join(t.TempDir(), "export")
	if err := cmdExport(root, []string{"wxr", "--to", dir, "--ref", "draft", "--base-url", "https://example.org:443"}); err != nil {
		t.Fatal(err)
	}
	var found bool
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(body), "example.org:443") {
			t.Errorf("%s names the site with :443", strings.TrimPrefix(path, dir))
		}
		found = found || strings.Contains(string(body), "https://example.org/")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("no file of the export names the site at https://example.org/")
	}
}
