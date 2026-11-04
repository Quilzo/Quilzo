// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
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
