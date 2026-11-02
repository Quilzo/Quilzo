// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package seo

import "testing"

// A page's canonical address is the one it copies when it names a usable
// one, its own otherwise; a page left out of results, or a copy of one
// elsewhere, is not in the sitemap.
func TestAPageSaysWhereItLives(t *testing.T) {
	const base = "https://shop.example/"
	if got := Canonical(base, "about", "index", map[string]any{}); got != "https://shop.example/about" {
		t.Fatal(got)
	}
	if got := Canonical(base, "index", "index", nil); got != "https://shop.example/" {
		t.Fatal(got)
	}
	if got := Canonical("", "about", "index", nil); got != "" {
		t.Fatal(got)
	}
	copied := map[string]any{"canonical": "https://medium.example/p/first"}
	if got := Canonical(base, "post", "index", copied); got != "https://medium.example/p/first" {
		t.Fatal(got)
	}
	for _, bad := range []string{"javascript:alert(1)", "/relative", "https://user:pw@x.example/", "ftp://x.example/", " "} {
		if _, ok := CanonicalOf(map[string]any{"canonical": bad}); ok {
			t.Errorf("%q taken", bad)
		}
	}
	if InSitemap(base, "post", "index", copied) {
		t.Error("a copy of a page elsewhere is in the sitemap")
	}
	if InSitemap(base, "thanks", "index", map[string]any{"noindex": true}) {
		t.Error("a page left out of results is in the sitemap")
	}
	if !InSitemap(base, "about", "index", map[string]any{"canonical": "https://shop.example/about"}) {
		t.Error("a page naming itself is not in the sitemap")
	}
}
