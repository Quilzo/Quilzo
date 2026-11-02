// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package seo

import "testing"

// A missing address is matched to the page it most likely meant, and to
// none when nothing is close.
func TestTheLikelyPageIsSuggested(t *testing.T) {
	pages := []string{"index", "about", "shop/fountain-pens", "returns", "blog/how-we-make-paper"}
	for missing, want := range map[string]string{
		"/about.html":                "about",
		"/abuot":                     "about",
		"/products/fountain-pens":    "shop/fountain-pens",
		"/2019/05/how-we-make-paper": "blog/how-we-make-paper",
		"/return":                    "returns",
	} {
		if got, ok := Suggest(missing, pages); !ok || got != want {
			t.Errorf("%s: %q %v", missing, got, ok)
		}
	}
	for _, missing := range []string{"/wp-login.php", "/careers", "/"} {
		if got, ok := Suggest(missing, pages); ok {
			t.Errorf("%s suggested %q", missing, got)
		}
	}
}
