// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"strings"
	"testing"
)

// Every screen in the navigation has its icon, and the icons travel with
// the licence they were given under.
func TestEveryDestinationHasAnIconAndTheIconsTheirLicence(t *testing.T) {
	for _, d := range destinations {
		if iconFor(d.Key) == "" {
			t.Errorf("%s (%s) has no icon; fetch the Material Symbol and add it "+
				"to iconSymbol and assets/icons", d.Key, d.Label)
		}
	}
	lic, err := assets.ReadFile("assets/icons/LICENSE")
	if err != nil || !strings.Contains(string(lic), "Apache License") {
		t.Error("the icons are here without the Apache licence they are given under")
	}
	if _, err := assets.ReadFile("assets/icons/README.md"); err != nil {
		t.Error("the icons do not say where they came from")
	}
}

func TestTheMenuDrawsTheIconsAndHidesThemFromScreenReaders(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/", token).Body.String()
	if !strings.Contains(body, `<svg class="navicon" viewBox="0 -960 960 960" aria-hidden="true"`) {
		t.Error("the navigation draws no icons, or announces them")
	}
}

// The typeface is served with its licence beside it, under its own name.
func TestTheTypefaceTravelsWithItsLicenceAndNotUnderGooglesName(t *testing.T) {
	for _, f := range []string{"assets/fonts/quilzo-ui.woff2", "assets/fonts/OFL.txt",
		"assets/fonts/README.md"} {
		if _, err := assets.ReadFile(f); err != nil {
			t.Errorf("%s is missing", f)
		}
	}
	srv, token := setup(t)
	w := get(t, srv, "/fonts/quilzo-ui.woff2", token)
	if w.Code != 200 || w.Header().Get("Content-Type") != "font/woff2" {
		t.Fatalf("the font answered %d as %q", w.Code, w.Header().Get("Content-Type"))
	}
	css := get(t, srv, "/style.css", token).Body.String()
	if !strings.Contains(css, `font-family: "Quilzo UI"`) ||
		strings.Contains(css, `font-family: "Google Sans`) {
		t.Error("the stylesheet does not use the face under its own name")
	}
	csp := get(t, srv, "/", token).Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "font-src 'self'") {
		t.Errorf("the policy does not let the page load its typeface: %s", csp)
	}
}
