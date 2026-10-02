// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"regexp"
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

// Every icon is a Material Symbol from assets/icons, drawn by the icon
// function; none is drawn by hand. Hand-drawn ones were the theme switch's
// sun and moon, the search glass, and chevrons made of two borders, and
// they were a different family from everything beside them.
func TestEveryIconIsAMaterialSymbolFromTheIconFiles(t *testing.T) {
	names := regexp.MustCompile(`\{\{icon "([a-z_]+)"\}\}`)
	toneNames := []string{toneIcon("good"), toneIcon("warning"), toneIcon("serious"), toneIcon("critical")}
	entries, err := assets.ReadDir("assets")
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		b, _ := assets.ReadFile("assets/" + e.Name())
		page := string(b)
		if strings.Contains(page, `<svg class="icon"`) {
			t.Errorf("%s draws an icon by hand; use {{icon \"name\"}}", e.Name())
		}
		for _, sum := range regexp.MustCompile(`(?s)<summary[^>]*>.*?</summary>`).FindAllString(page, -1) {
			if !strings.Contains(sum, `class="chev"`) {
				t.Errorf("%s has a disclosure with the browser's triangle: %.60s", e.Name(), sum)
			}
		}
		for _, m := range names.FindAllStringSubmatch(page, -1) {
			used[m[1]] = true
		}
	}
	for _, n := range toneNames {
		used[n] = true
	}
	for n := range used {
		if _, err := uiIcon(n); err != nil {
			t.Error(err)
		}
	}
	css := stylesheet(t)
	if regexp.MustCompile(`content: *"[^"]+"`).MatchString(css) {
		t.Error("the stylesheet draws an icon with a character")
	}
	if regexp.MustCompile(`summary::after \{[^}]*border-(right|bottom)`).MatchString(css) {
		t.Error("a chevron is drawn with borders")
	}
}

// The current screen's icon is the filled symbol, as Material marks the
// selected destination; the others are outlined.
func TestTheCurrentScreenHasTheFilledIcon(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/people", token).Body.String()
	filled, outline := filledFor("people"), iconFor("people")
	if filled == outline {
		t.Fatal("People has no filled symbol to show")
	}
	current := regexp.MustCompile(`<a href="/people" aria-current="page"><svg class="navicon"[^>]*><path d="([^"]+)"`).FindStringSubmatch(body)
	if current == nil || current[1] != filled {
		t.Error("the current screen is not drawn with its filled symbol")
	}
	if strings.Count(body, filled) != 1 {
		t.Error("a screen that is not current is drawn filled")
	}
}
