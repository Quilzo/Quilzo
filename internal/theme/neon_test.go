// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"strings"
	"testing"
)

// Neon is a style like the others: chosen by name, its tokens defaults the
// operator overrides, and its layer in the stylesheet.
func TestNeonIsAStyle(t *testing.T) {
	th, problems := New(map[string]string{"style": "neon"}, nil)
	if Blocks(problems) || Blocks(th.Check()) {
		t.Fatal(problems, th.Check())
	}
	if th.Corner() != "chamfer" || !th.FromStyle("corner") {
		t.Errorf("neon's corners are %s", th.Corner())
	}
	if v, _ := th.Value("glow", false); v != "16px" || !strings.Contains(th.CSS(), "--glow: 16px;") {
		t.Errorf("neon's glow is %q", v)
	}
	p := th.Preset()
	for _, want := range []string{"/* style: neon */", "text-transform: uppercase", "background-clip: text",
		"@media (forced-colors: active)", "@media (prefers-contrast: more)", "corner-shape: bevel"} {
		if !strings.Contains(p, want) {
			t.Errorf("neon lacks %q", want)
		}
	}
	// The operator wins: a neon site may keep round corners and no glow.
	own, _ := New(map[string]string{"style": "neon", "corner": "round", "glow": "0"}, nil)
	if own.Corner() != "round" || strings.Contains(own.Preset(), "corner-shape") || !strings.Contains(own.CSS(), "--glow: 0;") {
		t.Error("the operator's corner or glow lost to the style")
	}
}

// The glow reads its token with the token's own default as the fallback, so
// a site whose style draws no glow and sets none gets none.
func TestTheGlowFallsBackToItsDefault(t *testing.T) {
	glow, _ := Lookup("glow")
	if !strings.Contains(neonCSS, "var(--glow, "+glow.Light+")") {
		t.Errorf("neon's fallback for --glow is not the token's default %s", glow.Light)
	}
	if strings.Contains(neonCSS, "var(--glow)") {
		t.Error("a glow is read with no fallback")
	}
}

// The gradient titles are checked where they meet the background, at every
// point along them, and a primary that makes the middle unreadable is
// refused even though both ends pass.
func TestNeonsGradientTitlesAreChecked(t *testing.T) {
	// A red text colour and a green accent on black: both ends read, and
	// their sRGB midpoint is a dark brown that does not.
	over := map[string]string{"style": "neon", "scheme": "dark",
		"surface": "#000000", "on-surface": "#ff0000", "primary": "#008900",
		"on-primary": "#000000", "on-surface-variant": "#c0c0c0", "surface-container": "#000000",
		"surface-container-high": "#000000", "focus-ring": "#ffffff", "outline": "#808080"}
	th, _ := New(over, nil)
	var found bool
	for _, f := range th.Check() {
		if f.Blocking && strings.Contains(f.Detail, "section titles") {
			found = true
		}
	}
	if Contrast(over["on-surface"], over["surface"]) < 4.5 || Contrast(over["primary"], over["surface"]) < 4.5 {
		t.Fatal("the fixture's ends should pass on their own")
	}
	if !found {
		t.Errorf("an unreadable midpoint passed: %.2f:1", Contrast(mixHex(over["on-surface"], over["primary"], 0.5), "#000000"))
	}
	over["style"] = "glass"
	other, _ := New(over, nil)
	for _, f := range other.Check() {
		if strings.Contains(f.Detail, "section titles") {
			t.Error("a style without gradient titles was checked for them")
		}
	}
}
