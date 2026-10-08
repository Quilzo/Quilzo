// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package theme

import (
	"regexp"
	"strings"
	"testing"
)

// A style sets its tokens wherever the operator has not; the operator's own
// value wins; and an unknown style is refused like any bad value.
func TestAStyleSetsDefaultsAndTheOperatorWins(t *testing.T) {
	th, problems := New(map[string]string{"style": "bold"}, nil)
	if Blocks(problems) {
		t.Fatal(problems)
	}
	if v, _ := th.Value("radius", false); v != "0px" || !th.FromStyle("radius") {
		t.Errorf("bold's radius is %q", v)
	}
	th, _ = New(map[string]string{"style": "bold", "radius": "12px"}, nil)
	if v, _ := th.Value("radius", false); v != "12px" || th.FromStyle("radius") {
		t.Errorf("the operator's radius lost to the style: %q", v)
	}
	if _, problems := New(map[string]string{"style": "rainbow"}, nil); !Blocks(problems) {
		t.Error("an unknown style was accepted")
	}
	if _, problems := New(map[string]string{"motion": "wild"}, nil); !Blocks(problems) {
		t.Error("an unknown motion was accepted")
	}
}

// Every style, with the shipped palette, passes the checks a publish runs,
// and its layer is in the stylesheet.
func TestEveryStylePassesAndIsServed(t *testing.T) {
	for _, style := range Styles {
		th, problems := New(map[string]string{"style": style}, nil)
		if Blocks(problems) {
			t.Fatalf("%s: %v", style, problems)
		}
		if f := th.Check(); Blocks(f) {
			t.Errorf("%s fails the contrast checks: %v", style, f)
		}
		if style != "classic" && !strings.Contains(th.Preset(), "/* style: "+style+" */") {
			t.Errorf("%s's layer is not in the preset", style)
		}
		if strings.Contains(th.CSS(), "--style") {
			t.Errorf("the style leaked into the tokens as a property")
		}
	}
}

// The layers take every colour from a token. A literal colour in one would
// be a colour the contrast gate never sees.
func TestNoStyleCarriesAColourOfItsOwn(t *testing.T) {
	literal := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(|\boklch\(|\b(?:white|black|red|blue|green|gray|grey)\b`)
	for name, css := range presetCSS {
		if m := literal.FindString(css); m != "" {
			t.Errorf("%s carries %q", name, m)
		}
	}
}

// Glass stays readable where blur is not supported and for a visitor who
// asks for less transparency.
func TestGlassHasItsFallbacks(t *testing.T) {
	g := presetCSS["glass"]
	for _, want := range []string{"@supports not", "prefers-reduced-transparency: reduce", "-webkit-backdrop-filter"} {
		if !strings.Contains(g, want) {
			t.Errorf("glass lacks %q", want)
		}
	}
}

func TestMotionCanBeTurnedOff(t *testing.T) {
	th, _ := New(map[string]string{"motion": "none"}, nil)
	if !strings.Contains(th.Preset(), "--dur: 0ms") {
		t.Error("motion none leaves things moving")
	}
	th, _ = New(nil, nil)
	if th.Motion() != "subtle" || th.Style() != "classic" || th.Preset() != "" {
		t.Errorf("defaults: %s %s %q", th.Style(), th.Motion(), th.Preset())
	}
}

func TestTheThemeExportsForTailwind(t *testing.T) {
	th, _ := New(map[string]string{"primary": "#0b57d0", "primary.dark": "#a8c7fa", "radius": "20px"}, nil)
	css := Tailwind(th)
	for _, want := range []string{"@theme {", "--color-primary: #0b57d0;", "--radius-lg: 20px;", "--radius-sm: 5px;",
		"@media (prefers-color-scheme: dark)", "--color-primary: #a8c7fa;", "--font-sans:", "--spacing: 0.25rem;"} {
		if !strings.Contains(css, want) {
			t.Errorf("missing %q in\n%s", want, css)
		}
	}
}
