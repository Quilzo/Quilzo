// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package theme_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/theme"
)

// The property the generator exists for: a palette from any seed passes the
// gate that would otherwise refuse the publish.
//
// Every hue on the circle, both schemes, checked by the same contrast rules a
// publish is checked by. If this ever fails, somebody's brand colour is a
// colour this program cannot build an accessible theme from — and they will
// find that out at the moment they try to publish.
func TestEveryHueProducesAThemeThatPasses(t *testing.T) {
	for hue := 0; hue < 360; hue += 5 {
		seed := seedAt(hue, 0.62, 0.48)
		t.Run(fmt.Sprintf("hue%03d", hue), func(t *testing.T) {
			overrides, err := theme.Generate(seed)
			if err != nil {
				t.Fatalf("seed %s: %v", seed, err)
			}
			_, findings := theme.New(overrides, nil)
			for _, f := range findings {
				if f.Blocking {
					t.Errorf("seed %s produces a theme that cannot be "+
						"published: %s — %s", seed, f.Token, f.Detail)
				}
			}
		})
	}
}

// Extremes, because the interesting failures are at the ends: a colour that is
// already nearly white has little room to go lighter, and one that is nearly
// black has little room to go darker.
func TestSeedsAtTheExtremesStillWork(t *testing.T) {
	for _, seed := range []string{
		"#000000", "#ffffff", "#7f7f7f", // no chroma at all
		"#ff0000", "#00ff00", "#0000ff", // fully saturated
		"#fffbe6", "#0a0a14", // nearly white, nearly black
		"#123", // the three-digit form
	} {
		overrides, err := theme.Generate(seed)
		if err != nil {
			t.Errorf("%s: %v", seed, err)
			continue
		}
		_, findings := theme.New(overrides, nil)
		if theme.Blocks(findings) {
			for _, f := range findings {
				if f.Blocking {
					t.Errorf("%s: %s — %s", seed, f.Token, f.Detail)
				}
			}
		}
	}
}

// The same seed twice is the same palette. A theme that differed between runs
// would make every rebuild look like somebody had edited the design.
func TestGeneratingIsDeterministic(t *testing.T) {
	first, err := theme.Generate("#3b6ea5")
	if err != nil {
		t.Fatal(err)
	}
	second, err := theme.Generate("#3b6ea5")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("%d tokens then %d", len(first), len(second))
	}
	for k, v := range first {
		if second[k] != v {
			t.Errorf("%s is %s then %s", k, v, second[k])
		}
	}
}

// Both schemes are produced. A generator that filled in light and left dark on
// the defaults would pass its own contrast checks and give a reader who
// prefers dark somebody else's palette.
func TestBothSchemesAreGenerated(t *testing.T) {
	overrides, err := theme.Generate("#3b6ea5")
	if err != nil {
		t.Fatal(err)
	}
	light, dark := 0, 0
	for k := range overrides {
		if strings.HasSuffix(k, ".light") {
			light++
		}
		if strings.HasSuffix(k, ".dark") {
			dark++
		}
	}
	if light == 0 || light != dark {
		t.Errorf("%d light tokens and %d dark ones", light, dark)
	}
}

// A colour nobody can read is refused rather than silently becoming black.
func TestAnUnreadableSeedIsRefused(t *testing.T) {
	for _, bad := range []string{"", "blue", "#12345", "rgb(1,2,3)", "#gggggg"} {
		if _, err := theme.Generate(bad); err == nil {
			t.Errorf("%q was accepted as a colour", bad)
		}
	}
}

// The seed's hue survives into the palette. A generator that produced a
// perfectly accessible theme unrelated to what somebody asked for would be
// answering a different question.
func TestTheSeedsHueSurvives(t *testing.T) {
	overrides, err := theme.Generate("#c0392b") // a red
	if err != nil {
		t.Fatal(err)
	}
	primary := overrides["primary.light"]
	if primary == "" {
		t.Fatal("no primary was generated")
	}
	// Red channel dominant, which is the weakest true statement about a red.
	r, g, b := channels(t, primary)
	if r <= g || r <= b {
		t.Errorf("a red seed produced primary %s, which is not red", primary)
	}
}

func seedAt(hue int, s, l float64) string {
	return theme.HexFromHSL(float64(hue), s, l)
}

func channels(t *testing.T, hex string) (int, int, int) {
	t.Helper()
	var r, g, b int
	if _, err := fmt.Sscanf(strings.TrimPrefix(hex, "#"), "%02x%02x%02x",
		&r, &g, &b); err != nil {
		t.Fatalf("%s: %v", hex, err)
	}
	return r, g, b
}

// Every scheme at every contrast level, round the circle, passes the gate,
// and the higher levels reach their ratios: a choice on a screen must never
// be a way to an unpublishable theme or a promise the colours do not keep.
func TestEverySchemeAndContrastLevelPasses(t *testing.T) {
	want := map[string]float64{"standard": 4.5, "medium": 6, "high": 7}
	for _, scheme := range theme.Schemes {
		for _, level := range theme.ContrastLevels {
			for hue := 0; hue < 360; hue += 30 {
				seed := seedAt(hue, 0.62, 0.48)
				out, err := theme.GenerateWith(seed, theme.Options{Scheme: scheme, Contrast: level})
				if err != nil {
					t.Fatalf("%s %s %s: %v", scheme, level, seed, err)
				}
				th, findings := theme.New(out, nil)
				if theme.Blocks(findings) {
					t.Fatalf("%s %s %s cannot be published: %v", scheme, level, seed, findings)
				}
				for _, dark := range []bool{false, true} {
					fg, _ := th.Value("on-surface", dark)
					bg, _ := th.Value("surface", dark)
					link, _ := th.Value("primary", dark)
					if c := theme.Contrast(fg, bg); c < want[level] {
						t.Errorf("%s %s %s dark=%v: body text at %.2f:1, want %.1f", scheme, level, seed, dark, c, want[level])
					}
					if c := theme.Contrast(link, bg); c < want[level] {
						t.Errorf("%s %s %s dark=%v: links at %.2f:1, want %.1f", scheme, level, seed, dark, c, want[level])
					}
				}
			}
		}
	}
}

func TestMonochromeHasNoHueAndUnknownOptionsAreRefused(t *testing.T) {
	out, err := theme.GenerateWith("#0b57d0", theme.Options{Scheme: "monochrome"})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range out {
		if len(v) == 7 && !(v[1:3] == v[3:5] && v[3:5] == v[5:7]) {
			t.Errorf("monochrome %s is %s, which has a hue", k, v)
		}
	}
	if _, err := theme.GenerateWith("#0b57d0", theme.Options{Scheme: "rainbow"}); err == nil {
		t.Error("an unknown scheme was accepted")
	}
	if _, err := theme.GenerateWith("#0b57d0", theme.Options{Contrast: "extreme"}); err == nil {
		t.Error("an unknown contrast level was accepted")
	}
}
