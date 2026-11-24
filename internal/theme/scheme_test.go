// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"strings"
	"testing"
)

// A dark site set each colour once and was told twenty-three times that each
// was the same in both schemes. Declared dark, it is told nothing of the kind.
func TestADarkSiteIsNotToldItsColoursMatch(t *testing.T) {
	over := map[string]string{"surface": "#07050d", "on-surface": "#ece6ff", "primary": "#b388ff",
		"on-primary": "#12002b", "on-surface-variant": "#b9acd9", "surface-container": "#150d28",
		"surface-container-high": "#1f1438", "primary-container": "#24104f",
		"on-primary-container": "#f3ecff", "secondary-container": "#341566",
		"on-secondary-container": "#f1e8ff", "tertiary-container": "#00313d",
		"on-tertiary-container": "#a6f4ff", "gradient-from": "#2a0b61", "gradient-to": "#0a0420",
		"outline": "#7f6bb8", "focus-ring": "#22e4ff"}
	both, _ := New(over, nil)
	same := 0
	for _, f := range both.Check() {
		if !f.Blocking && strings.Contains(f.Detail, "same colour in both schemes") {
			same++
		}
	}
	if same == 0 {
		t.Fatal("the advisory this removes was not there to begin with")
	}
	over["scheme"] = "dark"
	dark, problems := New(over, nil)
	if Blocks(problems) {
		t.Fatal(problems)
	}
	for _, f := range dark.Check() {
		if strings.Contains(f.Detail, "same colour in both schemes") {
			t.Errorf("still told: %s", f.Detail)
		}
		if f.Scheme == "light" {
			t.Errorf("a dark site was checked in light: %s", f.Detail)
		}
	}
}

// A dark site is served its dark palette whatever the reader asks for. The
// colour nobody set — here, every semantic one — is its dark default, not the
// light one a reader with a light system would otherwise get on a dark page.
func TestADarkSiteServesOnePaletteToEveryReader(t *testing.T) {
	th, _ := New(map[string]string{"scheme": "dark", "surface": "#07050d"}, nil)
	css := th.CSS()
	positive, _ := Lookup("positive")
	if !strings.Contains(css, "--positive: "+positive.Dark+";") || strings.Contains(css, positive.Light) {
		t.Errorf("the unset colour is not its dark value everywhere:\n%s", css)
	}
	for _, block := range []string{"prefers-color-scheme", `data-theme="light"`} {
		if strings.Contains(css, block) {
			t.Errorf("a one-scheme site still writes the %s block", block)
		}
	}
	if !strings.Contains(th.Preset(), `:root, :root[data-theme="light"], :root[data-theme="dark"] { color-scheme: dark; }`) {
		t.Errorf("the scheme is not declared: %q", th.Preset())
	}
	// What is not a colour is the same in every scheme, and a dark site keeps
	// it: the radius somebody chose, and what the style set.
	own, _ := New(map[string]string{"scheme": "dark", "radius": "3px", "style": "neon"}, nil)
	if c := own.CSS(); !strings.Contains(c, "--radius: 3px;") || !strings.Contains(c, "--glow: 16px;") {
		t.Errorf("a dark site lost a value that is not a colour:\n%s", c)
	}
	light, _ := New(map[string]string{"scheme": "light"}, nil)
	if !strings.Contains(light.Preset(), "color-scheme: light;") || strings.Contains(light.CSS(), "prefers-color-scheme") {
		t.Error("a light site is not drawn in light alone")
	}
	if _, problems := New(map[string]string{"scheme": "dim"}, nil); !Blocks(problems) {
		t.Error("an unknown scheme was accepted")
	}
}

// Both is what every site had, and it writes exactly what it wrote.
func TestBothSchemesIsWhatEverySiteHad(t *testing.T) {
	plain, _ := New(map[string]string{"primary": "#0b4f6c"}, nil)
	both, _ := New(map[string]string{"primary": "#0b4f6c", "scheme": "both"}, nil)
	if plain.CSS() != both.CSS() || plain.Preset() != both.Preset() {
		t.Error("choosing both changed the stylesheet")
	}
}

// A chamfer is a corner-shape, never a clip-path. A clip cuts off whatever
// is outside the shape, and the focus ring is outside the shape.
func TestAChamferKeepsTheFocusRing(t *testing.T) {
	th, problems := New(map[string]string{"corner": "chamfer"}, nil)
	if Blocks(problems) {
		t.Fatal(problems)
	}
	p := th.Preset()
	if !strings.Contains(p, "corner-shape: bevel") || strings.Contains(p, "clip-path") {
		t.Errorf("the chamfer is drawn wrongly:\n%s", p)
	}
	round, _ := New(map[string]string{"corner": "round"}, nil)
	def, _ := New(nil, nil)
	if round.Preset() != def.Preset() {
		t.Error("round is not what a site that chose nothing gets")
	}
	if _, problems := New(map[string]string{"corner": "scalloped"}, nil); !Blocks(problems) {
		t.Error("an unknown corner was accepted")
	}
}
