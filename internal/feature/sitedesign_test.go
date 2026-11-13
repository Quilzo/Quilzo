// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"encoding/json"
	"strings"
	"testing"
)

// A site package says how it looks with everything the theme offers: the
// neon style, a scheme, a corner and a style layer, each checked as the
// theme checks it and each said on the card.
func TestASitePackageCarriesTheWholeLook(t *testing.T) {
	layer := ".hero h1 { text-shadow: 0 0 1rem color-mix(in srgb, var(--primary) 40%, transparent); }"
	p := withSite(Site{Name: "Nyxvale", Style: "neon", Colour: "#7c3aed", Scheme: "dark", Corner: "chamfer", Layer: layer})
	if err := p.Validate(Checks{}); err != nil {
		t.Fatal(err)
	}
	look, err := p.Site.Look()
	if err != nil || look["scheme"] != "dark" || look["corner"] != "chamfer" || look["style"] != "neon" {
		t.Fatalf("the look is %v, %v", look, err)
	}
	text := p.MakeCard().Shows[0].Text
	for _, want := range []string{"the neon style", "drawn in dark alone", "chamfer corners", "a style layer of its own"} {
		if !strings.Contains(text, want) {
			t.Errorf("the card does not say %q: %s", want, text)
		}
	}
	for name, bad := range map[string]Site{
		"no such scheme":   {Name: "B", Scheme: "dusk"},
		"no such corner":   {Name: "B", Corner: "scalloped"},
		"a hex in a layer": {Name: "B", Layer: ".a { color: #ff0000; }"},
		"an import":        {Name: "B", Layer: `@import "/fonts/x.css";`},
		"a remote picture": {Name: "B", Layer: ".hero { background: url(https://example.com/x.png); }"},
	} {
		if err := withSite(bad).Validate(Checks{}); err == nil || !strings.Contains(err.Error(), "site:") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A package written before any of this has the same bytes and the same look.
func TestAnOlderSiteBlockIsUnchanged(t *testing.T) {
	old := Site{Name: "Hart's Bakery", Style: "soft", Colour: "#c2410c", Motion: "subtle"}
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"scheme", "corner", "layer"} {
		if strings.Contains(string(b), `"`+key+`"`) {
			t.Errorf("a site block that sets no %s writes one: %s", key, b)
		}
	}
	look, _ := old.Look()
	if _, has := look["scheme"]; has {
		t.Error("a site block with no scheme sets one")
	}
}

// The builder takes a scheme from the person, and never a layer from a
// model: a model's CSS is left out and said to be.
func TestTheBuilderTakesASchemeAndNoLayer(t *testing.T) {
	brief := SiteBrief{Description: "A games studio", Name: "Nyxvale", Style: "neon", Scheme: "dark"}
	start, err := BuildSite(brief, "dana", buildTime)
	if err != nil {
		t.Fatal(err)
	}
	if start.Site.Scheme != "dark" || start.Site.Style != "neon" {
		t.Fatalf("the start is %+v", start.Site)
	}
	if _, err := BuildSite(SiteBrief{Description: "x", Name: "x", Scheme: "dusk"}, "dana", buildTime); err == nil {
		t.Error("an unknown scheme was built")
	}
	answer := `{"format": 1, "name": "nyxvale", "version": "1", "title": "Nyxvale", "purpose": "A studio.",
		"site": {"name": "Nyxvale", "style": "neon", "scheme": "dusk", "corner": "wavy",
			"layer": ".notice { display: none; }"},
		"pages": [{"name": "index", "body": {"title": "Nyxvale"}}]}`
	p, notes, err := ReadSiteDraft(answer, SiteBrief{Description: "A games studio", Name: "Nyxvale"}, start, "dana", "m", buildTime)
	if err != nil {
		t.Fatal(err)
	}
	if p.Site.Layer != "" || p.Site.Scheme != "dark" || p.Site.Corner != "" {
		t.Errorf("the drafted site is %+v", p.Site)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "style layer") {
		t.Errorf("leaving the model's layer out was not said: %v", notes)
	}
	if !strings.Contains(SitePrompt(nil), "neon") || !strings.Contains(SitePrompt(nil), "Write no layer") {
		t.Error("the prompt does not offer neon, or does not say to write no layer")
	}
}
