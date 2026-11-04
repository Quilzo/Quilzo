// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"os"
	"strings"
	"testing"
)

// The layer a real site was built with passes as written.
//
// testdata/arena.css is the <style> block of the hand-made layout the demo
// site used before a style layer existed: a glow, gradient titles, chamfered
// cards and a full-bleed hero, every colour a token. That it passes is the
// claim that the rule refuses what the contrast check cannot see and nothing
// a token-only designer writes.
func TestARealTokenOnlyLayerPasses(t *testing.T) {
	b, err := os.ReadFile("testdata/arena.css")
	if err != nil {
		t.Fatal(err)
	}
	th, _ := New(nil, nil)
	for _, f := range CheckLayer(string(b), th) {
		t.Errorf("%s", f)
	}
}

// Every way of writing a colour the check never sees is refused, and so is
// every way of reaching outside the site.
func TestALayerIsRefusedWhatTheCheckCannotSee(t *testing.T) {
	th, _ := New(nil, nil)
	cases := map[string]string{
		"hex":                 `.card { color: #ff0000; }`,
		"short hex":           `.card { border: 1px solid #fff; }`,
		"rgb":                 `.card { background: rgb(0 0 0 / 50%); }`,
		"hsl in a gradient":   `.hero { background: linear-gradient(hsl(20 50% 50%), var(--surface)); }`,
		"oklch":               `.btn { color: oklch(70% 0.1 200); }`,
		"color()":             `.btn { color: color(display-p3 1 0 0); }`,
		"named":               `.card { box-shadow: 0 0 4px black; }`,
		"named, any case":     `.card { color: RebeccaPurple; }`,
		"system colour":       `.card { color: CanvasText; }`,
		"import":              `@import "/fonts/x.css"; .a { color: var(--primary); }`,
		"font-face":           `@font-face { font-family: X; src: url(/fonts/X.woff2); }`,
		"remote url":          `.hero { background: url(https://example.com/x.png); }`,
		"protocol-relative":   `.hero { background: url(//example.com/x.png); }`,
		"traversal":           `.hero { background: url(/media/../site.css); }`,
		"not an asset id":     `.hero { background: url(/media/picture.png); }`,
		"image-set":           `.hero { background: image-set("/media/x.png" 1x); }`,
		"important":           `* { animation-duration: 10s !important; }`,
		"redefines a token":   `:root { --on-surface: var(--surface); }`,
		"redefines derived":   `:root { --space-4: 0; }`,
		"removes the outline": `a:focus-visible { outline: none; }`,
		"outline width 0":     `.btn:focus { outline-width: 0; }`,
		"escape":              `.a { color: var(--primary); } @\69mport "x";`,
		"angle bracket":       `.a { content: "</style>"; }`,
		"behavior":            `.a { behavior: url(/media/x); }`,
		"expression":          `.a { width: expression(alert(1)); }`,
		"unclosed comment":    `.a { color: var(--primary); } /* left open`,
		"unclosed block":      `.a { color: var(--primary);`,
		"typed attr":          `.a::after { content: attr(data-x url); }`,
		"custom property hex": `:root { --mine: #123456; }`,
		"stray declaration":   `color: var(--primary);`,
		"unreadable pair":     `.box { color: var(--primary); background: var(--primary); }`,
	}
	for name, css := range cases {
		if !Blocks(CheckLayer(css, th)) {
			t.Errorf("%s: %q was accepted", name, css)
		}
	}
	if !Blocks(CheckLayer(strings.Repeat(".a { color: var(--primary); }\n", MaxLayer/20), th)) {
		t.Error("a layer over the size bound was accepted")
	}
}

// What the shipped styles write is what a layer may write.
func TestALayerMayUseWhatTheStylesUse(t *testing.T) {
	th, _ := New(nil, nil)
	for name, css := range map[string]string{
		"tokens and mixes": `.card { background: color-mix(in srgb, var(--surface-container-low) 74%, transparent);
  border-color: color-mix(in srgb, var(--outline-variant) 70%, transparent); }`,
		"keywords":         `.chip { background: transparent; color: currentColor; border-color: inherit; }`,
		"forced colours":   `@media (forced-colors: active) { .card { border: 1px solid CanvasText; } }`,
		"own asset":        `.hero { background: url("/media/` + strings.Repeat("a", 64) + `") center / cover; }`,
		"own font":         `.x { background: url(/fonts/Satoshi-400..700.woff2); }`,
		"nesting":          `.card { color: var(--on-surface); &:hover { color: var(--primary); } }`,
		"keyframes":        `@keyframes drift { from { opacity: 0.4; } to { opacity: 1; } } .a { animation: drift 6s infinite; }`,
		"layer statement":  `@layer site; @layer site { .a { color: var(--primary); } }`,
		"supports":         `@supports (backdrop-filter: blur(1px)) { .card { backdrop-filter: blur(8px); } }`,
		"own property":     `:root { --halo: color-mix(in srgb, var(--primary) 40%, transparent); } h1 { text-shadow: 0 0 1rem var(--halo); }`,
		"string with bang": `.a::after { content: "New!"; }`,
		"readable pair":    `.box { color: var(--on-primary); background: var(--primary); }`,
		"ids in selectors": `#main .card:has(> img) { gap: var(--space-2); }`,
		"a focus ring":     `a:focus-visible { outline: 3px solid var(--focus-ring); outline-offset: 2px; }`,
	} {
		if f := CheckLayer(css, th); Blocks(f) {
			t.Errorf("%s was refused: %v", name, f)
		}
	}
}

// A name nothing defines is said, and does not block: it is a typo, not a
// colour the check cannot see.
func TestALayerReadingAnUnknownPropertyIsTold(t *testing.T) {
	th, _ := New(nil, nil)
	f := CheckLayer(`.a { color: var(--primray); }`, th)
	if Blocks(f) || len(f) != 1 || !strings.Contains(f[0].Detail, "--primray") {
		t.Errorf("findings: %v", f)
	}
}

// A pair is judged in the scheme the site is served in. A rule whose pair is
// unreadable only in light is refused on a site drawn in both and passes on
// one drawn in dark alone, because no reader is served the light one.
func TestALayerPairIsJudgedInTheSchemesServed(t *testing.T) {
	css := `.box { color: var(--on-surface); background: var(--tertiary-container); }`
	over := map[string]string{"on-surface.light": "#f0f0f0", "on-surface.dark": "#f0f0f0",
		"tertiary-container.light": "#ffffff", "tertiary-container.dark": "#101010",
		"surface.light": "#101010", "on-surface-variant.light": "#d0d0d0"}
	both, _ := New(over, nil)
	if !Blocks(CheckLayer(css, both)) {
		t.Error("an unreadable light pair passed on a site drawn in both schemes")
	}
	over["scheme"] = "dark"
	dark, _ := New(over, nil)
	if f := CheckLayer(css, dark); Blocks(f) {
		t.Errorf("a pair readable in the only scheme served was refused: %v", f)
	}
}

// A layer that a browser reads differently from this check is refused.
//
// Each of these passed. A string with a line break in it is, to a browser, a
// broken string that ends at the line break, so whatever follows on the next
// line is a declaration it applies — and to this check it was the inside of
// a string, so a picture from another host, a hex colour, a removed focus
// outline and a redefined token all went through unread. A custom property
// may hold a { } block, which a browser keeps as its value and this check
// read as a rule whose selector nobody looks at. And a control character is
// text a terminal obeys when `theme check` prints the rule back.
func TestALayerABrowserReadsDifferentlyIsRefused(t *testing.T) {
	th, _ := New(nil, nil)
	hidden := "; background: url(https://evil.example/x.png); color: #ff0000; " +
		"outline: none; --on-surface: var(--surface); content: "
	for name, css := range map[string]string{
		"line break in a string":        ".a { content: \"x\n" + hidden + "\"; }",
		"carriage return":               ".a { content: 'x\r" + hidden + "'; }",
		"form feed":                     ".a { content: \"x\f" + hidden + "\"; }",
		"block in a custom value":       ".a { --x: {} url(https://evil.example/a); background-image: var(--x); }",
		"a property that is not a name": ".a { b url(//evil.example/x): 1; }",
		"control character":             ".a::after { content: \"\x1b]0;owned\x07\"; }",
	} {
		if !Blocks(CheckLayer(css, th)) {
			t.Errorf("%s: %q was accepted", name, css)
		}
	}
	// A rule over several lines, and a string that ends on its own line, are
	// what every stylesheet is.
	ok := ".a {\n  content: \"one line\";\n\tcolor: var(--primary);\r\n}\f\n"
	if f := CheckLayer(ok, th); Blocks(f) {
		t.Errorf("an ordinary layer over several lines was refused: %v", f)
	}
}

// System colours are the reader's own palette only where forced colours are
// certainly on. A query that also matches without them — negated, or with a
// second branch — applied the operating system's default colours to every
// reader, unjudged.
func TestSystemColoursOnlyWhereForcedColoursAreCertain(t *testing.T) {
	th, _ := New(nil, nil)
	for _, query := range []string{
		"not (forced-colors: active)",
		"(forced-colors: active), all",
		"(forced-colors: active), (prefers-contrast: more)",
		"(forced-colors: active) or (min-width: 0)",
		"not all and (forced-colors: active)",
	} {
		css := "@media " + query + " { .a { color: CanvasText; background: Canvas; } }"
		if !Blocks(CheckLayer(css, th)) {
			t.Errorf("system colours under @media %s were accepted", query)
		}
	}
	for _, query := range []string{
		"(forced-colors: active)",
		"(forced-colors:active)",
		"screen and (forced-colors: active)",
		"(forced-colors: active) and (min-width: 40rem)",
		"(forced-colors: active), print and (forced-colors: active)",
	} {
		css := "@media " + query + " { .a { color: CanvasText; } }"
		if f := CheckLayer(css, th); Blocks(f) {
			t.Errorf("system colours under @media %s were refused: %v", query, f)
		}
	}
}

// The focus outline is taken away however it is written: a zero width in
// any unit, "none" anywhere in the shorthand, or a custom property of the
// layer's own that says either.
func TestTheFocusOutlineCannotBeTakenAwayAnyWay(t *testing.T) {
	th, _ := New(nil, nil)
	for _, css := range []string{
		"a:focus-visible { outline: 0px solid var(--primary); }",
		"a:focus-visible { outline: solid 0 var(--primary); }",
		"a:focus-visible { outline: 0.0px; }",
		"a:focus-visible { outline-width: 0em; }",
		"a:focus-visible { outline-width: 0rem; }",
		"a:focus-visible { outline: var(--primary) none 2px; }",
		"a:focus-visible { outline: NONE; }",
		":root { --off: none; } a:focus-visible { outline: var(--off); }",
		"a:focus-visible { outline-style: var(--gone); } :root { --gone: none; }",
		":root { --thin: 0px; } a:focus-visible { outline: var(--thin) solid var(--focus-ring); }",
	} {
		if !Blocks(CheckLayer(css, th)) {
			t.Errorf("%q was accepted", css)
		}
	}
	for _, css := range []string{
		"a:focus-visible { outline: 3px solid var(--focus-ring); outline-offset: 0; }",
		"a:focus-visible { outline: 0.2rem dashed currentColor; }",
		":root { --ring: 3px; } a:focus-visible { outline: var(--ring) solid var(--focus-ring); }",
		"a:focus-visible { outline-width: 2px; outline-style: solid; }",
	} {
		if f := CheckLayer(css, th); Blocks(f) {
			t.Errorf("%q was refused: %v", css, f)
		}
	}
}
