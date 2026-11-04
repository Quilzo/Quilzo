// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import "fmt"

// The eighth style: neon.
//
// # Why it exists
//
// A games studio's site wanted what the other seven do not offer: a glow on
// the headings and the filled buttons, section titles that run from the text
// colour into the accent, chamfered corners and capital display type. None of
// those were tokens and no style drew them, so the only route was a
// hand-written layout with a <style> block — which worked, and which nobody
// could choose from a screen, and whose colours the contrast check never saw.
//
// It is a style like the others: it sets corners, density and type and takes
// every colour from a token, mixed with color-mix() where it needs to be
// translucent. Its glow is the glow token, so 0 turns it off; its corners are
// the corner choice, which it sets to chamfer and an operator can set back.
//
// # What it does about being readable
//
// A glow is a halo in the accent colour behind the words, which is the one
// effect here that could stand between a reader and the text. So it is drawn
// only on large type, mixed at half strength, and removed wherever a reader
// asked for more contrast or the system forced its own colours.
//
// The gradient titles are text in a colour the pairs table does not hold: a
// mix of on-surface and primary, which in sRGB can be darker than either end.
// checkNeon below samples that mix against the background and holds it to the
// large-text ratio, so the gate's word covers the colour readers actually get.
// Only on the page background: a title on a tinted band keeps its band's own
// checked colour. A browser that cannot clip a background to text keeps the
// plain colour, because color: transparent with nothing behind it is a title
// nobody can see.

// neonCSS is the neon style's component layer. Token references only.
const neonCSS = `
/* style: neon */
h1, h2, .brand { text-transform: uppercase; }
h1, .section-head h2 { letter-spacing: 0.04em; }
.btn { text-transform: uppercase; letter-spacing: 0.08em; font-weight: 800; }
h1 { text-shadow: 0 0 var(--glow, 0px) color-mix(in srgb, var(--primary) 55%, transparent); }
.btn:not(.btn-outlined):not(.btn-quiet):not(.btn-tonal) {
  box-shadow: 0 0 calc(var(--glow, 0px) * 1.25) color-mix(in srgb, var(--primary) 50%, transparent); }
.card, .plan { border-color: color-mix(in srgb, var(--primary) 30%, var(--outline-variant)); }
.card:hover, .plan:hover {
  box-shadow: inset 0 0 0 var(--border) var(--primary),
              0 0 calc(var(--glow, 0px) * 1.5) color-mix(in srgb, var(--primary) 26%, transparent); }
.site-header { border-bottom: var(--border) solid color-mix(in srgb, var(--primary) 40%, transparent); }
@supports ((background-clip: text) or (-webkit-background-clip: text)) {
  .section-head h2 {
    background: linear-gradient(90deg, var(--on-surface), var(--primary));
    -webkit-background-clip: text; background-clip: text; color: transparent;
    filter: drop-shadow(0 0 calc(var(--glow, 0px) * 0.5) color-mix(in srgb, var(--primary) 45%, transparent)); }
  :is(.tone-accent, .tone-primary, .tone-contrast, .tone-raised, .surface-gradient, .surface-media, .hero) .section-head h2 {
    background: none; color: inherit; filter: none; }
}
@media (prefers-contrast: more) {
  h1 { text-shadow: none; }
  .section-head h2 { background: none; color: var(--on-surface); filter: none; }
  .btn, .card:hover, .plan:hover { box-shadow: none; }
}
@media (forced-colors: active) {
  h1 { text-shadow: none; }
  .section-head h2 { background: none; color: CanvasText; filter: none; }
}
`

// cornerCSS is each corner choice's rules.
//
// corner-shape rather than clip-path, which is what the hand-written version
// used and what costs the most: a clip-path cuts everything outside the
// shape, and the focus ring is outside the shape, so a chamfered button lost
// the one thing that says it has the keyboard. corner-shape changes what a
// radius draws — border, shadow and outline follow it — and a browser that
// does not know the property draws the radius it already had.
var cornerCSS = map[string]string{
	"round": "",
	"chamfer": `
/* corner: chamfer */
.btn, .chip, .card, .plan, .metric, .hero, .notice, .side, .table-wrap, .ask-box, .answer,
.tab-list, .faq details, input, select, textarea, .split img, .media-full img, .media-full video,
.carousel img, .gallery img, .card-media img, .hero-media img, .hero-showcase img {
  corner-shape: bevel; }
`,
}

// checkNeon holds the neon style's gradient titles to the large-text ratio.
//
// Five points along the gradient, both ends included. sRGB interpolation is
// not monotonic in luminance, so the ends passing says nothing about the
// middle, and the middle is where a red and a green meet in a brown.
func (t *Theme) checkNeon() []Finding {
	if t.Style() != "neon" {
		return nil
	}
	fg, _ := Lookup("on-surface")
	to, _ := Lookup("primary")
	bg, _ := Lookup("surface")
	var out []Finding
	for _, scheme := range t.checkedSchemes() {
		from, end, ground := t.value(fg, scheme.dark), t.value(to, scheme.dark), t.value(bg, scheme.dark)
		for _, at := range []float64{0, 0.25, 0.5, 0.75, 1} {
			mixed := mixHex(from, end, at)
			ratio := Contrast(mixed, ground)
			if ratio >= 3.0 {
				continue
			}
			out = append(out, Finding{
				Token: "primary", Blocking: true, Scheme: scheme.name,
				Ratio: ratio, Needs: 3.0, Criterion: "WCAG 1.4.3",
				Detail: fmt.Sprintf("the neon style's section titles run from "+
					"on-surface into primary, and %d%% of the way along the colour "+
					"is %.2f:1 against surface in the %s scheme. A title is large "+
					"text and needs 3.0:1. Choose a primary nearer the text colour's "+
					"end of the range, or another style",
					int(at*100), ratio, scheme.name),
			})
			break
		}
	}
	return out
}

// mixHex mixes two hex colours in sRGB, as color-mix(in srgb, a, b) and a
// linear-gradient both do, at a fraction of the way from a to b.
func mixHex(a, b string, at float64) string {
	ar, ag, ab, okA := rgb(a)
	br, bgr, bb, okB := rgb(b)
	if !okA || !okB {
		return ""
	}
	mix := func(x, y float64) int { return int(255*(x+(y-x)*at) + 0.5) }
	return fmt.Sprintf("#%02x%02x%02x", mix(ar, br), mix(ag, bgr), mix(ab, bb))
}
