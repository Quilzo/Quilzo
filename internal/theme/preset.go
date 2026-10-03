// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package theme

import (
	"sort"
	"strings"
)

// Styles: a whole look in one setting.
//
// # What a style is, and what it is not allowed to be
//
// A style sets the tokens that make a look — corners, density, the type
// scale and stacks, the border — and adds a short layer of component rules
// for what tokens cannot say: a translucent card, a hard offset shadow, a
// rule in place of a box. Every value it sets passes the same checks an
// operator's own does, and an operator's own wins: a style is the defaults
// a site starts from, not a lock.
//
// What it never touches is colour. The palette stays the operator's and the
// contrast gate's, so no style can make a site unreadable, and the
// component rules here take every colour from a token — including the
// translucent ones, mixed from tokens with color-mix().
//
// # The six, and where each comes from
//
//	expressive  Material 3 Expressive (Google, 2025): large and varied
//	            corners, tonal containers, springs, shape that answers touch
//	glass       translucent layers over a soft gradient, as Apple's Liquid
//	            Glass (2025); solid wherever blur is not supported or the
//	            visitor asks for reduced transparency
//	editorial   type first: a serif display face, a long measure, hairline
//	            rules instead of boxes, no shadows
//	bold        heavy type, square corners, thick borders and a hard offset
//	            shadow, the neo-brutalist look of 2025–26
//	soft        large corners, generous space, borderless cards lifted by a
//	            soft shadow
//	business    compact and quiet: small corners, a fine border, a slight
//	            shadow, a gentle type scale
//
// classic is what a site had before styles existed, and the default.

// Styles lists the styles, in the order a screen offers them.
var Styles = []string{"classic", "expressive", "glass", "editorial", "bold", "soft", "business"}

// StyleWords says what each style is, for a screen and `theme styles`.
var StyleWords = map[string]string{
	"classic":    "Quilzo's own: rounded, tonal, calm.",
	"expressive": "Material 3 Expressive: big rounded shapes, tonal colour and springy motion.",
	"glass":      "Translucent layers over a soft gradient, solid where blur is not supported.",
	"editorial":  "Type first: a serif display face, a long measure, rules instead of boxes.",
	"bold":       "Heavy type, square corners, thick borders and hard shadows.",
	"soft":       "Large corners, generous space and cards lifted by soft shadows.",
	"business":   "Compact and quiet: small corners, fine borders, a gentle type scale.",
}

// Motions are how much moves.
var Motions = []string{"subtle", "expressive", "none"}

// presetTokens are the tokens each style sets, before the operator's own.
var presetTokens = map[string]map[string]string{
	"classic": {},
	"expressive": {
		"radius": "28px", "scale": "1.3", "tracking-display": "-0.03em", "density": "1.05",
		"font-display": "geometric",
	},
	"glass": {
		"radius": "22px", "scale": "1.25", "tracking-display": "-0.02em", "density": "1.05",
	},
	"editorial": {
		"radius": "4px", "scale": "1.333", "line": "1.7", "measure": "64ch", "tracking-display": "-0.01em",
		"font-display": "transitional", "density": "1.1",
	},
	"bold": {
		"radius": "0px", "border": "2px", "scale": "1.4", "tracking-display": "-0.04em", "density": "1",
		"font-display": "grotesque",
	},
	"soft": {
		"radius": "24px", "scale": "1.25", "density": "1.15", "font-display": "rounded",
	},
	"business": {
		"radius": "6px", "scale": "1.2", "density": "0.9", "tracking-display": "-0.015em",
	},
}

// presetCSS is each style's component layer. Only token references: every
// colour is a token or a mix of tokens, so the contrast gate's word stands.
var presetCSS = map[string]string{
	"expressive": `
/* style: expressive */
.btn { min-height: 52px; font-size: var(--text-base); }
.btn:active { border-radius: var(--radius-sm); }
.card { border-color: transparent; background: var(--surface-container-low); }
.card:hover { border-radius: calc(var(--radius) * 0.6); }
.hero { border-radius: calc(var(--radius) * 2); }
.hero h1, .section-head h2 { font-weight: 800; }
.chip { border-radius: var(--radius-pill); text-transform: none; letter-spacing: 0; }
.site-header { border-bottom-color: transparent; }
`,
	"glass": `
/* style: glass */
body { background: var(--gradient) fixed, var(--surface); }
.card, .site-header, .plan, .quotes blockquote {
  background: color-mix(in srgb, var(--surface-container-low) 74%, transparent);
  border-color: color-mix(in srgb, var(--outline-variant) 70%, transparent);
  -webkit-backdrop-filter: blur(18px) saturate(1.4);
  backdrop-filter: blur(18px) saturate(1.4);
}
.site-header { background: color-mix(in srgb, var(--surface-container) 72%, transparent); }
.hero { background: color-mix(in srgb, var(--primary-container) 82%, transparent);
  -webkit-backdrop-filter: blur(18px) saturate(1.4); backdrop-filter: blur(18px) saturate(1.4); }
.btn { box-shadow: inset 0 1px 0 color-mix(in srgb, var(--on-primary) 24%, transparent); }
@supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px))) {
  .card, .site-header, .plan, .quotes blockquote { background: var(--surface-container-low); }
  .site-header { background: var(--surface-container); }
  .hero { background: var(--primary-container); }
}
@media (prefers-reduced-transparency: reduce) {
  body { background: var(--surface); }
  .card, .site-header, .plan, .quotes blockquote, .hero { -webkit-backdrop-filter: none; backdrop-filter: none; }
  .card, .plan, .quotes blockquote { background: var(--surface-container-low); }
  .site-header { background: var(--surface-container); }
  .hero { background: var(--primary-container); }
}
`,
	"editorial": `
/* style: editorial */
.card { background: transparent; border: 0; border-top: var(--border) solid var(--outline-variant);
  border-radius: 0; padding-inline: 0; }
.card:hover { border-radius: 0; }
.hero { background: transparent; color: inherit; padding-inline: 0; border-radius: 0;
  border-bottom: var(--border) solid var(--outline-variant); }
.hero h1 { font-weight: 600; }
.btn { border-radius: var(--radius-sm); }
.btn:active { border-radius: var(--radius-sm); }
.chip { background: transparent; border: var(--border) solid var(--outline-variant); color: inherit; }
.site-header { background: var(--surface); }
`,
	"bold": `
/* style: bold */
.card { border: var(--border) solid var(--on-surface); box-shadow: 4px 4px 0 var(--on-surface); }
.card:hover { border-radius: var(--radius); transform: translate(-2px, -2px); box-shadow: 6px 6px 0 var(--on-surface); }
.btn { border-radius: var(--radius); border: var(--border) solid var(--on-surface); box-shadow: 3px 3px 0 var(--on-surface); }
.btn:active { border-radius: var(--radius); transform: translate(3px, 3px); box-shadow: none; }
.hero { border: var(--border) solid var(--on-surface); box-shadow: 6px 6px 0 var(--on-surface); }
h1, h2 { font-weight: 900; }
.chip { border-radius: var(--radius); border: var(--border) solid currentColor; }
.site-header { border-bottom: var(--border) solid var(--on-surface); }
@media (prefers-reduced-motion: reduce) { .card:hover, .btn:active { transform: none; } }
`,
	"soft": `
/* style: soft */
.card { border-color: transparent;
  box-shadow: 0 1px 2px color-mix(in srgb, var(--on-surface) 6%, transparent),
              0 8px 24px color-mix(in srgb, var(--on-surface) 8%, transparent); }
.card:hover { border-radius: var(--radius-xl); }
.hero { box-shadow: 0 12px 32px color-mix(in srgb, var(--on-surface) 10%, transparent); }
.chip { border-radius: var(--radius-pill); text-transform: none; letter-spacing: 0; }
.site-header { border-bottom-color: transparent;
  box-shadow: 0 1px 12px color-mix(in srgb, var(--on-surface) 6%, transparent); }
`,
	"business": `
/* style: business */
.card { box-shadow: 0 1px 2px color-mix(in srgb, var(--on-surface) 8%, transparent); }
.card:hover { border-radius: var(--radius-lg); border-color: var(--outline); }
.btn { border-radius: var(--radius-md); min-height: 44px; }
.btn:active { border-radius: var(--radius-sm); }
.hero { border-radius: var(--radius-lg); }
.chip { border-radius: var(--radius-sm); }
`,
}

// motionCSS is each motion setting's override of the motion tokens. Reduced
// motion, which the component sheet honours whatever is chosen here, still
// wins: this decides how much moves for visitors who have not asked.
var motionCSS = map[string]string{
	"subtle": "",
	"expressive": `
/* motion: expressive */
:root { --dur: 450ms;
  --spring: linear(0, 0.009, 0.035 2.1%, 0.141 4.4%, 0.723 12.9%, 0.938 16.7%, 1.017 19.4%, 1.061 22.2%, 1.078 25.3%,
            1.068 29.3%, 1.017 39.7%, 0.996 46.8%, 0.991 53.6%, 1.001 75.5%, 1); }
`,
	"none": `
/* motion: none */
:root { --dur: 0ms; --spring: linear; }
*, *::before, *::after { transition-duration: 0ms !important; animation-duration: 0ms !important; animation-iteration-count: 1 !important; }
`,
}

// Style is the theme's style, "classic" when none is set.
func (t *Theme) Style() string {
	if t == nil {
		return "classic"
	}
	if v, ok := t.light["style"]; ok && presetTokens[v] != nil {
		return v
	}
	return "classic"
}

// Motion is the theme's motion setting.
func (t *Theme) Motion() string {
	if t == nil {
		return "subtle"
	}
	if v, ok := t.light["motion"]; ok {
		if _, known := motionCSS[v]; known {
			return v
		}
	}
	return "subtle"
}

// Preset is the style's component layer and the motion setting, appended
// after the shared components so they win, and before the arrangement rules.
func (t *Theme) Preset() string {
	return presetCSS[t.Style()] + motionCSS[t.Motion()]
}

// applyStyle fills in what the chosen style sets, wherever the operator has
// not set it themselves.
func (t *Theme) applyStyle() {
	style := t.Style()
	names := make([]string, 0, len(presetTokens[style]))
	for k := range presetTokens[style] {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, own := t.light[name]; own {
			continue
		}
		v := presetTokens[style][name]
		tok, ok := Lookup(name)
		if !ok || t.validate(tok, v) != nil {
			continue
		}
		t.light[name] = v
		t.fromStyle = append(t.fromStyle, name)
	}
}

// FromStyle reports whether a token's value came from the style rather than
// the operator, for a screen saying why a value is what it is.
func (t *Theme) FromStyle(name string) bool {
	if t == nil {
		return false
	}
	for _, n := range t.fromStyle {
		if n == name {
			return true
		}
	}
	return false
}

func choiceOK(name, v string) bool {
	switch name {
	case "style":
		return presetTokens[v] != nil
	case "motion":
		_, ok := motionCSS[v]
		return ok
	}
	return false
}

func choiceList(name string) string {
	switch name {
	case "style":
		return strings.Join(Styles, ", ")
	case "motion":
		return strings.Join(Motions, ", ")
	}
	return ""
}
