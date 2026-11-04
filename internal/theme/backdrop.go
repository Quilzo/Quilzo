// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package theme

import (
	"fmt"
	"strconv"
	"strings"
)

// Words over a picture, and the arithmetic that keeps them readable.
//
// # The problem
//
// Text over a backdrop picture or video cannot be checked the way every
// other pair here is checked, because one of the two colours is a picture: a
// frame of a recording has every colour in it somewhere, and the one behind
// the word "Tickets" is not known until the frame is. A layout that put words
// straight onto one was a layout this gate could say nothing about, which is
// how a hand-made hero ended up with a gradient scrim that was strong at the
// bottom left and nothing at all behind half its heading.
//
// # The answer
//
// A veil of one colour, at one strength, between the picture and the words —
// and then the worst case, which is computable. Whatever the picture, the
// colour a reader sees behind a word is the veil mixed with something between
// black and white, so the darkest it can be is the veil over black and the
// lightest the veil over white. The text is checked against both ends, and a
// text colour whose own luminance falls between them is a pair some picture
// makes invisible: refused, with the strength that would fix it named.
//
// The veil is uniform for that reason. A gradient from strong to clear is
// prettier and is unreadable somewhere along it by construction.

// backdropPairs are what sits directly on a backdrop's veil: the words, and
// the ring that shows where the keyboard is. Links on a veil take the text
// colour (see the components), so they are the words.
var backdropPairs = []Pair{
	{"on-surface", "scrim", 4.5, "the words over a backdrop picture or video", "WCAG 1.4.3"},
	{"focus-ring", "scrim", 3.0, "the focus ring over a backdrop picture or video", "WCAG 2.4.11"},
}

// CheckBackdrop reports what would be unreadable over a backdrop, whatever
// picture or video is behind it.
//
// Separate from Check, because it applies only where a page has a backdrop:
// a site that never uses one must not have its palette refused over a veil
// it never draws. The publish gate runs this for every page that has one.
func (t *Theme) CheckBackdrop() []Finding {
	strength, ok := t.scrimStrength()
	var out []Finding
	if !ok {
		return []Finding{{Token: "scrim-strength", Blocking: true, Criterion: "WCAG 1.4.3",
			Detail: "the veil's strength cannot be read, so nothing over a backdrop can be checked"}}
	}
	for _, scheme := range t.checkedSchemes() {
		veil := t.value(lookupOrZero("scrim"), scheme.dark)
		for _, p := range backdropPairs {
			fg := t.value(lookupOrZero(p.Foreground), scheme.dark)
			ratio := WorstOver(fg, veil, strength)
			if ratio >= p.Min {
				continue
			}
			out = append(out, Finding{
				Token: "scrim", Blocking: true, Scheme: scheme.name,
				Ratio: ratio, Needs: p.Min, Criterion: p.Criterion,
				Detail: fmt.Sprintf("%s over a backdrop is %.2f:1 at worst in the %s "+
					"scheme — the veil (%s at %s) over the picture least like it — and "+
					"needs %.1f:1. This is %s. Strengthen the veil with "+
					"`quilzo theme set scrim-strength 90%%`, or give it a colour further "+
					"from the text", p.Foreground, ratio, scheme.name, veil,
					t.valueOf("scrim-strength"), p.Min, p.What),
			})
		}
	}
	return out
}

// WorstOver is the lowest contrast a text colour can have against a veil of
// one colour at a strength between 0 and 1, laid over any picture at all.
//
// Browsers blend in sRGB, so a pixel under the veil is veil*strength plus the
// picture's own value times what is left. Each channel of that lies between
// veil*strength and veil*strength plus the rest, so its luminance lies
// between those of the two corners — the veil over black and over white —
// and the contrast is least at the end nearer the text, or 1 where the text's
// own luminance falls between them.
func WorstOver(text, veil string, strength float64) float64 {
	vr, vg, vb, okV := rgb(veil)
	lt, okT := luminance(text)
	if !okV || !okT || strength < 0 || strength > 1 {
		return 0
	}
	lum := func(r, g, b float64) float64 {
		return 0.2126*linear(r) + 0.7152*linear(g) + 0.0722*linear(b)
	}
	lo := lum(vr*strength, vg*strength, vb*strength)
	rest := 1 - strength
	hi := lum(vr*strength+rest, vg*strength+rest, vb*strength+rest)
	switch {
	case lt >= lo && lt <= hi:
		return 1
	case lt > hi:
		return (lt + 0.05) / (hi + 0.05)
	default:
		return (lo + 0.05) / (lt + 0.05)
	}
}

// scrimStrength is the veil's strength as a fraction.
func (t *Theme) scrimStrength() (float64, bool) {
	v := strings.TrimSuffix(t.valueOf("scrim-strength"), "%")
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || n < 0 || n > 100 {
		return 0, false
	}
	return n / 100, true
}

func lookupOrZero(name string) Token {
	tok, _ := Lookup(name)
	return tok
}
