// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package theme

import (
	"fmt"
	"strconv"
	"strings"
)

// Tailwind is the theme as a Tailwind CSS v4 stylesheet, for a team that
// builds part of the product elsewhere and wants it to look like the site.
//
// Tailwind v4 keeps its design tokens in CSS, in an @theme block, as custom
// properties under fixed namespaces: --color-*, --font-*, --radius-*,
// --text-*, --spacing, --container-*. So the export is the same values this
// site serves, renamed into those namespaces, with the dark scheme as the
// same properties redefined under prefers-color-scheme. Nothing is computed
// that the site does not compute; the radii are the same fractions of one
// radius that the site's own stylesheet derives.
func Tailwind(t *Theme) string {
	var b strings.Builder
	b.WriteString("/* This site's theme, exported for Tailwind CSS v4.\n" +
		"   Use it after @import \"tailwindcss\"; every colour has a dark value below. */\n@theme {\n")
	for _, tok := range tokens {
		if tok.Kind == Colour {
			fmt.Fprintf(&b, "  --color-%s: %s;\n", tok.Name, t.value(tok, false))
		}
	}
	for _, f := range []struct{ tw, name string }{{"sans", "font-body"}, {"display", "font-display"}, {"mono", "font-mono"}} {
		tok, _ := Lookup(f.name)
		fmt.Fprintf(&b, "  --font-%s: %s;\n", f.tw, t.cssValue(tok, false))
	}
	if r, unit, ok := splitLength(t.valueOf("radius")); ok {
		if n, err := strconv.ParseFloat(r, 64); err == nil {
			for _, step := range []struct {
				name string
				x    float64
			}{{"sm", 0.25}, {"md", 0.5}, {"lg", 1}, {"xl", 1.75}} {
				fmt.Fprintf(&b, "  --radius-%s: %s%s;\n", step.name, trimF(n*step.x), unit)
			}
		}
	}
	fmt.Fprintf(&b, "  --radius-full: %s;\n", t.valueOf("radius-pill"))
	fmt.Fprintf(&b, "  --text-base: %s;\n", t.valueOf("text-base"))
	if d, err := strconv.ParseFloat(t.valueOf("density"), 64); err == nil {
		fmt.Fprintf(&b, "  --spacing: %srem;\n", trimF(0.25*d))
	}
	fmt.Fprintf(&b, "  --container-page: %s;\n", t.valueOf("page-width"))
	fmt.Fprintf(&b, "  --container-prose: %s;\n", t.valueOf("measure"))
	b.WriteString("}\n\n@media (prefers-color-scheme: dark) {\n  :root {\n")
	for _, tok := range tokens {
		if tok.Kind == Colour {
			fmt.Fprintf(&b, "    --color-%s: %s;\n", tok.Name, t.value(tok, true))
		}
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// valueOf is one token's light value, by name.
func (t *Theme) valueOf(name string) string {
	tok, ok := Lookup(name)
	if !ok {
		return ""
	}
	return t.value(tok, false)
}
