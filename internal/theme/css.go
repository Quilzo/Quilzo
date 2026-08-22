package theme

import (
	"fmt"
	"sort"
	"strings"
)

// CSS is the custom-property block a themed site is served.
//
// # Why three blocks and not two
//
// A reader has three states, not two. An explicit choice stamps
// data-theme="dark" or data-theme="light" on the root element; the default
// setting stamps nothing, and in that state only prefers-color-scheme separates
// one from the other. So the light palette is declared on bare :root, the dark
// palette is declared again under the media query — guarded so an explicit light
// choice beats a dark operating system — and once more under the explicit
// attribute so the choice wins in both directions.
//
// A token whose only definition sits inside a media query is the classic version
// of this bug: the page renders one scheme's text on the other scheme's ground
// for every reader who never touched the setting. Emitting all three from one
// list is how that stops being possible to get wrong.
//
// # Why derived values are computed in CSS rather than here
//
// The heading sizes come from text-base and scale, and the gaps come from
// density. Both could be multiplied out in Go and written as literals. They are
// not, because calc() keeps the relationship visible in the served stylesheet:
// an operator reading it can see that h2 is two steps up the scale, and a
// browser recomputes it when the reader changes their default font size. A
// literal would silently stop respecting that.
func (t *Theme) CSS() string {
	var b strings.Builder

	b.WriteString("/* Generated from this site's theme. Every value here is a\n")
	b.WriteString(" * token an operator set or a default this release shipped;\n")
	b.WriteString(" * the component rules below are not editable, because they\n")
	b.WriteString(" * are where the accessibility work lives. */\n")

	t.fontFaces(&b)

	b.WriteString(":root {\n")
	t.writeTokens(&b, false)
	b.WriteString(t.derived())
	b.WriteString("}\n")

	b.WriteString("@media (prefers-color-scheme: dark) {\n")
	b.WriteString("  :root:not([data-theme=\"light\"]) {\n")
	t.writeColours(&b, true, "    ")
	b.WriteString("  }\n}\n")

	b.WriteString(":root[data-theme=\"dark\"] {\n")
	t.writeColours(&b, true, "  ")
	b.WriteString("}\n")

	b.WriteString(":root[data-theme=\"light\"] {\n")
	t.writeColours(&b, false, "  ")
	b.WriteString("}\n")

	return b.String()
}

// fontFaces declares the faces this site serves itself.
//
// Self-hosted or nothing. A page that reaches another origin for a font has
// given that origin a request on every visit, a record of every reader, and the
// ability to stall the first paint — and the CSP cannot help, because the page
// asked for it. font-display: swap so a slow font is a restyle rather than
// invisible text.
func (t *Theme) fontFaces(b *strings.Builder) {
	if len(t.families) == 0 {
		return
	}
	families := make([]Family, len(t.families))
	copy(families, t.families)
	sort.Slice(families, func(i, j int) bool {
		if families[i].Name != families[j].Name {
			return families[i].Name < families[j].Name
		}
		return families[i].Style < families[j].Style
	})
	for _, f := range families {
		weight := f.Weight
		if weight == "" {
			weight = "100 900"
		}
		style := f.Style
		if style == "" {
			style = "normal"
		}
		fmt.Fprintf(b, "@font-face {\n"+
			"  font-family: %q;\n"+
			"  src: url(%q) format(\"woff2\");\n"+
			"  font-weight: %s;\n"+
			"  font-style: %s;\n"+
			"  font-display: swap;\n"+
			"}\n", f.Name, f.Href, weight, style)
	}
}

// writeTokens emits every token for the light scheme, colours included.
func (t *Theme) writeTokens(b *strings.Builder, dark bool) {
	for _, tok := range tokens {
		fmt.Fprintf(b, "  --%s: %s;\n", tok.Name, t.cssValue(tok, dark))
	}
}

// writeColours emits only the tokens that differ between schemes.
//
// Only the colours, because redeclaring the radius inside a dark block would be
// three copies of a value that cannot differ — and three copies is how one of
// them ends up stale.
func (t *Theme) writeColours(b *strings.Builder, dark bool, indent string) {
	for _, tok := range tokens {
		if tok.Kind != Colour {
			continue
		}
		fmt.Fprintf(b, "%s--%s: %s;\n", indent, tok.Name, t.cssValue(tok, dark))
	}
}

// cssValue renders a token's value as CSS. A font stack name becomes the stack.
func (t *Theme) cssValue(tok Token, dark bool) string {
	v := t.value(tok, dark)
	if tok.Kind != FontStack {
		return v
	}
	if stack, built := stacks[v]; built {
		return stack
	}
	// A self-hosted family, with a stack behind it. The fallback is not
	// decoration: the font is a separate request that can fail, and a page whose
	// text is invisible until it arrives is a page that failed to load.
	return fmt.Sprintf("%q, %s", v, stacks["system"])
}

// derived is the values computed from the tokens above.
//
// The type scale is the interesting one. Each step multiplies by --scale, so
// setting scale to 1.2 produces a gentle hierarchy and 1.333 a dramatic one,
// from one number. Written as repeated multiplication rather than pow(), which
// is not yet something every browser in use can do.
func (t *Theme) derived() string {
	return `
  /* Type scale: each step is one --scale multiple up from --text-base. */
  --text-sm:  calc(var(--text-base) / var(--scale));
  --text-lg:  calc(var(--text-base) * var(--scale));
  --text-xl:  calc(var(--text-base) * var(--scale) * var(--scale));
  --text-2xl: calc(var(--text-base) * var(--scale) * var(--scale) * var(--scale));
  --text-3xl: calc(var(--text-base) * var(--scale) * var(--scale) * var(--scale) * var(--scale));

  /* Spacing: one ladder, multiplied by --density, so compact and airy are
     one number rather than forty edits. */
  --space-1: calc(0.25rem * var(--density));
  --space-2: calc(0.5rem  * var(--density));
  --space-3: calc(0.75rem * var(--density));
  --space-4: calc(1rem    * var(--density));
  --space-5: calc(1.5rem  * var(--density));
  --space-6: calc(2rem    * var(--density));
  --space-7: calc(3rem    * var(--density));
  --space-8: calc(4.5rem  * var(--density));

  /* Radii derived from one --radius, so a square design is one setting. */
  --radius-sm: calc(var(--radius) / 4);
  --radius-md: calc(var(--radius) / 2);
  --radius-lg: var(--radius);
  --radius-xl: calc(var(--radius) * 1.75);

  /* The gradient, assembled from its two stops so the stops stay ordinary
     colours the contrast check can reach. */
  --gradient: linear-gradient(calc(var(--gradient-angle) * 1deg),
              var(--gradient-from), var(--gradient-to));

  /* Motion. Both are overridden wholesale by the reduced-motion block in the
     component stylesheet, so a spring that overshoots is still an opt-in. */
  --ease: cubic-bezier(0.2, 0, 0, 1);
  --spring: linear(0, 0.19 5%, 0.44 11%, 0.71 18%, 0.92 25%, 1.05 32%,
            1.08 39%, 1.03 50%, 0.99 66%, 1);
  --dur: 300ms;
`
}

// Responsive is the part of the design that cannot be a custom property.
//
// A container query is evaluated before the cascade, so `@container (min-width:
// var(--break-md))` does not work and will not start working. That is the whole
// reason this function exists: the queries are written out with this site's
// numbers substituted, which is the only way a breakpoint becomes something an
// operator can change.
//
// It is appended after the components so these declarations win, and it is the
// only place in the served stylesheet where a value is baked in rather than
// referenced — so it is small on purpose, and it holds arrangement only. A
// colour in here would be a colour the contrast check cannot see.
func (t *Theme) Responsive() string {
	sm := t.lengthOf("break-sm")
	md := t.lengthOf("break-md")
	lg := t.lengthOf("break-lg")

	var b strings.Builder
	b.WriteString("\n/* Arrangement at each breakpoint, generated from this " +
		"site's break-sm,\n * break-md and break-lg. Container queries cannot " +
		"read a custom property,\n * so these are the numbers rather than a " +
		"reference to them. */\n")

	// The bento's lead cell claims two columns once there is room for two.
	fmt.Fprintf(&b, "@container (min-width: %s) {\n"+
		"  .grid-bento > :first-child { grid-column: span 2; grid-row: span 2; }\n"+
		"}\n", sm)

	// A split, a hero with an image and a record's detail all become two
	// columns at the same point, because they are the same shape.
	fmt.Fprintf(&b, "@container (min-width: %s) {\n"+
		"  .split { grid-template-columns: 1fr 1fr; }\n"+
		"  .split.flip > :first-child { order: 2; }\n"+
		"  .detail-grid { grid-template-columns: 1fr 1fr; }\n"+
		"  .hero-split { grid-template-columns: 1.1fr 1fr; }\n"+
		"}\n", md)

	// A sidebar needs more room than a split does: it is a narrow column that
	// still has to hold readable text beside it.
	fmt.Fprintf(&b, "@container (min-width: %s) {\n"+
		"  .with-side { grid-template-columns: 15rem 1fr; }\n"+
		"}\n", lg)

	return b.String()
}

// lengthOf resolves a length token, falling back to its shipped value.
func (t *Theme) lengthOf(name string) string {
	tok, ok := Lookup(name)
	if !ok {
		return "0"
	}
	return t.value(tok, false)
}

// Report renders findings as text for a terminal.
func Report(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	var b strings.Builder
	for _, f := range findings {
		b.WriteString(f.String())
		b.WriteString("\n")
	}
	return b.String()
}
