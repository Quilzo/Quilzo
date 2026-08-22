// Package theme is the part of a site's design an operator may change, and the
// checks that stop them making it unreadable.
//
// # Why a token set rather than a stylesheet upload
//
// The obvious way to let somebody customise a design is to let them replace the
// stylesheet. That is also how a CMS ends up serving a site nobody can read:
// there is no gate a free-form stylesheet can be held to, so the tool that
// refuses to publish an image with no alternative text will happily publish
// grey-on-grey body text at 1.8:1.
//
// So the design splits in two. The component rules — what a card is, how a grid
// wraps, where the focus ring goes — ship with the tool and are not editable,
// because they are the accessibility work. The tokens — colours, type, radius,
// density — are a closed list of named values, and every one of them is checked
// before it reaches a page.
//
// That is a real constraint and it is worth being plain about what it costs: an
// operator cannot invent a new component here. What they get instead is every
// colour, both colour schemes, three type stacks, the corner radius, the
// spacing scale and the measure, on any layout, with a promise that the result
// still passes the gate.
//
// # Why contrast is checked here and refused at publish
//
// internal/a11y lists colour contrast under what it does not cover, on the
// grounds that contrast "lives in stylesheets this tool does not see". That was
// true and it stopped being true the moment the tool started generating the
// stylesheet. A ratio is arithmetic over two hex values; there is nothing to
// judge and nothing to guess. So it is computed, and a theme that puts text
// below 4.5:1 against its own background is refused with both numbers named —
// the same treatment an inaccessible page gets, for the same reason.
//
// # Why values are matched rather than sanitised
//
// Every value here lands inside a stylesheet this origin serves. A sanitiser is
// a promise about every future version of the CSS grammar, which is not a
// promise this package can keep, so each token declares a pattern and anything
// that does not match it is refused. Three hex digits or six after a #, and
// nothing else: no rgb(), no named colours, no var(), no calc(). The same
// argument the admin's accent colour already makes, applied to a larger set.
package theme

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kind is what a token holds, and therefore what it is checked against.
type Kind string

const (
	// Colour is a hex colour: #abc or #aabbcc. Both schemes take one.
	Colour Kind = "colour"
	// Length is a CSS length in rem, em, px or ch. Bounded, because a radius
	// of 9999rem and a measure of 3ch are both technically valid and neither
	// produces a page anybody can use.
	Length Kind = "length"
	// Ratio is a unitless positive number, for the type scale and line height.
	Ratio Kind = "ratio"
	// FontStack names one of the built-in stacks, or a self-hosted family the
	// site actually serves.
	FontStack Kind = "font"
)

// Token is one thing an operator may change.
type Token struct {
	// Name is the token as it appears in configuration and in the CSS custom
	// property: "surface" becomes --surface.
	Name string
	Kind Kind
	// Light and Dark are the shipped values. A token with no Dark uses Light
	// in both schemes, which is right for a radius and wrong for a colour —
	// so every Colour token declares both and a test refuses one that does not.
	Light string
	Dark  string
	// Summary is what it is, in the terms somebody choosing would use.
	Summary string
	// Group orders the tokens on a screen and in `quilzo theme show`.
	Group string
}

// Pair is a foreground token that has to stay legible against a background one.
//
// Written out rather than inferred from the naming convention. The convention
// (on-x sits on x) covers most of them and not the interesting ones: a link
// colour sits on the surface and is not called on-surface, and an outline is
// non-text so it answers to 3:1 rather than 4.5:1. A list is longer and cannot
// be quietly wrong.
type Pair struct {
	Foreground string
	Background string
	// Min is the ratio this pair has to meet: 4.5 for body text, 3.0 for large
	// text and for anything non-textual that still has to be perceivable.
	Min float64
	// What names the thing that would become unreadable, so the refusal says
	// what breaks rather than which two tokens disagree.
	What string
	// Criterion is the WCAG success criterion, so a report can cite it.
	Criterion string
}

var pairs = []Pair{
	{"on-surface", "surface", 4.5, "body text on the page background", "WCAG 1.4.3"},
	{"on-surface-variant", "surface", 4.5, "secondary text — captions, metadata, the standfirst", "WCAG 1.4.3"},
	{"on-surface-variant", "surface-container", 4.5, "secondary text inside a card or a header", "WCAG 1.4.3"},
	{"on-surface", "surface-container", 4.5, "text inside a card", "WCAG 1.4.3"},
	{"on-surface", "surface-container-high", 4.5, "text on the raised surface", "WCAG 1.4.3"},
	{"on-primary", "primary", 4.5, "the label on a filled button", "WCAG 1.4.3"},
	{"on-primary-container", "primary-container", 4.5, "text in the hero", "WCAG 1.4.3"},
	{"on-secondary-container", "secondary-container", 4.5, "text on a chip", "WCAG 1.4.3"},
	{"on-tertiary-container", "tertiary-container", 4.5, "text on an accent card", "WCAG 1.4.3"},
	{"primary", "surface", 4.5, "a link in body text", "WCAG 1.4.3"},
	{"primary", "surface-container", 4.5, "a link inside a card or the header", "WCAG 1.4.3"},
	{"on-primary-container", "gradient-from", 4.5, "text on a gradient, at its first stop", "WCAG 1.4.3"},
	{"on-primary-container", "gradient-to", 4.5, "text on a gradient, at its second stop", "WCAG 1.4.3"},
	{"outline", "surface", 3.0, "a border, so a card's edge is visible at all", "WCAG 1.4.11"},
	{"focus-ring", "surface", 3.0, "the keyboard focus ring, which is how anybody not using a mouse knows where they are", "WCAG 2.4.11"},
	{"focus-ring", "surface-container", 3.0, "the focus ring over a card or the header", "WCAG 2.4.11"},
}

// tokens is the closed list. Adding one is a deliberate act with a default in
// both schemes and a sentence saying what it does.
var tokens = []Token{
	// -- surfaces -------------------------------------------------------------
	{"surface", Colour, "#f8f9fa", "#121414", "the page background", "surfaces"},
	{"on-surface", Colour, "#1a1c1d", "#e1e3e4", "body text", "surfaces"},
	{"on-surface-variant", Colour, "#3d484e", "#bec8cd", "secondary text: captions, metadata, the standfirst", "surfaces"},
	{"surface-container-lowest", Colour, "#feffff", "#0d0e0f", "the lowest surface, under a tonal button", "surfaces"},
	{"surface-container-low", Colour, "#f2f4f5", "#1a1c1d", "a card", "surfaces"},
	{"surface-container", Colour, "#eceeef", "#1e2021", "the header, a table head, a quote", "surfaces"},
	{"surface-container-high", Colour, "#e6e8e9", "#282a2b", "a raised surface: a sticky bar, a popover", "surfaces"},

	// -- accents --------------------------------------------------------------
	{"primary", Colour, "#00515f", "#93d0dc", "links, filled buttons, the accent everything else answers to", "accents"},
	{"on-primary", Colour, "#f1ffff", "#003741", "the label on a filled button", "accents"},
	{"primary-container", Colour, "#c2e9f1", "#00414d", "the hero background", "accents"},
	{"on-primary-container", Colour, "#002026", "#c2e9f1", "text in the hero", "accents"},
	{"secondary-container", Colour, "#d7e5e8", "#304b50", "a chip, a current navigation item", "accents"},
	{"on-secondary-container", Colour, "#121d1f", "#d7e5e8", "text on a chip", "accents"},
	{"tertiary-container", Colour, "#f0dded", "#5c3c58", "an accent card, a callout — the second colour in the palette", "accents"},
	{"on-tertiary-container", Colour, "#251723", "#f0dded", "text on an accent card", "accents"},

	// -- gradient -------------------------------------------------------------
	//
	// Two stops and an angle rather than a free-form gradient string. A
	// gradient is the one decorative value people most want to set and the one
	// that most easily becomes unreadable, so the stops are ordinary colours —
	// which means they go through the same pattern match, and text sitting on
	// them is checked against the darker stop like any other pair.
	{"gradient-from", Colour, "#c2e9f1", "#00414d", "the gradient's first stop", "gradient"},
	{"gradient-to", Colour, "#f0dded", "#5c3c58", "its second stop", "gradient"},
	{"gradient-angle", Length, "160", "", "the angle in degrees, unitless", "gradient"},

	// -- breakpoints ----------------------------------------------------------
	//
	// These are the one part of the design that cannot be a custom property. A
	// container or media query is evaluated before the cascade, so it cannot
	// read var(--anything) — which is a real CSS limitation and not an
	// oversight. So the queries that use them are generated per site, in
	// Responsive() below, from the values here.
	//
	// They are container queries rather than viewport ones: a split section put
	// inside a narrow column should stack because its column is narrow, not
	// because the window is. That is also why the numbers are smaller than the
	// device widths people expect.
	{"break-sm", Length, "34rem", "", "where a two-across grid pairs up", "breakpoints"},
	{"break-md", Length, "46rem", "", "where a split section goes side by side", "breakpoints"},
	{"break-lg", Length, "52rem", "", "where a sidebar appears beside the content", "breakpoints"},

	// -- lines ----------------------------------------------------------------
	{"outline", Colour, "#677a84", "#83939c", "a visible border", "lines"},
	{"outline-variant", Colour, "#bec8cd", "#3d484e", "a hairline: a divider, a card edge", "lines"},
	{"focus-ring", Colour, "#006c7e", "#5eb8c7", "the keyboard focus ring", "lines"},

	// -- semantics ------------------------------------------------------------
	// Separate from the accent on purpose. A design whose "good" and its brand
	// are the same green cannot say a number is healthy, and a dashboard that
	// cannot say that is decoration.
	{"positive", Colour, "#175c3c", "#8fd6ae", "a good state: in stock, passing, up", "semantics"},
	{"caution", Colour, "#6b4a00", "#f0c860", "a state worth attention: low stock, degraded", "semantics"},
	{"critical", Colour, "#8c1d28", "#f6adb2", "a bad state: sold out, failing, down", "semantics"},

	// -- type -----------------------------------------------------------------
	{"font-body", FontStack, "system", "", "the face body text is set in", "type"},
	{"font-display", FontStack, "system", "", "the face headings are set in", "type"},
	{"font-mono", FontStack, "mono", "", "the face code and figures are set in", "type"},
	{"text-base", Length, "1.0625rem", "", "body text size, which everything else scales from", "type"},
	{"scale", Ratio, "1.25", "", "how much bigger each heading step is; 1.2 is gentle, 1.333 is dramatic", "type"},
	{"line", Ratio, "1.65", "", "body line height", "type"},
	{"measure", Length, "68ch", "", "how wide a line of body text is allowed to get", "type"},
	{"tracking-display", Length, "-0.025em", "", "letter spacing on large headings; negative tightens", "type"},

	// -- shape and space ------------------------------------------------------
	{"radius", Length, "16px", "", "the corner radius everything derives from; 0 is square, 28px is very round", "shape"},
	{"radius-pill", Length, "999px", "", "the radius for buttons and chips; set it to the radius above for square buttons", "shape"},
	{"density", Ratio, "1", "", "multiplies every gap and pad: 0.85 is compact, 1.15 is airy", "shape"},
	{"page-width", Length, "64rem", "", "the widest the content column gets", "shape"},
	{"border", Length, "1px", "", "hairline thickness; 0 removes every card and table border", "shape"},
}

// stacks are the built-in font stacks.
//
// Every one is a list of faces that are already on the device. Nothing is
// downloaded, because a page that fetches a font from another origin has handed
// that origin a request on every visit and the ability to stall the render —
// and a self-hosted face is a better answer anyway, which is what the site's
// own /fonts route is for.
var stacks = map[string]string{
	"system":       `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`,
	"grotesque":    `"Helvetica Neue", Helvetica, Arial, "Liberation Sans", sans-serif`,
	"geometric":    `Futura, "Century Gothic", "URW Gothic", Avenir, "Trebuchet MS", sans-serif`,
	"humanist":     `"Segoe UI", Tahoma, Verdana, "DejaVu Sans", sans-serif`,
	"transitional": `Charter, "Bitstream Charter", "Sitka Text", Cambria, Georgia, serif`,
	"oldstyle":     `"Iowan Old Style", "Palatino Linotype", Palatino, "URW Palladio L", Georgia, serif`,
	"didone":       `Didot, "Bodoni MT", "Playfair Display", "Book Antiqua", Georgia, serif`,
	"slab":         `Rockwell, "Rockwell Nova", "Roboto Slab", "DejaVu Serif", Georgia, serif`,
	"industrial":   `Bahnschrift, "DIN Alternate", "Franklin Gothic Medium", Oswald, "Nimbus Sans Narrow", sans-serif`,
	"rounded":      `ui-rounded, "SF Pro Rounded", "Hiragino Maru Gothic ProN", Quicksand, Verdana, sans-serif`,
	"mono":         `ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace`,
	"antique":      `Superclarendon, "Bookman Old Style", "URW Bookman L", "Georgia Pro", Georgia, serif`,
}

// StackNames lists the built-in stacks, in a stable order.
func StackNames() []string {
	out := make([]string, 0, len(stacks))
	for n := range stacks {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Tokens lists every token, in declaration order.
//
// Declaration order rather than alphabetical: they are grouped by what they do,
// and a screen listing colours next to colours is easier to choose from than one
// listing "caution" next to "critical" next to "density".
func Tokens() []Token {
	out := make([]Token, len(tokens))
	copy(out, tokens)
	return out
}

// Lookup returns one token's declaration.
func Lookup(name string) (Token, bool) {
	for _, t := range tokens {
		if t.Name == name {
			return t, true
		}
	}
	return Token{}, false
}

var (
	reHex    = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
	reLength = regexp.MustCompile(`^-?(?:0|[1-9][0-9]{0,3})(?:\.[0-9]{1,3})?(?:rem|em|px|ch|%)?$`)
	reRatio  = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,2})(?:\.[0-9]{1,3})?$`)
	reFamily = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 _-]{0,40}$`)
)

// Theme is a set of overrides over the shipped defaults.
//
// Sparse on purpose. A theme that copied every token would freeze the design at
// the moment it was written: a contrast fix or a new token shipped in a release
// would not reach any site that had ever been themed. Storing only what somebody
// changed means the rest keeps improving.
type Theme struct {
	// light and dark hold overrides per scheme. A colour set in light only
	// leaves dark on its default, which is usually not what anybody wants and
	// is reported as an advisory rather than refused — a site that is only ever
	// viewed in one scheme is a real situation.
	light map[string]string
	dark  map[string]string
	// families are the self-hosted faces this site serves, by family name.
	// A font token may name one of these or one of the built-in stacks.
	families []Family
}

// Family is a self-hosted typeface the site serves from its own origin.
type Family struct {
	// Name is the family as CSS refers to it, taken from the filename.
	Name string
	// Href is where the site serves it, e.g. /fonts/Satoshi.woff2.
	Href string
	// Weight is the weight or variable range, e.g. "400" or "100 900".
	Weight string
	// Style is "normal" or "italic".
	Style string
}

// Finding is a theme value that is wrong, or right in a way worth mentioning.
type Finding struct {
	Token     string  `json:"token,omitempty"`
	Detail    string  `json:"detail"`
	Blocking  bool    `json:"blocking"`
	Ratio     float64 `json:"ratio,omitempty"`
	Needs     float64 `json:"needs,omitempty"`
	Criterion string  `json:"criterion,omitempty"`
	Scheme    string  `json:"scheme,omitempty"`
}

func (f Finding) String() string {
	sev := "advisory"
	if f.Blocking {
		sev = "blocking"
	}
	s := "[" + sev + "] "
	if f.Token != "" {
		s += f.Token + ": "
	}
	return s + f.Detail
}

// New builds a theme from overrides.
//
// Keys are "token" for both schemes, or "token.dark" for the dark scheme alone.
// An unknown key is an error rather than a warning: a typo that is ignored is a
// setting somebody believes they made.
func New(overrides map[string]string, families []Family) (*Theme, []Finding) {
	t := &Theme{
		light:    map[string]string{},
		dark:     map[string]string{},
		families: families,
	}
	var problems []Finding

	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := strings.TrimSpace(overrides[key])
		if value == "" {
			continue
		}
		name, scheme := key, "both"
		if base, found := strings.CutSuffix(key, ".dark"); found {
			name, scheme = base, "dark"
		} else if base, found := strings.CutSuffix(key, ".light"); found {
			name, scheme = base, "light"
		}

		tok, known := Lookup(name)
		if !known {
			problems = append(problems, Finding{
				Token: name, Blocking: true,
				Detail: fmt.Sprintf("there is no %q token. The set is closed — "+
					"see `quilzo theme tokens` for the whole list", name),
			})
			continue
		}
		if err := t.validate(tok, value); err != nil {
			problems = append(problems, Finding{
				Token: name, Blocking: true, Scheme: scheme,
				Detail: err.Error(),
			})
			continue
		}
		if tok.Kind != Colour && scheme != "both" {
			problems = append(problems, Finding{
				Token: name, Blocking: true, Scheme: scheme,
				Detail: fmt.Sprintf("%s is not a colour, so it has one value "+
					"rather than one per scheme. Set %s without the suffix",
					name, name),
			})
			continue
		}
		switch scheme {
		case "dark":
			t.dark[name] = value
		case "light":
			t.light[name] = value
		default:
			t.light[name] = value
			if tok.Kind == Colour {
				// A colour set once applies to both schemes, which is almost
				// never what somebody meant — the same hex against a light and
				// a dark ground cannot both be legible. Kept rather than
				// refused, because a single-scheme site is a real choice, and
				// Check() reports the contrast either way.
				t.dark[name] = value
			}
		}
	}
	return t, problems
}

func (t *Theme) validate(tok Token, value string) error {
	switch tok.Kind {
	case Colour:
		if !reHex.MatchString(value) {
			return fmt.Errorf("%q is not a hex colour. Three or six hex "+
				"digits after a #, and nothing else: rgb(), a named colour "+
				"and var() are refused because this value lands inside a "+
				"stylesheet this site serves, and a sanitiser would be a "+
				"promise about every future version of CSS", value)
		}
	case Length:
		if !reLength.MatchString(value) {
			return fmt.Errorf("%q is not a length. A number with rem, em, px, "+
				"ch or %% — no calc(), no var()", value)
		}
	case Ratio:
		n, err := strconv.ParseFloat(value, 64)
		if err != nil || !reRatio.MatchString(value) {
			return fmt.Errorf("%q is not a number", value)
		}
		if n <= 0 {
			return fmt.Errorf("%s has to be greater than zero", tok.Name)
		}
	case FontStack:
		if _, built := stacks[value]; built {
			return nil
		}
		if !reFamily.MatchString(value) {
			return fmt.Errorf("%q is neither a built-in stack (%s) nor a "+
				"usable family name", value, strings.Join(StackNames(), ", "))
		}
		for _, f := range t.families {
			if strings.EqualFold(f.Name, value) {
				return nil
			}
		}
		return fmt.Errorf("%q is not a built-in stack and this site does not "+
			"serve a font by that name. Put the .woff2 in templates/fonts/ "+
			"and it becomes available under its filename. Built in: %s",
			value, strings.Join(StackNames(), ", "))
	}
	return nil
}

// value resolves a token in one scheme, falling back to the shipped default.
func (t *Theme) value(tok Token, dark bool) string {
	if t != nil {
		set := t.light
		if dark {
			set = t.dark
		}
		if v, ok := set[tok.Name]; ok {
			return v
		}
	}
	if dark && tok.Dark != "" {
		return tok.Dark
	}
	return tok.Light
}

// Value resolves one token by name, for use by a screen showing what is in
// effect. The second return says whether an operator set it.
func (t *Theme) Value(name string, dark bool) (string, bool) {
	tok, ok := Lookup(name)
	if !ok {
		return "", false
	}
	set := t.light
	if dark {
		set = t.dark
	}
	_, overridden := set[name]
	return t.value(tok, dark), overridden
}

// Overrides returns what was set, for round-tripping into configuration.
func (t *Theme) Overrides() map[string]string {
	out := map[string]string{}
	for k, v := range t.light {
		out[k] = v
	}
	for k, v := range t.dark {
		if out[k] != v {
			out[k+".dark"] = v
		}
	}
	return out
}

// Check reports contrast failures in both schemes.
//
// Both, always. A site checked in light and served in dark to half its readers
// is checked for half its readers, and the dark palette is the one people get
// wrong — it is the one that gets less looking at.
func (t *Theme) Check() []Finding {
	var out []Finding
	for _, scheme := range []struct {
		name string
		dark bool
	}{{"light", false}, {"dark", true}} {
		for _, p := range pairs {
			fg, okF := Lookup(p.Foreground)
			bg, okB := Lookup(p.Background)
			if !okF || !okB {
				continue
			}
			ratio := Contrast(t.value(fg, scheme.dark), t.value(bg, scheme.dark))
			if ratio >= p.Min {
				continue
			}
			out = append(out, Finding{
				Token: p.Foreground, Blocking: true, Scheme: scheme.name,
				Ratio: ratio, Needs: p.Min, Criterion: p.Criterion,
				Detail: fmt.Sprintf(
					"%s is %.2f:1 against %s in the %s scheme, and needs "+
						"%.1f:1. This is %s",
					p.Foreground, ratio, p.Background, scheme.name, p.Min, p.What),
			})
		}
	}
	// A colour changed in one scheme and not the other is legal and is almost
	// always an oversight, so it is said out loud without blocking.
	for name := range t.light {
		tok, ok := Lookup(name)
		if !ok || tok.Kind != Colour {
			continue
		}
		if t.dark[name] == t.light[name] {
			out = append(out, Finding{
				Token: name, Blocking: false,
				Detail: fmt.Sprintf("%s is the same colour in both schemes. "+
					"Set %s.dark if it should differ in dark mode", name, name),
			})
		}
	}
	return out
}

// Blocks reports whether any finding refuses a publish.
func Blocks(findings []Finding) bool {
	for _, f := range findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

// Contrast is the WCAG 2.x contrast ratio between two hex colours.
//
// Arithmetic, not judgement, which is the whole reason this can be a gate: two
// hex values in, one number out, the same number every time. An unparseable
// colour returns 0 so it fails rather than passes — a malformed value must not
// be the thing that lets a theme through.
func Contrast(a, b string) float64 {
	la, okA := luminance(a)
	lb, okB := luminance(b)
	if !okA || !okB {
		return 0
	}
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// luminance is the WCAG relative luminance of a hex colour.
func luminance(hex string) (float64, bool) {
	r, g, b, ok := rgb(hex)
	if !ok {
		return 0, false
	}
	return 0.2126*linear(r) + 0.7152*linear(g) + 0.0722*linear(b), true
}

func linear(c float64) float64 {
	if c <= 0.03928 {
		return c / 12.92
	}
	// The sRGB transfer function. Written out rather than pulled from math,
	// because ((c+0.055)/1.055)^2.4 with a fixed exponent is a handful of
	// multiplications and this package has no dependencies to spend.
	return pow((c+0.055)/1.055, 2.4)
}

// pow is x^y for the one exponent this package needs. Newton's method on the
// logarithm would be the general answer; exp(y*ln(x)) with series for both is
// enough here and keeps the package free of imports it does not otherwise need.
func pow(x, y float64) float64 {
	if x <= 0 {
		return 0
	}
	return exp(y * ln(x))
}

func ln(x float64) float64 {
	// Range-reduce to [1, 2) by counting halvings, then the atanh series, which
	// converges quickly over that interval.
	n := 0
	for x >= 2 {
		x /= 2
		n++
	}
	for x < 1 {
		x *= 2
		n--
	}
	z := (x - 1) / (x + 1)
	z2 := z * z
	sum, term := z, z
	for i := 3; i <= 21; i += 2 {
		term *= z2
		sum += term / float64(i)
	}
	return 2*sum + float64(n)*0.6931471805599453
}

func exp(x float64) float64 {
	neg := x < 0
	if neg {
		x = -x
	}
	sum, term := 1.0, 1.0
	for i := 1; i <= 24; i++ {
		term *= x / float64(i)
		sum += term
	}
	if neg {
		return 1 / sum
	}
	return sum
}

func rgb(hex string) (r, g, b float64, ok bool) {
	s := strings.TrimPrefix(strings.TrimSpace(hex), "#")
	if len(s) == 3 {
		s = string([]byte{s[0], s[0], s[1], s[1], s[2], s[2]})
	}
	if len(s) != 6 {
		return 0, 0, 0, false
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, 0, 0, false
	}
	return float64((v>>16)&0xff) / 255, float64((v>>8)&0xff) / 255,
		float64(v&0xff) / 255, true
}
