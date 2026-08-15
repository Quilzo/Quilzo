package admin

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The stylesheet claims AAA contrast. This computes it.
//
// A palette checked once by hand is a palette that was correct on the day
// somebody checked it. Every later edit — a tone swapped for one that "looks
// better", a role repointed — is a silent regression, because nothing in a
// stylesheet fails when the contrast drops. So the ratios are derived from the
// file itself, and changing a token to something unreadable breaks the build.
//
// The specific reason this matters here: Material 3's standard light scheme puts
// primary at tone 40, which lands near 4.5:1 on white. Adopting M3 without
// noticing that would have quietly downgraded this interface from AAA to AA.

// Not anchored to the line start: the palette blocks pack several
// declarations onto one line, and an anchored pattern would silently see
// only the first of each — which is the kind of partial match that makes a
// test pass by checking less than it claims.
var tokenRE = regexp.MustCompile(`(--[a-z0-9-]+)\s*:\s*([^;{}]+);`)

// tokens reads every custom property in the stylesheet and resolves var()
// chains down to a literal colour.
func tokens(t *testing.T, scope string) map[string]string {
	t.Helper()
	raw := string(mustAsset(t, "style.css"))

	// Light values come from the :root block, dark from the media query. Split
	// on the media query so a dark override does not leak into the light map.
	light, dark, _ := strings.Cut(raw, "@media (prefers-color-scheme: dark)")
	src := light
	if scope == "dark" {
		// Dark inherits everything not overridden, so start from light and let
		// the media block replace what it names.
		src = light + dark
	}

	out := map[string]string{}
	for _, m := range tokenRE.FindAllStringSubmatch(src, -1) {
		out[m[1]] = strings.TrimSpace(m[2])
	}

	// Resolve var(--x) references, bounded so a cycle cannot hang the test.
	varRE := regexp.MustCompile(`var\((--[a-z0-9-]+)\)`)
	for range 8 {
		changed := false
		for k, v := range out {
			if m := varRE.FindStringSubmatch(v); m != nil {
				if target, ok := out[m[1]]; ok && !strings.Contains(target, "var(") {
					out[k] = target
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	return out
}

func rgb(hex string) (float64, float64, float64, bool) {
	hex = strings.TrimSpace(hex)
	if !strings.HasPrefix(hex, "#") || (len(hex) != 7 && len(hex) != 4) {
		return 0, 0, 0, false
	}
	if len(hex) == 4 {
		hex = "#" + string(hex[1]) + string(hex[1]) + string(hex[2]) +
			string(hex[2]) + string(hex[3]) + string(hex[3])
	}
	var c [3]float64
	for i := range 3 {
		v, err := strconv.ParseInt(hex[1+i*2:3+i*2], 16, 32)
		if err != nil {
			return 0, 0, 0, false
		}
		c[i] = float64(v) / 255
	}
	return c[0], c[1], c[2], true
}

// relative luminance, WCAG 2.x definition.
func luminance(hex string) (float64, bool) {
	r, g, b, ok := rgb(hex)
	if !ok {
		return 0, false
	}
	f := func(c float64) float64 {
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*f(r) + 0.7152*f(g) + 0.0722*f(b), true
}

func contrast(t *testing.T, tok map[string]string, fg, bg string) float64 {
	t.Helper()
	lf, ok1 := luminance(tok[fg])
	lb, ok2 := luminance(tok[bg])
	if !ok1 || !ok2 {
		t.Fatalf("cannot resolve %s (%q) or %s (%q) to a colour",
			fg, tok[fg], bg, tok[bg])
	}
	if lf < lb {
		lf, lb = lb, lf
	}
	return (lf + 0.05) / (lb + 0.05)
}

// pair is a foreground role and the surface it is designed to sit on. The M3
// naming convention makes these mechanical: on-X always goes on X.
var textPairs = []struct{ fg, bg, what string }{
	{"--on-surface", "--surface", "body text"},
	{"--on-surface", "--surface-container", "text on a card"},
	{"--on-surface", "--surface-container-low", "text on a low card"},
	{"--on-surface", "--surface-container-high", "text on a raised card"},
	{"--on-surface-variant", "--surface", "secondary text"},
	{"--on-surface-variant", "--surface-container", "secondary text on a card"},
	{"--on-primary", "--primary", "filled button label"},
	{"--on-primary-container", "--primary-container", "text in a primary chip"},
	{"--on-secondary-container", "--secondary-container", "tonal button label"},
	{"--on-tertiary-container", "--tertiary-container", "text in a tertiary chip"},
	{"--on-error-container", "--error-container", "text in an error notice"},
	{"--on-ok-container", "--ok-container", "text in a success notice"},
	{"--on-warning-container", "--warning-container", "text in a warning notice"},
	{"--primary", "--surface", "link"},
	{"--inverse-on-surface", "--inverse-surface", "text on an inverted surface"},
}

// Non-text: borders, focus rings, the edge of an input. WCAG 1.4.11 asks 3:1.
var uiPairs = []struct{ fg, bg, what string }{
	{"--outline", "--surface", "input border"},
	{"--outline", "--surface-container-lowest", "input border on a field"},
	{"--focus-ring", "--surface", "focus indicator on the page"},
	{"--focus-ring", "--surface-container-low", "focus indicator on a card"},
	{"--error", "--surface", "error accent"},
}

func TestEveryTextPairingMeetsAAAInBothSchemes(t *testing.T) {
	for _, scheme := range []string{"light", "dark"} {
		tok := tokens(t, scheme)
		for _, p := range textPairs {
			r := contrast(t, tok, p.fg, p.bg)
			if r < 7.0 {
				t.Errorf("%s/%s: %s is %.2f:1 (%s on %s) — AAA needs 7:1",
					scheme, p.what, p.fg, r, tok[p.fg], tok[p.bg])
			}
		}
	}
}

func TestNonTextPairingsMeetTheUIMinimum(t *testing.T) {
	for _, scheme := range []string{"light", "dark"} {
		tok := tokens(t, scheme)
		for _, p := range uiPairs {
			r := contrast(t, tok, p.fg, p.bg)
			if r < 3.0 {
				t.Errorf("%s/%s: %.2f:1 (%s on %s) — 1.4.11 needs 3:1",
					scheme, p.what, r, tok[p.fg], tok[p.bg])
			}
		}
	}
}

// The two schemes must define the same roles. A role present in one and missing
// from the other renders as an inherited colour that nobody chose and nobody
// checked — and it will be the dark scheme, because that is the one fewer
// people look at.
func TestBothSchemesDefineEveryRole(t *testing.T) {
	light, dark := tokens(t, "light"), tokens(t, "dark")
	for _, p := range append(append([]struct{ fg, bg, what string }{},
		textPairs...), uiPairs...) {
		for _, role := range []string{p.fg, p.bg} {
			if _, ok := light[role]; !ok {
				t.Errorf("%s is not defined in the light scheme", role)
			}
			if _, ok := dark[role]; !ok {
				t.Errorf("%s is not defined in the dark scheme", role)
			}
		}
	}
}

// Nothing may remove a focus indicator. A keyboard user who cannot see where
// they are is a keyboard user locked out, and this is the single most common
// way that happens — someone silences a ring they found ugly.
func TestNothingRemovesTheFocusIndicator(t *testing.T) {
	css := string(mustAsset(t, "style.css"))
	// Strip comments first: this file discusses `outline: none` in prose, and
	// a test that greps the discussion is a test that fails for being right.
	stripped := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(css, "")

	for _, bad := range []string{"outline:none", "outline:0"} {
		flat := strings.ReplaceAll(strings.ReplaceAll(stripped, " ", ""), "\n", "")
		if strings.Contains(flat, bad) {
			t.Errorf("the stylesheet contains %q", bad)
		}
	}
	if !strings.Contains(stripped, ":focus-visible") {
		t.Error("no focus-visible rule at all")
	}
}

// M3 Expressive motion overshoots by design, which is exactly what 2.3.3 is
// about. Every animated property has to degrade to an instant state change.
func TestMotionIsDisabledWhenAsked(t *testing.T) {
	css := string(mustAsset(t, "style.css"))
	if !strings.Contains(css, "prefers-reduced-motion") {
		t.Fatal("the springs are unconditional")
	}
	block := css[strings.Index(css, "prefers-reduced-motion"):]
	for _, want := range []string{"transition-duration", "animation-duration"} {
		if !strings.Contains(block, want) {
			t.Errorf("reduced motion does not neutralise %s", want)
		}
	}
}

// Target size: 2.5.8 asks 24x24 and Material asks 48. Taking the stricter of
// the two is free, and the pointer-accuracy research behind 48 is the reason
// it is Material's default.
func TestInteractiveTargetsAreLargeEnough(t *testing.T) {
	css := string(mustAsset(t, "style.css"))
	stripped := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(css, "")

	minRE := regexp.MustCompile(`min-height:\s*(\d+)px`)
	found := 0
	for _, m := range minRE.FindAllStringSubmatch(stripped, -1) {
		v, _ := strconv.Atoi(m[1])
		// 0 is the reset on a checkbox, which sets its own 24px box.
		if v == 0 {
			continue
		}
		found++
		if v < 24 {
			t.Errorf("a min-height of %dpx is below the 2.5.8 floor", v)
		}
	}
	if found < 3 {
		t.Errorf("only %d sized targets found; this test has stopped looking",
			found)
	}
}

// mustAsset reads an embedded asset, so these tests check what actually ships
// rather than a file on disk that may not be the one compiled in.
func mustAsset(t *testing.T, name string) []byte {
	t.Helper()
	b, err := assets.ReadFile("assets/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// -- what a stylesheet must declare about the browser's own painting --------

// The bug this exists to prevent, and the reason the contrast tests above did
// not catch it: they check the colours this program chooses. They cannot check
// the colours the *browser* chooses for the parts nobody styles — the inside
// of a select's dropdown, checkboxes, scrollbars, spinner arrows.
//
// Without `color-scheme`, Chrome paints that dropdown with the OS light
// palette while the page supplies a light text colour, and the options are
// white on white: readable only under the hover highlight. Reported from a
// real browser, invisible to every test here, and invisible in a screenshot
// too unless the dropdown happens to be open.
func TestEveryStylesheetDeclaresAColourScheme(t *testing.T) {
	for _, name := range []string{"style.css"} {
		css := string(mustAsset(t, name))
		if !strings.Contains(css, "color-scheme") {
			t.Errorf("%s does not declare color-scheme, so native controls "+
				"will be drawn with the wrong palette in one theme", name)
		}
	}
}

// The playground builds its own page rather than using the layout, so it is
// checked separately — which is exactly why it had neither the declaration nor
// a palette when it shipped.
func TestThePlaygroundDeclaresAColourSchemeToo(t *testing.T) {
	body, _ := fetchPlayground(t)
	if !strings.Contains(body, "color-scheme") {
		t.Error("the playground page does not declare color-scheme")
	}
	// And it must not hand its controls the page's colour with the browser's
	// background, which is the pair that does not match.
	if strings.Contains(body, "background: inherit") ||
		strings.Contains(body, "color: inherit;") {
		t.Error("a form control inherits its colours, which is how the " +
			"select's options became invisible")
	}
	// Options styled explicitly, because the popup is the part that breaks.
	if !strings.Contains(body, ".pg option") {
		t.Error("the option elements are not given an explicit surface")
	}
}

// Anything a keyboard can reach must show where it is. A focus ring that
// inherits from a theme that does not define one is no focus ring.
func TestFocusIsVisible(t *testing.T) {
	css := string(mustAsset(t, "style.css"))
	if !strings.Contains(css, "focus-visible") {
		t.Error("nothing declares a focus style, so keyboard users cannot " +
			"see where they are")
	}
	body, _ := fetchPlayground(t)
	if !strings.Contains(body, "focus-visible") {
		t.Error("the playground has no focus style")
	}
}
