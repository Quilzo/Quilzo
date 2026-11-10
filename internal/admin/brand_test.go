// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"slices"
	"strings"
	"testing"
)

// A colour that is not a colour is refused, not sanitised.
//
// The value lands inside a style attribute on the root element, so one that
// escapes its declaration writes CSS chosen by whoever set the configuration —
// and on a multi-tenant deployment that is not necessarily the person looking
// at the screen. A sanitiser here would be a promise about every future CSS
// grammar; a pattern is a promise about this one.
func TestABrandColourIsRefusedRatherThanCleaned(t *testing.T) {
	for _, bad := range []string{
		"red",                         // named colours are another grammar
		"rgb(1,2,3)",                  // so is this
		"var(--x)",                    // and this
		"#0b6fa4; background: url(x)", // the escape it exists to stop
		"#0b6fa4\"onload=alert(1)",    // out of the attribute entirely
		"#zzz", "#12345", "0b6fa4", "",
	} {
		b := Brand{Colour: bad}
		if bad != "" {
			if err := b.Validate(); err == nil {
				t.Errorf("the colour %q was accepted", bad)
			}
		}
		// And whatever Validate did, nothing invalid reaches the attribute.
		if s := string(b.Style()); s != "" && !strings.HasSuffix(s, "#0b6fa4") {
			if strings.ContainsAny(s, ";\"'<>()") {
				t.Errorf("the colour %q reached the style attribute as %q",
					bad, s)
			}
		}
	}

	ok := Brand{Colour: "#0b6fa4"}
	if err := ok.Validate(); err != nil {
		t.Errorf("a plain hex colour was refused: %v", err)
	}
	if got := string(ok.Style()); got != "--brand: #0b6fa4" {
		t.Errorf("style is %q", got)
	}
}

// Style re-checks rather than trusting that Validate ran.
//
// "The caller validated it" is an assumption, and this is the one value in the
// interface that becomes CSS.
func TestStyleRecheckstheColourItself(t *testing.T) {
	b := Brand{Colour: "#fff; position:fixed; inset:0"}
	if got := string(b.Style()); got != "" {
		t.Errorf("an unvalidated brand produced the style %q; Style has to "+
			"check for itself, because a caller that skipped Validate is "+
			"exactly the case this guards", got)
	}
}

// The name is bounded and cannot break out of its line.
func TestABrandNameIsBounded(t *testing.T) {
	if err := (Brand{Name: strings.Repeat("x", MaxBrandName+1)}).Validate(); err == nil {
		t.Error("an over-long brand name was accepted")
	}
	if err := (Brand{Name: "Acme\nInc"}).Validate(); err == nil {
		t.Error("a brand name containing a line break was accepted")
	}
	if err := (Brand{Name: "Acme Publishing"}).Validate(); err != nil {
		t.Errorf("an ordinary name was refused: %v", err)
	}
}

// The mark is one character, because an image would be bytes this origin serves.
func TestTheMarkIsASingleCharacter(t *testing.T) {
	if err := (Brand{Mark: "AB"}).Validate(); err == nil {
		t.Error("a two-character mark was accepted")
	}
	if err := (Brand{Mark: "A"}).Validate(); err != nil {
		t.Errorf("a single character was refused: %v", err)
	}
	// A multi-byte character is still one character.
	if err := (Brand{Mark: "◆"}).Validate(); err != nil {
		t.Errorf("a multi-byte mark was refused: %v", err)
	}
}

// An unbranded deployment looks exactly as it always did.
func TestTheDefaultIsQuilzo(t *testing.T) {
	var b Brand
	if b.Label() != "Quilzo" {
		t.Errorf("the default label is %q", b.Label())
	}
	if b.Style() != "" {
		t.Error("an unconfigured brand emitted a style attribute")
	}
	if b.Initial() != "" {
		t.Error("an unconfigured brand replaced the mark")
	}
}

// The brand reaches the page, and the name is escaped by the template.
func TestTheBrandReachesTheInterface(t *testing.T) {
	srv, token := setup(t)
	srv.Brand = Brand{Name: `Acme & Co <script>`, Colour: "#0b6fa4", Mark: "A"}

	body := get(t, srv, "/", token).Body.String()
	// Through the stylesheet, which the policy allows; a style attribute
	// carrying it passed this test for months and was refused by the browser.
	if !strings.Contains(body, `href="/brand.css"`) ||
		!strings.Contains(get(t, srv, "/brand.css", "").Body.String(), "--brand: #0b6fa4") {
		t.Error("the accent did not reach the page")
	}
	if strings.Contains(body, "<script>") {
		t.Fatal("the brand name reached the page unescaped")
	}
	if !strings.Contains(body, "Acme &amp; Co") {
		t.Error("the brand name is not shown")
	}
	// And the built-in mark is replaced rather than sitting beside it.
	if strings.Contains(body, `viewBox="0 0 24 24" width="22"`) {
		t.Error("the built-in logo is still drawn beside the operator's mark")
	}
}

// A malicious colour cannot reach the page, even though the escaper stands
// aside for this one value.
//
// Style returns template.CSS, which tells html/template not to check it. That
// makes the pattern the only thing standing between a configuration value and
// the stylesheet, so the guarantee is asserted end to end rather than at the
// function that produces the string.
func TestAMaliciousBrandColourNeverReachesThePage(t *testing.T) {
	for _, bad := range []string{
		`#fff; position: fixed; inset: 0; background: red`,
		`#fff" onload="alert(1)`,
		`#fff; background: url(https://evil.example/x)`,
		`red`,
		`var(--surface)`,
	} {
		srv, token := setup(t)
		// Set directly, as a caller who skipped Validate would.
		srv.Brand = Brand{Colour: bad}

		body := get(t, srv, "/", token).Body.String()
		if strings.Contains(body, "position: fixed") ||
			strings.Contains(body, "evil.example") ||
			strings.Contains(body, "onload") {
			t.Errorf("the colour %q reached the page", bad)
		}
		if strings.Contains(body, "--brand:") {
			t.Errorf("the colour %q was emitted as a brand declaration", bad)
		}
	}
}

// The colour reaches the page through a stylesheet the policy allows. In a
// style attribute it was refused by style-src 'self' and never shown.
func TestTheBrandColourIsAStylesheetThePolicyAllows(t *testing.T) {
	srv, token := setup(t)
	srv.Brand = Brand{Colour: "#0b6fa4"}
	page := get(t, srv, "/", token)
	body := page.Body.String()
	if strings.Contains(body, `style="--brand`) {
		t.Error("the colour is still in a style attribute, which the policy refuses")
	}
	if !strings.Contains(body, `href="/brand.css"`) {
		t.Error("the page does not link the brand stylesheet")
	}
	if p := page.Header().Get("Content-Security-Policy"); !strings.Contains(p, "style-src 'self'") {
		t.Fatalf("policy changed: %s", p)
	}
	css := get(t, srv, "/brand.css", "").Body.String()
	if !strings.Contains(css, "--brand: #0b6fa4") {
		t.Errorf("brand.css is %q", css)
	}
	srv.Brand = Brand{Colour: "#fff; position:fixed"}
	if css := get(t, srv, "/brand.css", "").Body.String(); strings.TrimSpace(css) != "" {
		t.Errorf("an invalid colour reached the stylesheet: %q", css)
	}
	if strings.Contains(get(t, srv, "/", token).Body.String(), `href="/brand.css"`) {
		t.Error("the stylesheet is linked with no colour to give")
	}
}

// A brand colour is the links' and buttons' colour in each scheme it is
// legible in, and the logo's tint only where it is not, with the Settings
// screen saying which and why.
//
// It tinted only the logo, the name and the initial chip, so a deployment
// could not wear its own accent. It does not simply replace --primary
// either: a brand would then take this interface below the 7:1 its text is
// held to, in the scheme fewer people look at.
func TestABrandColourIsTheAccentWhereItIsLegible(t *testing.T) {
	for _, c := range []struct {
		colour, primary string
		says            []string
	}{
		// Dark enough for the light scheme, and nothing like it in the dark.
		{"#5b1a8c", "--primary: light-dark(#5b1a8c, var(--primary-80))",
			[]string{"links and buttons in the light scheme", "In the dark one it tints only", "7:1"}},
		// Pale enough for the dark scheme only.
		{"#ffd8e4", "--primary: light-dark(var(--primary-30), #ffd8e4)",
			[]string{"links and buttons in the dark scheme", "In the light one it tints only", "7:1"}},
		// Under the floor in both: today's tint, and why.
		{"#0b6fa4", "",
			[]string{"tints only the logo and the name", "4.25:1", "2.24:1", "7:1"}},
	} {
		srv, token := setup(t)
		srv.Brand = Brand{Colour: c.colour}
		css := get(t, srv, "/brand.css", "").Body.String()
		if !strings.Contains(css, "--brand: "+c.colour) {
			t.Errorf("%s: the tint is gone: %q", c.colour, css)
		}
		if c.primary == "" && strings.Contains(css, "--primary") {
			t.Errorf("%s is under the floor in both schemes and still set --primary: %q", c.colour, css)
		}
		if c.primary != "" && !strings.Contains(css, c.primary) {
			t.Errorf("%s: brand.css is %q, want %q", c.colour, css, c.primary)
		}

		withSettings(t, srv, map[string]string{"admin.brand.colour": c.colour})
		page := get(t, srv, "/settings", token).Body.String()
		for _, want := range c.says {
			if !strings.Contains(page, want) {
				t.Errorf("%s: the Settings screen does not say %q", c.colour, want)
			}
		}
	}
}

// The surfaces and on-primary the accent is checked against are the
// stylesheet's, in both schemes, and so is the primary it leaves in place:
// a palette changed in one and not the other would check a brand against
// colours nobody is shown.
func TestTheAccentIsCheckedAgainstTheStylesheetsOwnColours(t *testing.T) {
	for _, dark := range []bool{false, true} {
		scheme := map[bool]string{false: "light", true: "dark"}[dark]
		tok := tokens(t, scheme)
		var want []string
		for _, role := range []string{"--surface", "--surface-container-lowest", "--surface-container-low",
			"--surface-container", "--surface-container-high", "--surface-container-highest"} {
			if !slices.Contains(want, tok[role]) {
				want = append(want, tok[role])
			}
		}
		if strings.Join(want, " ") != strings.Join(accentSurfaces[dark], " ") {
			t.Errorf("%s: the accent is checked against %v; the stylesheet's surfaces are %v",
				scheme, accentSurfaces[dark], want)
		}
		if tok["--on-primary"] != accentOnPrimary[dark] {
			t.Errorf("%s: on-primary is %s in the stylesheet and %s here", scheme, tok["--on-primary"], accentOnPrimary[dark])
		}
	}
	css := string(mustAsset(t, "style.css"))
	if want := "--primary: light-dark(" + primaryDefault[false] + ", " + primaryDefault[true] + ");"; !strings.Contains(css, want) {
		t.Errorf("the stylesheet's primary is not %q, which is what a brand leaves in place", want)
	}
}
