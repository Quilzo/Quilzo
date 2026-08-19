package admin

import (
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
	if !strings.Contains(body, "--brand: #0b6fa4") {
		t.Error("the accent did not reach the root element")
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
