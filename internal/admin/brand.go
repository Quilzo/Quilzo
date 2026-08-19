package admin

import (
	"fmt"
	"html/template"
	"regexp"
	"strings"
)

// Whose product this appears to be.
//
// # Why this is a feature and not a preference
//
// An agency running Quilzo for a client, or a company running it for its own
// staff, is showing this interface to people who have no relationship with
// this project and no reason to wonder what "Quilzo" is. White-labelling is
// consistently near the top of what buyers mean by customisation, and its
// absence is the sort of thing that loses a deal without anybody filing a bug.
//
// # Why it is three fields rather than a stylesheet
//
// The obvious implementation is to let an operator supply CSS. That is a
// remote code execution problem wearing a cardigan: CSS in the admin's own
// origin can load fonts and images, position elements over each other, and
// restyle a refusal to look like a confirmation. The admin's policy is
// `style-src 'self'`, and an operator-supplied stylesheet would either break
// that or be exempted from it.
//
// So the surface is deliberately tiny: a name, a colour, and an initial. Enough
// that nobody has to explain the interface to a client; not enough to change
// what any control does or says.
//
// The colour is the part that has to be checked rather than trusted. It lands
// inside a `style` attribute on the root element, so a value that escapes its
// declaration writes CSS chosen by whoever set the configuration — and on a
// multi-tenant deployment that is not necessarily the same person as the one
// looking at the screen. It is matched against a hex pattern and refused
// otherwise; there is no sanitising, because a sanitiser is a promise that the
// next CSS grammar will keep.

// reHexColour is the whole permitted vocabulary for a brand colour.
//
// Three or six hex digits, nothing else. Not `rgb()`, not a named colour, not
// `var(--x)`: each of those is another grammar to be right about, and the
// difference they make to somebody's brand is nil.
var reHexColour = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// MaxBrandName bounds the name.
//
// It sits in a heading and a page title. A long one does not break anything —
// the layout wraps — but it does let somebody push the sign-out link off a
// narrow screen, and a limit is cheaper than finding out which width does it.
const MaxBrandName = 40

// Brand is what an operator may change about the interface's appearance.
type Brand struct {
	// Name replaces "Quilzo" in the header and the page title. Empty keeps it.
	Name string `json:"name,omitempty"`
	// Colour is the accent, as a hex value. Empty keeps the built-in palette.
	Colour string `json:"colour,omitempty"`
	// Mark is a single character shown in place of the built-in logo, for an
	// operator who wants their own initial rather than this project's shape.
	//
	// One character rather than an image, because an uploaded logo is a file
	// this origin then serves, and the admin's policy allows images from
	// 'self' — so it would be a way to place chosen bytes at a URL inside the
	// origin. A letter cannot be a payload.
	Mark string `json:"mark,omitempty"`
}

// Validate refuses a brand that cannot mean what it appears to.
func (b Brand) Validate() error {
	if n := strings.TrimSpace(b.Name); len([]rune(n)) > MaxBrandName {
		return fmt.Errorf(
			"the brand name is %d characters and the limit is %d",
			len([]rune(n)), MaxBrandName)
	}
	if strings.ContainsAny(b.Name, "\r\n") {
		return fmt.Errorf("the brand name contains a line break")
	}
	if b.Colour != "" && !reHexColour.MatchString(b.Colour) {
		return fmt.Errorf(
			"%q is not a colour this accepts. Give three or six hex digits "+
				"after a #, like #0b6fa4. Anything else — rgb(), a named "+
				"colour, a var() — is another CSS grammar to be right about, "+
				"and this one lands inside a style attribute",
			b.Colour)
	}
	if b.Mark != "" && len([]rune(b.Mark)) != 1 {
		return fmt.Errorf(
			"the mark is %d characters; it is one, or empty for the default",
			len([]rune(b.Mark)))
	}
	return nil
}

// Label is what the interface calls itself.
func (b Brand) Label() string {
	if n := strings.TrimSpace(b.Name); n != "" {
		return n
	}
	return "Quilzo"
}

// Initial is the character shown in place of the built-in mark, or empty when
// the built-in one should be drawn.
func (b Brand) Initial() string { return strings.TrimSpace(b.Mark) }

// Style is the root element's style attribute, or empty.
//
// Built here rather than in the template so there is one place that decides
// what may land in it, and it re-checks the colour rather than trusting that
// Validate ran. A value reaching a style attribute unvalidated is the whole
// risk this type exists to bound, and "the caller validated it" is an
// assumption rather than a check.
//
// # Why this returns template.CSS
//
// html/template refuses to emit a custom property in a style attribute: it does
// not recognise `--brand: #0b6fa4` as CSS it can vouch for, and substitutes
// ZgotmplZ. That is the escaper being right about its own limits rather than
// wrong about this value, and the first version of this shipped a brand colour
// that silently did nothing because of it.
//
// So the type says the string is known-safe CSS. The safety comes from the
// pattern above and the re-check on the line below — a hex colour and nothing
// else — and not from the escaper, which has been told to stand aside. That is
// worth stating plainly: this is the one place in the admin where a
// configuration value becomes CSS on the authority of a regular expression.
func (b Brand) Style() template.CSS {
	if b.Colour == "" || !reHexColour.MatchString(b.Colour) {
		return ""
	}
	return template.CSS("--brand: " + b.Colour)
}
