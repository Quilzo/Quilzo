// Package marking carries a deployment's classification banner and enforces
// where it appears.
//
// # What this does and does not decide
//
// It does not decide anything's classification. That is a judgement made by a
// person with the authority to make it, against their own authority's
// register, and a program that guessed at it would be producing the most
// dangerous kind of wrong answer: a confident one, in the right typeface.
//
// What it does is mechanical, and mechanical is what gets skipped. A banner
// has to be on every page, top and bottom, on the screen and in every export.
// A page marked above the deployment's banner must not publish. Portion
// markings have to come from the register rather than from somebody's memory.
// Those are rules a program can hold to exactly, and they are the ones people
// get wrong at four in the afternoon.
//
// # The syntax
//
// From the CAPCO Register, which is the authority for the vocabulary and is
// not reproduced here. Double slashes separate the classification from the
// control markings and separate categories of control marking; a single slash
// separates markings within a category; a hyphen separates a marking from its
// sub-control. So SECRET//NOFORN, and a portion is (S//NF).
//
// The vocabulary is the deployment's own, configured from their register.
// Shipping a list would be shipping a copy of somebody's controlled register
// that goes stale, and a marking accepted because this program's copy is out
// of date is worse than one refused.
//
// # Ordering
//
// Levels are ordered so a comparison can be made, and the order is the
// deployment's: they list their levels lowest first. Nothing here assumes
// what those levels are called. An installation using CONFIDENTIAL, SECRET
// and TOP SECRET and one using OFFICIAL and OFFICIAL-SENSITIVE both work,
// because the program never needs to know what the words mean -- only which
// of two is higher, and the operator said.
package marking

import (
	"fmt"
	"strings"
)

// Policy is a deployment's marking scheme.
type Policy struct {
	// Levels are the classification levels, lowest first. Empty disables
	// marking entirely, which is the default.
	Levels []string
	// Banner is the marking for the deployment as a whole: what appears at
	// the top and bottom of every page, and the ceiling nothing may exceed.
	Banner string
	// Controls are the control markings that may appear, from the
	// deployment's register.
	Controls []string
	// Portions maps a portion abbreviation to the level or control it stands
	// for, so (S//NF) can be checked rather than merely rendered.
	Portions map[string]string
}

// Enabled reports whether this deployment marks anything.
func (p Policy) Enabled() bool { return len(p.Levels) > 0 && p.Banner != "" }

// Marking is one parsed banner or portion.
type Marking struct {
	// Level is the classification, e.g. SECRET.
	Level string
	// Controls are the control markings in order, e.g. NOFORN.
	Controls []string
}

// String renders the marking in banner form.
func (m Marking) String() string {
	if len(m.Controls) == 0 {
		return m.Level
	}
	return m.Level + "//" + strings.Join(m.Controls, "/")
}

// Parse reads a banner line against this policy.
//
// Every part is checked against the deployment's register. An unrecognised
// marking is refused rather than passed through: a banner is read by people
// who will act on it, and one containing a word this program did not
// recognise is one it should not have rendered.
func (p Policy) Parse(banner string) (Marking, error) {
	raw := strings.TrimSpace(banner)
	if raw == "" {
		return Marking{}, fmt.Errorf("an empty banner marks nothing")
	}

	parts := strings.Split(raw, "//")
	level := strings.TrimSpace(parts[0])
	if !p.knownLevel(level) {
		return Marking{}, fmt.Errorf(
			"%q is not a level this deployment uses. Its levels are %s",
			level, strings.Join(p.Levels, ", "))
	}

	out := Marking{Level: level}
	for _, category := range parts[1:] {
		for _, control := range strings.Split(category, "/") {
			control = strings.TrimSpace(control)
			if control == "" {
				continue
			}
			// A sub-control is separated from its marking by a hyphen, and it
			// is the marking that has to be in the register.
			base := control
			if i := strings.Index(control, "-"); i > 0 {
				base = control[:i]
			}
			if !p.knownControl(base) {
				return Marking{}, fmt.Errorf(
					"%q is not a control marking this deployment uses. Its "+
						"controls are %s. The register is the deployment's "+
						"own; add it there if it belongs",
					control, strings.Join(p.Controls, ", "))
			}
			out.Controls = append(out.Controls, control)
		}
	}
	return out, nil
}

// Rank returns a level's position, lowest first.
func (p Policy) Rank(level string) (int, bool) {
	for i, l := range p.Levels {
		if strings.EqualFold(l, level) {
			return i, true
		}
	}
	return 0, false
}

func (p Policy) knownLevel(level string) bool {
	_, ok := p.Rank(level)
	return ok
}

func (p Policy) knownControl(control string) bool {
	for _, c := range p.Controls {
		if strings.EqualFold(c, control) {
			return true
		}
	}
	return false
}

// CheckPage decides whether a page marked this way may be published under the
// deployment's banner.
//
// The control that matters. Everything else here is placement; this is
// spillage: a page carrying a level above what the site as a whole is
// accredited for must not reach it, and the failure is silent otherwise --
// the page renders, the banner at the top says the site's level, and the
// content underneath is higher than the banner claims.
func (p Policy) CheckPage(pageBanner string) error {
	if !p.Enabled() {
		return nil
	}
	site, err := p.Parse(p.Banner)
	if err != nil {
		return fmt.Errorf("this deployment's own banner does not parse: %w", err)
	}
	if strings.TrimSpace(pageBanner) == "" {
		// Unmarked content takes the deployment's banner. Not an error: most
		// pages are simply at the site's level, and requiring every one to
		// repeat it is how people start pasting markings without reading them.
		return nil
	}
	page, err := p.Parse(pageBanner)
	if err != nil {
		return err
	}

	siteRank, _ := p.Rank(site.Level)
	pageRank, _ := p.Rank(page.Level)
	if pageRank > siteRank {
		return fmt.Errorf(
			"this page is marked %s and the deployment is accredited to %s. "+
				"Publishing it would put content above the banner the site "+
				"carries, which is the definition of a spill. Raise the "+
				"deployment's banner deliberately, or move the page",
			page, site)
	}

	// A control on the page and not on the site is a dissemination limit the
	// site does not carry. Refused for the same reason: the banner a reader
	// sees would not carry the limit the content is under.
	for _, c := range page.Controls {
		if !hasControl(site.Controls, c) {
			return fmt.Errorf(
				"this page carries %s and the deployment's banner (%s) does "+
					"not. A reader would see a banner that does not carry "+
					"the limit this content is under",
				c, site)
		}
	}
	return nil
}

func hasControl(list []string, want string) bool {
	for _, c := range list {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	return false
}

// BannerHTML renders the banner for the top and bottom of a page.
//
// Both, always. A banner at the top of a long page is one a reader has
// scrolled past by the time they are reading the part that matters, which is
// why every marking standard asks for it in both places.
func (p Policy) BannerHTML() (top, bottom string) {
	if !p.Enabled() {
		return "", ""
	}
	// Escaped by the caller's template, not here: a marking that arrives with
	// markup in it is a configuration error, and rendering it as markup would
	// make it an injection.
	return p.Banner, p.Banner
}
