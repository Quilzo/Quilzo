package marking_test

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/marking"
)

// A deployment's own scheme, configured from its own register. Nothing in the
// package ships a vocabulary.
func scheme() marking.Policy {
	return marking.Policy{
		Levels:   []string{"UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"},
		Banner:   "SECRET//NOFORN",
		Controls: []string{"NOFORN", "REL TO", "ORCON"},
	}
}

// The syntax, as the register defines it: // between classification and
// controls and between categories, / within a category, - before a
// sub-control.
func TestABannerParsesTheWayTheRegisterDefinesIt(t *testing.T) {
	p := scheme()
	for _, banner := range []string{
		"SECRET",
		"SECRET//NOFORN",
		"SECRET//NOFORN/ORCON",
		"SECRET//REL TO-USA",
	} {
		if _, err := p.Parse(banner); err != nil {
			t.Errorf("%q did not parse: %v", banner, err)
		}
	}
}

// A word the deployment's register does not contain is refused rather than
// rendered. A banner is read by people who act on it, and one containing a
// marking this program did not recognise is one it should not have shown.
func TestAnUnknownMarkingIsRefused(t *testing.T) {
	p := scheme()
	for _, banner := range []string{
		"COSMIC TOP SECRET",  // not in this deployment's levels
		"SECRET//FOURTHEYES", // not in its controls
		"",
	} {
		if _, err := p.Parse(banner); err == nil {
			t.Errorf("%q was accepted", banner)
		}
	}
	// And the refusal names what is available, so somebody can act on it.
	_, err := p.Parse("SECRET//FOURTHEYES")
	if !strings.Contains(err.Error(), "NOFORN") {
		t.Errorf("the refusal does not say what the register holds: %v", err)
	}
}

// The control that matters: content above the site's banner must not publish.
//
// Everything else here is placement. This is spillage, and it is silent
// otherwise — the page renders, the banner says the site's level, and the
// content underneath is higher than the banner claims.
func TestAPageAboveTheDeploymentsBannerIsRefused(t *testing.T) {
	p := scheme() // accredited to SECRET

	err := p.CheckPage("TOP SECRET//NOFORN")
	if err == nil {
		t.Fatal("a TOP SECRET page passed on a SECRET deployment")
	}
	if !strings.Contains(err.Error(), "spill") {
		t.Errorf("the refusal does not name what happened: %v", err)
	}
}

// Below or equal is fine. A SECRET site carries CONFIDENTIAL pages.
func TestAPageAtOrBelowTheBannerPasses(t *testing.T) {
	p := scheme()
	for _, page := range []string{"", "CONFIDENTIAL", "SECRET", "SECRET//NOFORN"} {
		if err := p.CheckPage(page); err != nil {
			t.Errorf("%q was refused on a SECRET//NOFORN deployment: %v",
				page, err)
		}
	}
}

// A control the site's banner does not carry is refused too.
//
// Not a level check: ORCON on a SECRET page under a SECRET//NOFORN banner is
// the same level, and a reader would still see a banner that does not carry
// the limit the content is under.
func TestAControlTheBannerDoesNotCarryIsRefused(t *testing.T) {
	p := scheme() // SECRET//NOFORN

	err := p.CheckPage("SECRET//ORCON")
	if err == nil {
		t.Fatal("a page under a dissemination limit the site does not carry " +
			"was allowed")
	}
	if !strings.Contains(err.Error(), "ORCON") {
		t.Errorf("the refusal does not name the control: %v", err)
	}
}

// Unmarked content takes the deployment's banner rather than failing.
//
// Most pages are simply at the site's level. Requiring every one to repeat it
// is how people start pasting markings without reading them, which is the
// failure the whole scheme exists to prevent.
func TestUnmarkedContentTakesTheBanner(t *testing.T) {
	if err := scheme().CheckPage(""); err != nil {
		t.Errorf("unmarked content was refused: %v", err)
	}
}

// A deployment that does not mark is unaffected, which is every existing one.
func TestMarkingIsOffByDefault(t *testing.T) {
	var p marking.Policy
	if p.Enabled() {
		t.Fatal("a zero policy marks")
	}
	if err := p.CheckPage("TOP SECRET"); err != nil {
		t.Errorf("an unmarked deployment refused a page: %v", err)
	}
	top, bottom := p.BannerHTML()
	if top != "" || bottom != "" {
		t.Error("an unmarked deployment renders a banner")
	}
}

// The banner goes top and bottom, always. A banner at the top of a long page
// is one a reader scrolled past before reaching the part that matters.
func TestTheBannerIsRenderedAtBothEnds(t *testing.T) {
	top, bottom := scheme().BannerHTML()
	if top == "" || bottom == "" {
		t.Fatal("the banner is not rendered at both ends")
	}
	if top != bottom {
		t.Errorf("the two banners differ: %q and %q", top, bottom)
	}
}

// The order is the deployment's own, and nothing assumes what the levels are
// called. An installation using OFFICIAL and OFFICIAL-SENSITIVE works exactly
// as one using SECRET does.
func TestTheLevelOrderIsTheDeploymentsOwn(t *testing.T) {
	uk := marking.Policy{
		Levels:   []string{"OFFICIAL", "OFFICIAL-SENSITIVE", "SECRET"},
		Banner:   "OFFICIAL-SENSITIVE",
		Controls: []string{"HANDLING"},
	}
	if err := uk.CheckPage("OFFICIAL"); err != nil {
		t.Errorf("a lower level was refused: %v", err)
	}
	if err := uk.CheckPage("SECRET"); err == nil {
		t.Error("a higher level passed")
	}
}
