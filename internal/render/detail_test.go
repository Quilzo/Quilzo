package render

import (
	"testing"

	"github.com/quilzo/quilzo/internal/menu"
)

// Half a detail declaration is noticed, and is not the same as none.
//
// A page naming a listing and no key cannot answer for any record. Treating it
// as an ordinary page would write one empty file and link to records that have
// none — which is what happened, and is why Declared() is separate from the
// second return of DetailOf.
func TestHalfADeclarationIsDeclaredButNotUsable(t *testing.T) {
	for name, body := range map[string]any{
		"no key":     map[string]any{"detail": "catalogue"},
		"no listing": map[string]any{"detail_key": "slug"},
	} {
		d, declared := DetailOf(body)
		if !declared {
			t.Errorf("%s: not noticed at all, so the page renders as an "+
				"ordinary one and its record links go nowhere", name)
		}
		if d.Declared() {
			t.Errorf("%s: reported as usable", name)
		}
	}

	d, declared := DetailOf(map[string]any{
		"detail": "catalogue", "detail_key": "slug"})
	if !declared || !d.Declared() {
		t.Error("a complete declaration was not recognised")
	}
	if d.Listing != "catalogue" || d.Key != "slug" {
		t.Errorf("read back wrong: %+v", d)
	}

	// An ordinary page is not a detail route.
	if _, declared := DetailOf(map[string]any{"title": "Home"}); declared {
		t.Error("an ordinary page was treated as a detail route")
	}
	// Neither is a non-object body.
	if _, declared := DetailOf("a string"); declared {
		t.Error("a page that is not an object was treated as a detail route")
	}
}

// Whitespace is not a declaration.
func TestABlankDeclarationIsNotUsable(t *testing.T) {
	d, declared := DetailOf(map[string]any{
		"detail": "   ", "detail_key": "  "})
	if declared {
		t.Error("whitespace was read as a declaration, so the page would be " +
			"refused for being half-written rather than rendered normally")
	}
	if d.Declared() {
		t.Error("whitespace produced a usable declaration")
	}
}

// A feed's heading is what the listing is called, not what it is keyed by.
//
// The resolver puts the listing's human name in "label", and this looked for
// "title" and fell back to the machine name — so a published page carried a
// heading reading "new_in". A page-level "title" still wins, because that is
// the more specific answer, and a listing with neither gets no heading at all:
// every layout guards on feed.title, and no heading beats one that looks like a
// variable name.
func TestAFeedIsHeadedByItsLabelAndNeverByItsKey(t *testing.T) {
	cases := []struct {
		name     string
		resolved map[string]any
		want     string
	}{
		{"new_in", map[string]any{"label": "Out of the last bath"},
			"Out of the last bath"},
		{"new_in", map[string]any{"label": "Out of the last bath",
			"title": "Just dyed"}, "Just dyed"},
		{"by_dye", map[string]any{"label": "   "}, ""},
		{"by_dye", map[string]any{}, ""},
	}
	for _, c := range cases {
		if got := title(c.resolved, c.name); got != c.want {
			t.Errorf("title(%v, %q) = %q, want %q", c.resolved, c.name, got,
				c.want)
		}
	}
}

// A heading in a menu is not a link to the home page.
//
// Href fell through to "/" + Target for anything that was not external, and a
// heading's target is empty by definition — so a nested menu's group titles all
// pointed at "/". In a footer that is two identical links called "By dyestuff"
// and "Reading", which is also what a screen reader reads out.
func TestAMenuHeadingPointsNowhere(t *testing.T) {
	heading := menu.Rendered{Item: menu.Item{
		Label: "By dyestuff", Kind: menu.Heading}}
	if got := Href(heading); got != "" {
		t.Errorf("a heading points at %q; it is a label for the entries under "+
			"it and has nothing to point at", got)
	}

	page := menu.Rendered{Item: menu.Item{
		Label: "Shop", Kind: menu.Page, Target: "shop"}}
	if got := Href(page); got != "/shop" {
		t.Errorf("a page entry points at %q", got)
	}
	home := menu.Rendered{Item: menu.Item{
		Label: "Home", Kind: menu.Page, Target: "index"}}
	if got := Href(home); got != "/" {
		t.Errorf("the index page points at %q", got)
	}
	away := menu.Rendered{Item: menu.Item{
		Label: "Elsewhere", Kind: menu.External,
		Target: "https://example.com/x"}}
	if got := Href(away); got != "https://example.com/x" {
		t.Errorf("an external entry points at %q", got)
	}
}
