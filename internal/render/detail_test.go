package render

import "testing"

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
