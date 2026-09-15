// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package render

import "testing"

// pageWith builds a page body carrying listing sections with these names.
func pageWith(names ...string) map[string]any {
	secs := make([]any, 0, len(names)+1)
	secs = append(secs, map[string]any{"prose": map[string]any{"title": "Words"}})
	for _, n := range names {
		secs = append(secs, map[string]any{
			"listing": map[string]any{"name": n, "title": "Heading for " + n},
		})
	}
	return map[string]any{"title": "A page", "sections": secs}
}

func feed(name string, rows ...string) map[string]any {
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{"name": r})
	}
	return map[string]any{"name": name, "title": name, "rows": out}
}

// A listing named by a section is rendered there and not again at the end.
//
// The first attempt at this feature renders the rows twice: once where the
// author put them and once in the trailing block, which still holds every
// listing the page resolved. That is not a layout anybody asked for, and it is
// invisible in a unit test that only looks at the section.
func TestAPositionedListingLeavesTheTrailingBlock(t *testing.T) {
	page := pageWith("recent")
	rest := placeListings(page, []any{
		feed("recent", "one", "two"),
		feed("other", "three"),
	})

	if len(rest) != 1 {
		t.Fatalf("%d feed(s) left for the trailing block, want 1", len(rest))
	}
	if name, _ := rest[0].(map[string]any)["name"].(string); name != "other" {
		t.Errorf("the trailing block kept %q; the positioned one should have "+
			"gone and the unpositioned one stayed", name)
	}

	sec := listingSection(t, page, 0)
	rows, _ := sec["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("the section holds %d row(s), want 2", len(rows))
	}
	if sec["empty"] != false || sec["count"] != float64(2) {
		t.Errorf("the section says empty=%v count=%v", sec["empty"], sec["count"])
	}
}

// Two sections may name one listing, and both show it.
//
// The same rows in two places is a thing a page may legitimately want — a
// summary at the top and the whole thing lower down — and the bookkeeping that
// drops a feed from the trailing block must not drop it from the second
// section on the way.
func TestTwoSectionsMayNameOneListing(t *testing.T) {
	page := pageWith("recent", "recent")
	rest := placeListings(page, []any{feed("recent", "one")})
	if len(rest) != 0 {
		t.Errorf("%d feed(s) left over", len(rest))
	}
	for i := 0; i < 2; i++ {
		sec := listingSection(t, page, i)
		if rows, _ := sec["rows"].([]any); len(rows) != 1 {
			t.Errorf("section %d holds %d row(s), want 1", i, len(rows))
		}
	}
}

// A section naming nothing is an empty listing, not a missing one.
//
// This is the stub, straight off the button, before anybody has typed a name.
// Without the rows key the template's loop and its empty state are both
// false, and the section renders as a heading over nothing at all — which
// reads as a broken page rather than as a listing with no rows in it.
func TestASectionNamingNothingIsEmpty(t *testing.T) {
	page := map[string]any{"sections": []any{
		map[string]any{"listing": map[string]any{"title": "Recent", "name": ""}},
	}}
	if rest := placeListings(page, nil); len(rest) != 0 {
		t.Errorf("%d feed(s) came from nowhere", len(rest))
	}
	sec := listingSection(t, page, 0)
	if sec["empty"] != true {
		t.Errorf("empty is %v, want true", sec["empty"])
	}
	if rows, ok := sec["rows"].([]any); !ok || len(rows) != 0 {
		t.Errorf("rows is %#v, want an empty list", sec["rows"])
	}
}

// The view arrives as booleans, because the language cannot compare values.
//
// And an unknown view is the ordinary one. A page whose view field holds a
// typo should render as cards, not as a section with nothing inside it: the
// failure of a presentation choice must not cost the content.
func TestTheViewArrivesAsBooleans(t *testing.T) {
	for _, tc := range []struct {
		view        string
		cards, list bool
	}{
		{"", true, false},
		{"cards", true, false},
		{"list", false, true},
		{"cardz", true, false},
	} {
		page := map[string]any{"sections": []any{
			map[string]any{"listing": map[string]any{"name": "", "view": tc.view}},
		}}
		placeListings(page, nil)
		sec := listingSection(t, page, 0)
		if sec["view_cards"] != tc.cards || sec["view_list"] != tc.list {
			t.Errorf("view %q gave cards=%v list=%v, want %v and %v",
				tc.view, sec["view_cards"], sec["view_list"], tc.cards, tc.list)
		}
	}
}

// The section's own heading wins over the listing's label.
//
// A page may want "What's new" over a listing the site calls "recent", and the
// page is the more specific statement.
func TestTheSectionsOwnHeadingWins(t *testing.T) {
	page := pageWith("recent")
	placeListings(page, []any{feed("recent", "one")})
	if got := listingSection(t, page, 0)["title"]; got != "Heading for recent" {
		t.Errorf("the heading is %q; the listing's label overwrote the page's", got)
	}
}

// A page with no listing section is left exactly as it was.
func TestAPageWithNoListingSectionKeepsEveryFeed(t *testing.T) {
	page := map[string]any{"sections": []any{
		map[string]any{"prose": map[string]any{"title": "Words"}},
	}}
	rest := placeListings(page, []any{feed("recent", "one"), feed("other")})
	if len(rest) != 2 {
		t.Errorf("%d feed(s) survived, want 2", len(rest))
	}
}

// listingSection returns the nth listing section of a page body.
func listingSection(t *testing.T, page map[string]any, n int) map[string]any {
	t.Helper()
	secs, _ := page["sections"].([]any)
	seen := 0
	for _, item := range secs {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		inner, ok := m["listing"].(map[string]any)
		if !ok {
			continue
		}
		if seen == n {
			return inner
		}
		seen++
	}
	t.Fatalf("there is no listing section %d", n)
	return nil
}
