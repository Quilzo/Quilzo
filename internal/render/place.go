// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package render

import "github.com/quilzo/quilzo/internal/listing"

// Where a listing goes on the page.
//
// # What was missing
//
// Inline databases worked. A page could name listings, the queries resolved,
// the rows arrived, and every one of them rendered in a block after the last
// section — in alphabetical order, because that is the only order a map has.
// What no page could say was *here*: between the intro and the pricing, once,
// as three cards. Position is the whole of what a page builder is for, and it
// was the one thing the feature could not express.
//
// # Why the join happens in Go
//
// Because the template language cannot do it. A section carries the name of a
// listing, and the resolved rows live under that name in a map — so rendering
// it in place needs listings[s.listing.name], and there is no dynamic key
// lookup in this language, deliberately: a path that can be computed is a path
// an attacker can aim. The same reason rules out matching by comparison, since
// the language has no way to compare two values either.
//
// So the renderer does the join, once, and the section arrives at the template
// already carrying its rows. That is the same argument as every other derived
// companion in derive.go: compute in Go what the language cannot express, in
// one place, so the public site, the preview, the gate and the export cannot
// disagree about it.
//
// # Why a placed listing leaves the trailing block
//
// A page that positions a listing has said where it wants it. Leaving it in
// the appended arrangement as well would render the same rows twice — once
// where the author put them and once at the bottom — which is not a layout
// anybody asked for and is exactly what a first attempt produces.

// placeListings fills every listing section with the rows it names and returns
// the feeds that were not placed, for the trailing block.
//
// Sections are filled whether or not a feed was found. A section naming
// nothing — the stub, before somebody types a name — then renders as an empty
// listing rather than as a section with no marks on it at all, which is the
// same thing a listing matching no records shows.
func placeListings(page any, feeds []any) []any {
	sections := listing.Sections(page)
	if len(sections) == 0 {
		return feeds
	}

	byName := make(map[string]map[string]any, len(feeds))
	for _, f := range feeds {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name != "" {
			byName[name] = m
		}
	}

	placed := map[string]bool{}
	for _, sec := range sections {
		name, _ := sec["name"].(string)
		feed := byName[name]
		fillListingSection(sec, feed)
		if feed != nil {
			// Two sections may name one listing, and both get the rows. Only
			// the name is marked, so the feed is dropped from the trailing
			// block once rather than once per section.
			placed[name] = true
		}
	}

	kept := make([]any, 0, len(feeds))
	for _, f := range feeds {
		m, ok := f.(map[string]any)
		if !ok {
			kept = append(kept, f)
			continue
		}
		if name, _ := m["name"].(string); placed[name] {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// fillListingSection writes one resolved listing into the section that named it.
func fillListingSection(sec map[string]any, feed map[string]any) {
	var rows []any
	if feed != nil {
		rows, _ = feed["rows"].([]any)
	}
	if rows == nil {
		rows = []any{}
	}
	// Set, not setIfAbsent. These are facts about this render, and a page
	// carrying its own "rows" beside a listing name is a page somebody built
	// by hand and then pointed at a query; the query is the more recent
	// statement of what belongs there.
	sec["rows"] = rows
	sec["count"] = float64(len(rows))
	sec["empty"] = len(rows) == 0

	// The section's own heading wins, because it is the more specific one: a
	// page may want "What's new" over a listing the site calls "recent".
	if feed != nil {
		if t, ok := feed["title"].(string); ok && t != "" {
			setIfAbsent(sec, "title", t)
		}
	}

	// The language has no way to compare two values, so the choice of view
	// arrives as the booleans a template can test. Cards unless the page asks
	// for the other, and cards for a value nothing implements — an unknown
	// view renders as the ordinary one rather than as nothing at all.
	view, _ := sec["view"].(string)
	sec["view_list"] = view == "list"
	sec["view_cards"] = view != "list"
}
