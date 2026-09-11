// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package find

import (
	"strings"
	"testing"
)

func sources() Sources {
	return Sources{
		Commit: "abc123",
		Pages: map[string]any{
			"about": map[string]any{
				"title": "About us",
				"body":  "We make fountain pens in Leeds and have since 1974.",
			},
			"returns": map[string]any{
				"title": "Returns",
				"body":  "Thirty days, unused, and we pay the postage back.",
			},
		},
		Screens: []Destination{
			{Title: "Languages", Path: "/languages", Group: "Content",
				Also: []string{"translation", "locale"}},
			{Title: "Media", Path: "/media", Group: "Content"},
			{Title: "Access", Path: "/access", Group: "Administration",
				Also: []string{"permission", "role"}},
		},
		Settings: []Option{
			{Key: "token.api.ttl.default", Summary: "how long an API token lives"},
			{Key: "api.rate.per_minute", Summary: "requests a caller may make"},
		},
		Media: []File{
			{ID: "aa11", Alt: "A brass fountain pen on a desk"},
			{ID: "bb22", Alt: "The workshop in Leeds"},
		},
		Types: []ContentType{
			{Name: "product", Fields: []string{"price", "sku"}},
		},
	}
}

// The thing somebody is looking for is usually a screen, and a screen is
// findable by the word they would use rather than the word it was named.
func TestAScreenIsFoundByTheWordSomebodyWouldUse(t *testing.T) {
	for query, want := range map[string]string{
		"languages":   "/languages",
		"lang":        "/languages", // a prefix, which is what people type
		"translation": "/languages", // a synonym
		"locale":      "/languages",
		"permission":  "/access",
		"media":       "/media",
	} {
		hits := Search(query, sources(), 10)
		if len(hits) == 0 {
			t.Errorf("%q found nothing", query)
			continue
		}
		var paths []string
		found := false
		for _, h := range hits {
			paths = append(paths, h.Path)
			if h.Kind == Screen && h.Path == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q did not find the %s screen; got %v", query, want, paths)
		}
	}
}

// Screens come before pages.
//
// The scores are not comparable — a page's is tf-idf over prose, a screen's is
// how well a short title matched — so they are not sorted into one list. A
// page that mentions "media" in passing must not outrank the media screen.
func TestAScreenOutranksAPageThatMerelyMentionsIt(t *testing.T) {
	src := sources()
	src.Pages["guide"] = map[string]any{
		"title": "A guide to media",
		"body":  strings.Repeat("media ", 50),
	}

	hits := Search("media", src, 10)
	if len(hits) == 0 {
		t.Fatal("no hits")
	}
	if hits[0].Kind != Screen {
		t.Errorf("the first hit is a %s (%q); a page repeating the word "+
			"fifty times must not outrank the screen that manages it",
			hits[0].Kind, hits[0].Title)
	}
}

// A setting is findable by what it does, not only by its key.
//
// Seventy keys, each with a summary written for somebody deciding whether to
// change it, and no way to search that text until now.
func TestASettingIsFoundByWhatItDoes(t *testing.T) {
	for _, query := range []string{"token", "ttl", "how long an API token lives"} {
		var found bool
		for _, h := range Search(query, sources(), 10) {
			if h.Kind == Setting && h.Title == "token.api.ttl.default" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q did not find token.api.ttl.default", query)
		}
	}
}

// Every result says what matched.
//
// internal/search collects field names so a page is never in a list by magic,
// and the same argument applies to everything else: a result somebody cannot
// account for is a result they do not trust.
func TestEveryResultSaysWhyItIsThere(t *testing.T) {
	for _, query := range []string{"media", "token", "pens", "product", "Leeds"} {
		for _, h := range Search(query, sources(), 20) {
			if strings.TrimSpace(h.Why) == "" {
				t.Errorf("%q returned a %s (%q) with nothing saying why",
					query, h.Kind, h.Title)
			}
			if strings.TrimSpace(h.Title) == "" {
				t.Errorf("%q returned a %s with no title", query, h.Kind)
			}
		}
	}
}

// There is no syntax, and nothing that looks like syntax does anything.
//
// This is the property that keeps it out of what CONTRIBUTING.md refuses: "a
// query language over content. The absence of one is what removes an entire
// vulnerability class." A colon, a quote, a bracket, a minus sign and a star
// are characters in a word here and mean nothing else — so there is no
// expression to inject into, because there is no expression.
func TestNothingThatLooksLikeSyntaxIsSyntax(t *testing.T) {
	src := sources()

	// A field-scoped query in the shape every other CMS accepts finds what the
	// words find, not what the operator would mean.
	scoped := Search("title:media", src, 10)
	plain := Search("title media", src, 10)
	if len(scoped) != len(plain) {
		t.Errorf("`title:media` returned %d hits and `title media` returned "+
			"%d; the colon is doing something", len(scoped), len(plain))
	}

	// Negation is not negation.
	if hits := Search("-media", src, 10); len(hits) == 0 {
		t.Error("`-media` excluded something, so the minus sign is an operator")
	}

	// And none of these is an error, a panic, or a way to reach anything.
	for _, query := range []string{
		`" OR 1=1 --`, `{{ body }}`, `../../etc/passwd`, `*`, `()`,
		`media AND token`, `media|token`, `\x00`, strings.Repeat("a", 5000),
	} {
		for _, h := range Search(query, src, 10) {
			if h.Kind != Page && h.Kind != Screen && h.Kind != Setting &&
				h.Kind != Media && h.Kind != Type {
				t.Errorf("%q produced a hit of kind %q, which is not one of "+
					"the five", query, h.Kind)
			}
		}
	}
}

// An empty or wordless query finds nothing rather than everything.
//
// A blank search that returns the whole store is how somebody accidentally
// renders every page they have.
func TestAWordlessQueryFindsNothing(t *testing.T) {
	for _, query := range []string{"", "   ", "\t\n", "a", "-", "!!!"} {
		if hits := Search(query, sources(), 10); len(hits) != 0 {
			t.Errorf("%q returned %d hits; a query with no words in it should "+
				"return nothing rather than everything", query, len(hits))
		}
	}
}

// The caller decides what may be searched.
//
// Sources is passed in rather than opened here, so access rules are applied
// before anything is looked at. A finder that opened the store itself would be
// a second answer to "may this person see this", and filtering results
// afterwards is how the count of hits leaks what the list contained.
func TestNothingIsFoundInASourceThatWasNotSupplied(t *testing.T) {
	empty := Sources{}
	for _, query := range []string{"media", "token", "pens", "product"} {
		if hits := Search(query, empty, 10); len(hits) != 0 {
			t.Errorf("%q found %d things in an empty Sources", query, len(hits))
		}
	}

	// And a reader given no settings finds no settings, while still finding
	// the pages they may read.
	reader := Sources{Commit: "abc", Pages: sources().Pages}
	for _, h := range Search("token", reader, 10) {
		if h.Kind == Setting {
			t.Errorf("a caller that supplied no settings found one: %q", h.Title)
		}
	}
}

// The same search twice gives the same order.
//
// Map iteration is random in Go, so a finder that ranks straight out of one
// reorders between two identical searches — which makes somebody think the
// store changed underneath them.
func TestTheSameSearchTwiceGivesTheSameOrder(t *testing.T) {
	first := Search("media token pens", sources(), 20)
	for i := 0; i < 20; i++ {
		again := Search("media token pens", sources(), 20)
		if len(again) != len(first) {
			t.Fatalf("run %d returned %d hits, the first returned %d",
				i, len(again), len(first))
		}
		for j := range first {
			if again[j].Title != first[j].Title {
				t.Fatalf("run %d put %q where the first put %q",
					i, again[j].Title, first[j].Title)
			}
		}
	}
}

// The limit is a limit.
func TestTheLimitHolds(t *testing.T) {
	if hits := Search("media token pens product Leeds", sources(), 2); len(hits) > 2 {
		t.Errorf("asked for 2 and got %d", len(hits))
	}
}

// A term matches the start of a word, not any run of letters inside one.
//
// Searching "pen" returned network.mode, because its summary contains "open".
// That is the failure the page index already avoids by matching whole words,
// reaching keys and titles by a shorter route — and it matters more here,
// because these strings are short, so a spurious hit is a large fraction of a
// small list rather than noise at the bottom of a big one.
func TestATermMatchesTheStartOfAWordAndNotTheMiddle(t *testing.T) {
	src := Sources{
		Settings: []Option{
			{Key: "network.mode", Summary: "whether this deployment may reach " +
				"the network: open or offline"},
			{Key: "token.api.ttl.default", Summary: "how long an API token lives"},
		},
		Screens: []Destination{
			{Title: "Languages", Path: "/languages", Group: "Content"},
			{Title: "Start", Path: "/start", Group: "Reference"},
		},
	}

	// Inside a word: no.
	for _, query := range []string{"pen", "art", "oke"} {
		if hits := Search(query, src, 10); len(hits) != 0 {
			t.Errorf("%q matched %d things on a run of letters inside a word: "+
				"%s", query, len(hits), hits[0].Title)
		}
	}

	// The start of a word: yes, because that is what people type.
	for query, want := range map[string]string{
		"lang":  "Languages",
		"langu": "Languages",
		"star":  "Start",
		"token": "token.api.ttl.default",
		"ttl":   "token.api.ttl.default",
		"netw":  "network.mode",
	} {
		hits := Search(query, src, 10)
		found := false
		for _, h := range hits {
			if h.Title == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q did not find %q; people type the beginning of a word",
				query, want)
		}
	}
}
