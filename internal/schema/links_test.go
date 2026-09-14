// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package schema

import "testing"

func linkStore(t *testing.T) (*Store, map[string]any) {
	t.Helper()
	reg := NewRegistry()
	if err := reg.Add(Type{
		Name: "article",
		Fields: []Field{
			{Name: "title", Kind: Text, Required: true},
			{Name: "about", Kind: Reference},
			{Name: "sequel", Kind: Reference},
		},
	}); err != nil {
		t.Fatal(err)
	}
	s := &Store{Registry: reg, Bound: map[string]string{
		"first": "article", "second": "article", "third": "article",
	}}
	pages := map[string]any{
		"first": map[string]any{"title": "One", "about": "third"},
		"second": map[string]any{"title": "Two", "about": "third",
			"sequel": "gone"},
		"third": map[string]any{"title": "Three"},
	}
	return s, pages
}

// What points at this page, which nothing could answer.
//
// Unresolved has walked every reference field since references existed and
// reported only the ones naming nothing — so the same walk knew the whole
// answer and threw half of it away. There was no way to ask from the editor,
// from the delete screen, or from the command line; the first anybody heard
// about a reference was a refused publish naming a page they had already
// changed.
func TestLinksToFindsWhatPointsAtAPage(t *testing.T) {
	s, pages := linkStore(t)

	in := s.LinksTo(pages, "third")
	if len(in) != 2 {
		t.Fatalf("%d page(s) point at third, want 2: %+v", len(in), in)
	}
	if in[0].From != "first" || in[0].Field != "about" {
		t.Errorf("first link is %+v", in[0])
	}
	if !in[0].Resolves {
		t.Error("a link to a page that is there is reported as not resolving")
	}
	// Sorted, because this is printed and shown and a list that shuffles
	// between runs is one nobody can diff.
	if in[1].From != "second" {
		t.Errorf("the answer is not in a stable order: %+v", in)
	}

	if none := s.LinksTo(pages, "first"); len(none) != 0 {
		t.Errorf("nothing points at first, but %d thing(s) were found", len(none))
	}
}

// A link to nothing is reported rather than dropped: it is the one worth
// knowing about, and Unresolved only says so at publish.
func TestALinkToNothingIsStillALink(t *testing.T) {
	s, pages := linkStore(t)

	for _, l := range s.Links(pages) {
		if l.To != "gone" {
			continue
		}
		if l.Resolves {
			t.Error("a link to a page that is not there says it resolves")
		}
		if l.From != "second" || l.Field != "sequel" {
			t.Errorf("the dangling link does not say where it is: %+v", l)
		}
		return
	}
	t.Error("the link to a page that does not exist was dropped, so the " +
		"only way to hear about it is a refused publish")
}

// The index is of the set it was given, not of the store.
//
// Asking about a draft answers about the draft and asking about live answers
// about live, which is the distinction somebody deciding whether a rename is
// safe actually needs.
func TestLinksAnswersAboutTheSetItWasGiven(t *testing.T) {
	s, pages := linkStore(t)

	// The same pages, without the target. Every link to it now dangles.
	delete(pages, "third")
	for _, l := range s.LinksTo(pages, "third") {
		if l.Resolves {
			t.Errorf("a link to a page absent from this set says it "+
				"resolves: %+v", l)
		}
	}
}

// An untyped page has no reference fields to read, and that is not an error.
func TestAPageWithNoTypeContributesNoLinks(t *testing.T) {
	s, pages := linkStore(t)
	pages["loose"] = map[string]any{"title": "Untyped", "about": "third"}

	for _, l := range s.Links(pages) {
		if l.From == "loose" {
			t.Error("a page with no type declared a reference; nothing " +
				"knows that its `about` is a reference rather than a word")
		}
	}
}
