// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package find looks for one thing across everything this store holds.
//
// # What was missing
//
// The published site has had search since there was a site: internal/search,
// tf-idf over the pages, no engine. The interface that makes the site had none
// at all. A hundred and thirteen routes, twenty-nine destinations, seventy
// settings, and the only way to reach any of it was to remember which of five
// groups it was in and scroll a list.
//
// So this is not a new capability. It is the index that already existed,
// pointed at the things an author actually has to find.
//
// # Why it is not a query language
//
// CONTRIBUTING.md refuses "features that add a query language over content.
// The absence of one is what removes an entire vulnerability class", and
// internal/listing says the same: "A query language is the thing that
// eventually gets an injection."
//
// A free-text lookup is not one. There is no syntax here — no fields, no
// operators, no negation, no comparison. The input is tokenised into words and
// the words are looked up; a colon, a quote or a bracket is a character in a
// word and means nothing. Anybody wanting a condition over content still has to
// declare a listing, which is the mechanism that exists for it.
//
// # Why the kinds are a closed set
//
// A finder that searches "everything" is a finder whose results depend on what
// happened to be wired into it, and whose permission story is whatever each
// source happens to do. Five kinds, each with a stated reason to be here, and
// each supplied by the caller — which is what lets the caller apply its own
// access rules before anything is searched rather than filtering afterwards.
//
// Forms are deliberately absent even though they are content: a form's
// submissions are what somebody typed into a public page, and `quilzo form` is
// gated separately for that reason. A search that reached them would be a way
// past that gate with a text box in front of it.
package find

import (
	"sort"
	"strings"
	"unicode"

	"github.com/quilzo/quilzo/internal/search"
)

// Kind is what a hit is.
//
// A closed set, like every other vocabulary here: an open one is a string
// somebody types, and a result whose kind the interface does not recognise is
// a row it cannot render.
type Kind string

const (
	// Page is content: a draft or published page, matched on its text.
	Page Kind = "page"
	// Screen is somewhere in the interface. The most common thing somebody is
	// looking for is not a page at all, it is the screen that manages a kind
	// of thing — and "where do I set the language" is a question the
	// navigation answers only if you already know it is under Content.
	Screen Kind = "screen"
	// Setting is one of the configuration keys. Seventy of them, each with a
	// summary written for somebody deciding whether to change it, and no way
	// to search that text until now.
	Setting Kind = "setting"
	// Media is a file in the library, matched on its description. Every file
	// here has one, because the library refuses to store a picture without it
	// — so alternative text is a search index that was already being filled
	// in for another reason.
	Media Kind = "media"
	// Type is a content type, matched on its name and its fields.
	Type Kind = "type"
)

// A Hit is one thing worth showing, and enough to show it.
type Hit struct {
	Kind Kind `json:"kind"`
	// Title is what to call it.
	Title string `json:"title"`
	// Path is where to go. A route for a screen, a page's own address, a media
	// id. Empty means there is nowhere to go, which is true of nothing at
	// present and is worth being able to represent rather than assuming.
	Path string `json:"path,omitempty"`
	// Why says what matched, so a result is never there by magic. internal/
	// search already collects the field names for this reason and the same
	// argument applies to every other kind.
	Why string `json:"why,omitempty"`
	// Score orders within a kind. Not across them — see Search.
	Score float64 `json:"score"`
}

// Sources is what there is to look through.
//
// Supplied by the caller rather than opened here, so the caller applies its own
// access rules first. A finder that opened the store itself would be a second
// answer to "may this person see this", and the second answer is the one that
// is wrong.
type Sources struct {
	// Pages is the page tree to index, in the same shape internal/search
	// takes. Nil searches no pages.
	Pages map[string]any
	// Commit identifies the page set, so the index can be cached by the
	// caller. Empty is fine; it only affects reuse.
	Commit  string
	Screens []Destination
	// Settings are the configuration keys this person may see. The caller
	// filters: a reader has no business finding the token lifetime.
	Settings []Option
	Media    []File
	Types    []ContentType
}

// Destination is a screen in the interface.
type Destination struct {
	Title string
	Path  string
	// Group is which part of the navigation it sits in, shown so a result
	// teaches where the thing lives rather than only taking you there.
	Group string
	// Also are other words somebody might look for it under. "language" for
	// the translations screen, "password" for access — the vocabulary of the
	// person looking rather than of the person who named the screen.
	Also []string
}

// Option is a configuration key.
type Option struct {
	Key     string
	Summary string
}

// File is something in the media library.
type File struct {
	ID  string
	Alt string
}

// ContentType is a declared type and the fields it requires.
type ContentType struct {
	Name   string
	Fields []string
}

// Search returns what matches, best first within each kind.
//
// # Why the ordering is within a kind and not across them
//
// The scores are not comparable. A page's score is tf-idf over a body of prose;
// a screen's is how well a short title matched. Sorting them into one list
// means inventing an exchange rate between the two, and the result is a list
// where a page mentioning "media" in passing outranks the media screen.
//
// So kinds come in a fixed order and each is sorted on its own. Screens first,
// because the most common thing somebody cannot find is a screen, and a screen
// is also the cheapest kind of wrong answer — it costs a click and teaches
// where something lives.
func Search(query string, src Sources, limit int) []Hit {
	terms := search.Tokenise(query)
	if len(terms) == 0 {
		return nil
	}
	if limit <= 0 {
		limit = 20
	}

	var out []Hit
	out = append(out, matchScreens(terms, src.Screens)...)
	out = append(out, matchSettings(terms, src.Settings)...)
	out = append(out, matchTypes(terms, src.Types)...)
	out = append(out, matchPages(query, src)...)
	out = append(out, matchMedia(terms, src.Media)...)

	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// matchScreens scores a destination on its title, group and synonyms.
func matchScreens(terms []string, in []Destination) []Hit {
	var hits []Hit
	for _, d := range in {
		hay := append([]string{d.Title, d.Group, d.Path}, d.Also...)
		n, where := hitsIn(terms, hay)
		if n == 0 {
			continue
		}
		why := "in " + d.Group
		// A match on a synonym is worth saying, because it is the case where
		// the result is not obviously the thing that was asked for.
		if where != "" && !strings.EqualFold(where, d.Title) {
			why += ", matched on " + where
		}
		hits = append(hits, Hit{Kind: Screen, Title: d.Title, Path: d.Path,
			Why: why, Score: float64(n)})
	}
	return ranked(hits)
}

func matchSettings(terms []string, in []Option) []Hit {
	var hits []Hit
	for _, o := range in {
		n, _ := hitsIn(terms, []string{o.Key, o.Summary})
		if n == 0 {
			continue
		}
		hits = append(hits, Hit{Kind: Setting, Title: o.Key, Path: "/settings",
			Why: o.Summary, Score: float64(n)})
	}
	return ranked(hits)
}

func matchTypes(terms []string, in []ContentType) []Hit {
	var hits []Hit
	for _, t := range in {
		n, _ := hitsIn(terms, append([]string{t.Name}, t.Fields...))
		if n == 0 {
			continue
		}
		why := "a content type"
		if len(t.Fields) > 0 {
			why += " with " + strings.Join(shorten(t.Fields, 4), ", ")
		}
		hits = append(hits, Hit{Kind: Type, Title: t.Name, Path: "/types",
			Why: why, Score: float64(n)})
	}
	return ranked(hits)
}

func matchMedia(terms []string, in []File) []Hit {
	var hits []Hit
	for _, f := range in {
		n, _ := hitsIn(terms, []string{f.ID, f.Alt})
		if n == 0 {
			continue
		}
		title := f.Alt
		if strings.TrimSpace(title) == "" {
			title = f.ID
		}
		hits = append(hits, Hit{Kind: Media, Title: title, Path: "/media",
			Why: "in the library", Score: float64(n)})
	}
	return ranked(hits)
}

// matchPages uses the index the site already has.
//
// Built per call rather than cached, because the admin searches the draft and
// the draft changes on every save — an index held across requests would report
// yesterday's content, which is worse than taking a moment to build.
func matchPages(query string, src Sources) []Hit {
	if len(src.Pages) == 0 {
		return nil
	}
	idx := search.Build(src.Commit, src.Pages)
	if idx == nil {
		return nil
	}
	var hits []Hit
	for _, r := range idx.Search(query, 20) {
		title := r.Title
		if strings.TrimSpace(title) == "" {
			title = r.Page
		}
		why := "a page"
		if len(r.Fields) > 0 {
			why = "matched in " + strings.Join(shorten(r.Fields, 3), ", ")
		}
		hits = append(hits, Hit{Kind: Page, Title: title,
			Path: "/page/" + r.Page, Why: why, Score: r.Score})
	}
	return hits // already ordered by the index
}

// hitsIn counts how many terms match any of the haystacks, and returns the
// haystack that matched first.
//
// A term matches when it begins a word. Not an arbitrary substring, and not a
// whole word either.
//
// # Why not a substring
//
// It was one, and searching "pen" returned the setting network.mode — because
// its summary contains "open". That is the failure the page index avoids by
// matching whole words, and the same failure reaches keys and titles by a
// shorter route: these strings are short, so a spurious match is a large
// fraction of a small result list rather than noise at the bottom of a big one.
//
// # Why not a whole word
//
// Because "lang" has to find Languages and "config" has to find
// config.unset. People type the beginning of a word, and a finder that
// insists on the whole of it is one they stop using after the second time it
// finds nothing.
//
// Words are split on anything that is not a letter or a digit, so a dotted key
// (token.api.ttl.default), a path (/languages) and a phrase all break into the
// same kind of pieces.
func hitsIn(terms []string, hay []string) (int, string) {
	n, first := 0, ""
	for _, t := range terms {
		for _, h := range hay {
			if h == "" || !beginsAWord(h, t) {
				continue
			}
			n++
			if first == "" {
				first = h
			}
			break
		}
	}
	return n, first
}

// beginsAWord reports whether term starts a word in s, case-insensitively.
func beginsAWord(s, term string) bool {
	s = strings.ToLower(s)
	atStart := true
	for i, r := range s {
		if !isWordRune(r) {
			atStart = true
			continue
		}
		if atStart && strings.HasPrefix(s[i:], term) {
			return true
		}
		atStart = false
	}
	return false
}

func isWordRune(r rune) bool {
	return r == '\'' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// ranked sorts by score and then by title, so equal scores come out in the
// same order every time.
//
// Stability matters more than it looks: a list that reorders between two
// identical searches makes somebody think the store changed.
func ranked(hits []Hit) []Hit {
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Title < hits[j].Title
	})
	return hits
}

func shorten(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	return append(in[:max:max], "…")
}
