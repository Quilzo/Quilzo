// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package schema

import "sort"

// Which pages name which, and — the half that was missing — which pages name
// this one.
//
// # The gap
//
// A reference field has been resolvable in one direction since it existed:
// Unresolved walks every page's reference fields and reports the ones naming
// something that is not being published. That walk already knows the whole
// answer and threw half of it away.
//
// So there was no way to ask "what points at this page". Not from the editor,
// where somebody is about to rewrite it; not from the delete screen, which
// checks the menus for exactly this reason and not the references; and not
// from the command line at all. The first anybody heard about a reference was
// a refused publish naming a page they had already changed.
//
// internal/menu has had both directions for as long as it has had links —
// Mentioning and Retarget — because a navigation entry pointing at nothing is
// "a 404 every reader finds before anybody here does". A content reference
// pointing at nothing is the same sentence, and it only had the half that
// says no.
//
// # Still nothing is followed
//
// This is Unresolved's walk with the answer kept, and it inherits that
// function's rule: a name is looked up in the map it was given. Nothing is
// fetched, a chain is not a traversal, and the index is of the set handed in
// rather than of the store — so asking about a draft answers about the draft
// and asking about live answers about live, which is the distinction somebody
// deciding whether a rename is safe actually needs.

// A Link is one page naming another through a reference field.
type Link struct {
	// From is the page that carries the reference.
	From string
	// Field is which of its fields holds it, so a person reading the answer
	// knows where to go and not only that they have to look.
	Field string
	// To is the page named. It may not exist: a link to nothing is the thing
	// worth knowing about, so it is reported rather than dropped.
	To string
	// Resolves says whether To is in the set this was built from.
	Resolves bool
}

// Links is every reference in a set of pages, sorted by source then field.
//
// Deterministic order, because this is shown on a screen and printed by a
// command, and a list that shuffles between runs is one nobody can diff.
func (s *Store) Links(pages map[string]any) []Link {
	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []Link
	for _, name := range names {
		out = append(out, s.linksFrom(name, pages)...)
	}
	return out
}

// LinksTo is every reference that names target.
//
// The whole set is walked rather than an index kept, because the set is the
// draft and the draft changes under this on every save. A cache of the answer
// would need invalidating by everything that writes a page, which is the
// shape of bug this package exists to avoid rather than to acquire.
func (s *Store) LinksTo(pages map[string]any, target string) []Link {
	var out []Link
	for _, l := range s.Links(pages) {
		if l.To == target {
			out = append(out, l)
		}
	}
	return out
}

// linksFrom reads one page's reference fields.
func (s *Store) linksFrom(page string, pages map[string]any) []Link {
	typeName, bound := s.Bound[page]
	if !bound || s.Registry == nil {
		return nil
	}
	t, ok := s.Registry.Get(typeName)
	if !ok {
		return nil
	}
	body, ok := pages[page].(map[string]any)
	if !ok {
		return nil
	}

	var out []Link
	for _, f := range t.Fields {
		if f.Kind != Reference {
			continue
		}
		target, ok := body[f.Name].(string)
		if !ok || target == "" {
			continue
		}
		_, exists := pages[target]
		out = append(out, Link{
			From: page, Field: f.Name, To: target, Resolves: exists,
		})
	}
	return out
}

// Retarget rewrites every reference naming one page to name another.
//
// The other half internal/menu has had for as long as it has had links. A
// rename without it breaks every page that named the old one, and the first
// anybody hears is the publish gate refusing — naming pages somebody changed
// for unrelated reasons, after the edit is already saved.
//
// The pages are edited in place, because the caller is holding a set it is
// about to write and copying it here would leave them wondering which copy is
// the one that counts. The names of the pages that changed come back, so the
// caller can say what it did rather than that it did something.
func (s *Store) Retarget(pages map[string]any, from, to string) []string {
	var changed []string
	for _, l := range s.LinksTo(pages, from) {
		body, ok := pages[l.From].(map[string]any)
		if !ok {
			continue
		}
		body[l.Field] = to
		changed = append(changed, l.From)
	}
	sort.Strings(changed)
	return dedupe(changed)
}

// dedupe collapses a page that named the target twice.
func dedupe(names []string) []string {
	out := names[:0]
	var last string
	for i, n := range names {
		if i > 0 && n == last {
			continue
		}
		out = append(out, n)
		last = n
	}
	return out
}
