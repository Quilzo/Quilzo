// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package search

import "testing"

// Folding is judged on three properties, and linguistic correctness is not
// one of them.
//
// What a search needs is that a word finds itself, that a plural finds its
// singular, and that two different words do not become the same word. A stem
// that is not a real word is harmless as long as both ends produce it;
// "canvas" folding to "canva" costs nothing, because the document folds the
// same way and nothing else folds there. A stem that merges "universe" with
// "university" is not harmless, however linguistic it looks.

// The benefit: a plural query finds a singular page and the reverse.
func TestAPluralAndItsSingularAreTheSameWord(t *testing.T) {
	pairs := [][2]string{
		{"shop", "shops"},
		{"order", "orders"},
		{"policy", "policies"},
		{"batch", "batches"},
		{"box", "boxes"},
		{"cloth", "cloths"},
		{"tie", "ties"},
	}
	for _, p := range pairs {
		if fold(p[0]) != fold(p[1]) {
			t.Errorf("%q folds to %q and %q folds to %q; a reader searching "+
				"one will not find the other",
				p[0], fold(p[0]), p[1], fold(p[1]))
		}
	}
}

// The safety property: every word finds itself. This is what makes an
// imperfect stem harmless — both ends fold the same way.
func TestEveryWordStillFindsItself(t *testing.T) {
	words := []string{
		"dress", "status", "analysis", "bias", "canvas", "business",
		"address", "process", "indigo", "wholesale", "shipping", "gas",
	}
	idx := Build("t", map[string]any{})
	_ = idx
	for _, w := range words {
		page := map[string]any{"p": map[string]any{"title": "T", "body": w}}
		if got := Build("t", page).Search(w, 5); len(got) == 0 {
			t.Errorf("a page containing %q is not found by searching %q", w, w)
		}
	}
}

// The failure that would matter: two different words becoming one.
//
// Over-stemming is why this does plurals and not verb forms. A search for
// "universe" that returns the university page is the result nobody can
// explain, and one wrong hit sends somebody away where a miss only sends them
// to the navigation.
func TestDifferentWordsDoNotCollide(t *testing.T) {
	distinct := [][2]string{
		{"universe", "university"},
		{"organ", "organisation"},
		{"policy", "police"},
		{"business", "busy"},
		{"address", "addressed"},
	}
	for _, d := range distinct {
		if fold(d[0]) == fold(d[1]) {
			t.Errorf("%q and %q both fold to %q; a search for one returns the "+
				"other and nobody can explain why", d[0], d[1], fold(d[0]))
		}
	}
}

// Folding is applied at both ends or it is worse than not applying it.
func TestTheIndexAndTheQueryAgree(t *testing.T) {
	idx := Build("t", map[string]any{
		"trade": map[string]any{
			"title": "Trade", "body": "We supply shops and take orders.",
		},
	})
	for _, query := range []string{"shop", "shops", "order", "orders"} {
		if got := idx.Search(query, 5); len(got) == 0 {
			t.Errorf("%q found nothing; the index and the query disagree "+
				"about what a word is", query)
		}
	}
}

// Tokenise keeps its promise. The vector index is built with it, and folding
// there would change something the relevance measurement cannot evaluate.
func TestTokeniseIsUnchangedByFolding(t *testing.T) {
	got := Tokenise("We supply shops and take orders")
	for _, want := range []string{"shops", "orders"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("Tokenise no longer produces %q: %v", want, got)
		}
	}
}
