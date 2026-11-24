// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"strings"
	"unicode"
)

// Folding a plural onto its singular, and nothing more ambitious than that.
//
// # The measurement that justifies this
//
// search.go declines to tune relevance, because "fine-grained relevance tuning
// is what a search engine is for, and pretending to it here would be a knob
// nobody can evaluate". That is a fair objection to a knob. It stopped being
// an objection when there was something to evaluate against: see
// relevance_test.go, which is a corpus, a set of queries with a known right
// answer, and two numbers.
//
// What that measurement found is not a ranking problem. Ranking is already
// good — precision@1 of 1.00 on the judgement set — and the length bias that
// BM25 exists to correct does not appear here, because repetition saturates
// below what a title match is worth. What it found is a matching problem:
// somebody searching "shop" is not shown the page that says "shops", because
// those are different words to a tokeniser that does no morphology.
//
// # Why only plurals
//
// A full stemmer would fold "dyed" onto "dye" as well, and would also fold
// "university" and "universe" onto the same token, which is the classic
// over-stemming failure and produces results nobody can explain. Plural
// folding is the conservative subset: it is nearly all of the benefit for a
// site search, where the mismatch is almost always singular against plural,
// and it introduces very few conflations.
//
// It is deliberately not complete. "dye" still does not find "dyed", and the
// measurement says so rather than implying otherwise: this closes the common
// case and leaves the rest visible.

// indexTerms is Tokenise with folding applied: the form a term is indexed and
// searched under.
//
// Separate from Tokenise, which keeps its promise to produce whole words.
// That promise has other callers — the vector index is built with it — and
// folding there would change something this measurement cannot evaluate.
// Folding is a retrieval decision and belongs to retrieval.
//
// Applied at both ends, so the index and the query agree by construction
// rather than by two functions being kept in step.
func indexTerms(text string) []string {
	out := Tokenise(FoldLetters(text))
	for i, t := range out {
		out[i] = fold(t)
	}
	return out
}

// fold returns the singular form of a plural, or the term unchanged.
func fold(term string) string {
	// Short words are left alone. "gas" is not a plural, "is" is not a plural,
	// and the shorter the word the likelier a suffix rule is to be wrong
	// about it.
	if len(term) < 4 {
		return term
	}
	switch {
	case strings.HasSuffix(term, "ies") && len(term) > 4:
		// "policies" -> "policy". Not "ties", which is why the length guard
		// is above the rule rather than inside it.
		return term[:len(term)-3] + "y"
	case strings.HasSuffix(term, "sses"), strings.HasSuffix(term, "shes"),
		strings.HasSuffix(term, "ches"), strings.HasSuffix(term, "xes"):
		// "dresses", "washes", "batches", "boxes".
		return term[:len(term)-2]
	case strings.HasSuffix(term, "ss"), strings.HasSuffix(term, "us"),
		strings.HasSuffix(term, "is"):
		// Not plurals: "dress", "status", "analysis". Left alone, because
		// folding them produces a token no document contains.
		return term
	case strings.HasSuffix(term, "s"):
		return term[:len(term)-1]
	}
	return term
}

// FoldLetters is text in lower case with the marks taken off its letters,
// for matching a word however it was typed: "Çılbır", "ÇILBIR" and "cilbir"
// are one word to it.
//
// # Why not strings.ToLower
//
// Lowering alone is case-insensitive for every language but the one whose
// capital I is not the capital of i. Turkish has a dotted and a dotless i,
// and I lowers to i, never to ı, so a Turkish heading typed in capitals,
// as headings there often are, never met the same word in lower case:
// HAKKINDA did not find "Hakkında". And a word typed without its marks, on a
// keyboard that has none, did not find the word with them. So the i's are
// one letter here and a letter's marks are dropped, at both ends of a
// search, as the site's own addresses already drop them.
//
// The standard library has no decomposition tables, so the marks are taken
// off by a table of the Latin letters that carry them, and a combining mark
// written separately is dropped. A letter outside the table is only lowered.
// Over-folding is the risk this accepts, and it is small: two words that
// differ only by a mark are rarely two different things somebody is looking
// for on one site.
//
// Applied to the text before it is split into words, so a mark written as
// its own character does not split the word it belongs to.
func FoldLetters(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x80 {
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		r = unicode.ToLower(r)
		if to, ok := unmarked[r]; ok {
			b.WriteString(to)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// unmarked is each lower-case Latin letter with a mark, as the letter
// without it.
var unmarked = func() map[rune]string {
	m := map[rune]string{'æ': "ae", 'œ': "oe", 'ß': "ss"}
	for base, marked := range map[string]string{
		"a": "àáâãäåāăą", "c": "çćĉċč", "d": "ďđ", "e": "èéêëēĕėęě",
		"g": "ĝğġģ", "h": "ĥħ", "i": "ìíîïĩīĭįı", "j": "ĵ", "k": "ķ",
		"l": "ĺļľŀł", "n": "ñńņň", "o": "òóôõöøōŏő", "r": "ŕŗř",
		"s": "śŝşšș", "t": "ţťŧț", "u": "ùúûüũūŭůűų", "w": "ŵ",
		"y": "ýÿŷ", "z": "źżž",
	} {
		for _, r := range marked {
			m[r] = base
		}
	}
	return m
}()
