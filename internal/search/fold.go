package search

import "strings"

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
	out := Tokenise(text)
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
