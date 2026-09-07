// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package search_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/search"
)

// Measuring the ranker instead of arguing about it.
//
// search.go declines to tune relevance, on the grounds that fine-grained
// tuning "is what a search engine is for, and pretending to it here would be a
// knob nobody can evaluate". That is a fair objection to a knob and not to a
// measurement, and this is the measurement: a small corpus, a set of queries
// with a known right answer, and two numbers.
//
// Precision@1 is the one that matters for a site search. Somebody types two
// words and looks at the first result; if it is wrong they do not scroll, they
// leave. Mean reciprocal rank is reported alongside because it distinguishes
// "wrong and nearby" from "wrong and nowhere", which is the difference between
// a ranking problem and a matching one.
//
// The corpus is deliberately awkward in the way real sites are: a short page
// that is exactly about a thing, and a long page that mentions it repeatedly
// in passing.

// judgement is a query and the page that should win it.
type judgement struct {
	query string
	want  string
	why   string
}

func corpus() map[string]any {
	// A long page that mentions dyeing constantly without being the page about
	// dye. This is the shape that defeats a ranker with no length
	// normalisation: it has more occurrences of everything.
	journal := strings.Repeat(
		"We dyed a batch this week and the indigo vat was sluggish. "+
			"Dyeing in winter is slow. The dye takes longer to strike. "+
			"More notes on dyeing follow, and on the vat, and the indigo. ", 40)

	return map[string]any{
		"indigo": map[string]any{
			"title": "Indigo", "standfirst": "The vat, and how to keep it",
			"body": "An indigo vat is a living thing. Feed it, keep it warm.",
		},
		"journal": map[string]any{
			"title": "Journal", "standfirst": "Notes from the studio",
			"body": journal,
		},
		"shipping": map[string]any{
			"title": "Shipping", "standfirst": "How orders reach you",
			"body": "Orders leave within three days. Shipping is by post.",
		},
		"wholesale": map[string]any{
			"title": "Wholesale", "standfirst": "Trade orders and terms",
			"body": "Wholesale terms for shops. Minimum order, and shipping.",
		},
		"care": map[string]any{
			"title":      "Caring for dyed cloth",
			"standfirst": "Washing, drying and light",
			"body":       "Wash dyed cloth cold. Dry it out of direct light.",
		},
	}
}

func judgements() []judgement {
	return []judgement{
		{"indigo", "indigo", "the page about indigo, not the journal that mentions it"},
		{"indigo vat", "indigo", "both words, and the page is about them"},
		{"shipping", "shipping", "an exact title match"},
		{"wholesale terms", "wholesale", "both words in the standfirst"},
		{"dyed cloth", "care", "the page whose title is those words"},
		{"washing", "care", "a body-only match with one candidate"},
	}
}

// score runs the judgement set and returns precision@1 and MRR.
func score(t *testing.T, idx *search.Index) (float64, float64, []string) {
	t.Helper()
	js := judgements()
	hits, rr := 0.0, 0.0
	var misses []string

	for _, j := range js {
		results := idx.Search(j.query, 10)
		rank := 0
		for i, r := range results {
			if r.Page == j.want {
				rank = i + 1
				break
			}
		}
		switch {
		case rank == 1:
			hits++
			rr += 1
		case rank > 1:
			rr += 1 / float64(rank)
			misses = append(misses, fmt.Sprintf(
				"%-16q wanted %-10s got %-10s at rank %d — %s",
				j.query, j.want, first(results), rank, j.why))
		default:
			misses = append(misses, fmt.Sprintf(
				"%-16q wanted %-10s and it was not returned at all — %s",
				j.query, j.want, j.why))
		}
	}
	return hits / float64(len(js)), rr / float64(len(js)), misses
}

func first(rs []search.Result) string {
	if len(rs) == 0 {
		return "nothing"
	}
	return rs[0].Page
}

// The measurement. Not a pass/fail on a number somebody chose — a floor, so a
// change that makes ranking worse fails rather than being noticed later by a
// reader who left.
func TestRankingQuality(t *testing.T) {
	idx := search.Build("test", corpus())
	p1, mrr, misses := score(t, idx)

	t.Logf("precision@1 %.2f   MRR %.2f   over %d queries",
		p1, mrr, len(judgements()))
	for _, m := range misses {
		t.Logf("  %s", m)
	}

	if p1 < 0.80 {
		t.Errorf("precision@1 is %.2f. Somebody types two words and looks at "+
			"the first result; if it is wrong they do not scroll.", p1)
	}
	if mrr < 0.85 {
		t.Errorf("MRR is %.2f, so the right page is often not near the top", mrr)
	}
}

// The hypothesis that turned out to be wrong, kept because the answer is
// worth having written down.
//
// A ranker without document-length normalisation rewards long pages: they
// contain more occurrences of everything, so a page mentioning a term forty
// times in passing can outrank the page that is about it. That is BM25's main
// addition over plain TF-IDF, and it is the obvious thing to reach for here.
//
// It does not happen, and the measurement says why. Repetition saturates at
// 1 + n/(n+3), which cannot exceed 2 however many times a word appears, while
// a title match is worth 8. The field weights and the saturating term
// frequency together already do the work length normalisation would do, so
// adding it would be a knob with nothing to gain — which is what search.go
// says about knobs.
func TestALongPageDoesNotOutrankTheRightOne(t *testing.T) {
	idx := search.Build("test", corpus())

	// Terms that genuinely appear on both the long page and the right one.
	for _, query := range []string{"indigo", "dyed", "vat"} {
		results := idx.Search(query, 5)
		if len(results) == 0 {
			continue
		}
		if results[0].Page == "journal" {
			t.Errorf("%q ranks the long journal first, above the page that is "+
				"actually about it. That is the length bias document-length "+
				"normalisation exists to correct.", query)
			for i, r := range results {
				t.Logf("    %d. %-10s score %.2f matched %d",
					i+1, r.Page, r.Score, r.Matched)
			}
		}
	}
}

// What the measurement did find: a reader searching "dye" is not shown the
// page titled "Caring for dyed cloth".
//
// The tokeniser does no morphology, so "dye" and "dyed" are different words,
// and a query in one form misses a page written in the other. That is not a
// ranking problem — the page is not in the results at all — and it is the
// commonest way a small site search disappoints somebody: they searched for
// the singular and the page says the plural.
func TestMorphologyGap(t *testing.T) {
	idx := search.Build("test", corpus())

	type miss struct{ query, want string }
	for _, m := range []miss{
		{"dye", "care"},        // page says "dyed"
		{"order", "wholesale"}, // page says "orders"
		{"shop", "wholesale"},  // page says "shops"
	} {
		found := false
		for _, r := range idx.Search(m.query, 10) {
			if r.Page == m.want {
				found = true
			}
		}
		if !found {
			t.Logf("  %-8q does not return %-10s (the page uses another form "+
				"of the word)", m.query, m.want)
		}
	}
	t.Log("  recorded rather than asserted: whether to fold these together is " +
		"a decision about false matches, not only missed ones")
}
