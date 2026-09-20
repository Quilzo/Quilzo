// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package search_test

import (
	"testing"

	"github.com/quilzo/quilzo/internal/search"
)

// The queries the judgement set above does not contain.
//
// It scores precision@1 of 1.00 and there was nothing in it to improve. Every
// query in it is two or three words, all of which appear on the page that
// should win — which is what somebody types into a search box on a site they
// already know, and is not what they type when they do not, and is not
// remotely what an agent composes.
//
// The ranker required every term to appear, so one word the page did not
// happen to use emptied the result set. Every query below returned nothing at
// all before the ranker became BM25. An empty result reads to a visitor as
// "this site does not cover that" and to a model as a broken tool — the next
// thing it does is call it again with the same words.
func sentences() []judgement {
	return []judgement{
		{"indigo vat pricing", "indigo",
			"two words about the page and one it does not contain"},
		{"how do I wash dyed cloth", "care",
			"a question, with four words the page does not have"},
		{"shipping times for trade orders", "wholesale",
			"the trade page, asked about in the words a customer uses"},
		{"keeping the vat warm overnight", "indigo",
			"the instruction is on the page; most of these words are not"},
		{"drying cloth out of the light", "care",
			"almost a quotation, with enough around it to break a conjunction"},
	}
}

// measure scores the ranker over a judgement set.
func measure(idx *search.Index, js []judgement) (p1, mrr float64, empty int) {
	for _, j := range js {
		got := idx.Search(j.query, 10)
		if len(got) == 0 {
			empty++
			continue
		}
		if got[0].Page == j.want {
			p1++
		}
		for i, r := range got {
			if r.Page == j.want {
				mrr += 1 / float64(i+1)
				break
			}
		}
	}
	n := float64(len(js))
	return p1 / n, mrr / n, empty
}

// The number this change exists for.
func TestASentenceIsAnswered(t *testing.T) {
	idx := search.Build("c", corpus())
	js := sentences()
	p1, mrr, empty := measure(idx, js)

	t.Logf("over %d sentence queries: precision@1 %.2f  MRR %.2f  %d empty",
		len(js), p1, mrr, empty)

	if empty > 0 {
		t.Errorf("%d of %d sentence queries returned nothing. That is the "+
			"conjunction back, and it is the failure this ranker was changed "+
			"to fix", empty, len(js))
	}
	if p1 < 1.0 {
		t.Errorf("precision@1 over sentence queries is %.2f", p1)
	}
	if mrr < 1.0 {
		t.Errorf("MRR over sentence queries is %.2f", mrr)
	}
}

// And the queries that already worked must still work.
//
// This is the risk in dropping the conjunction, and it is not hypothetical:
// without length normalisation the long page in the corpus wins everything,
// because it contains more of every word. TestALongPageDoesNotOutrankTheRightOne
// is the specific case; this is the whole set.
func TestDroppingTheConjunctionCostsNothing(t *testing.T) {
	idx := search.Build("c", corpus())
	p1, mrr, empty := measure(idx, judgements())
	t.Logf("over the original %d queries: precision@1 %.2f  MRR %.2f  %d empty",
		len(judgements()), p1, mrr, empty)

	if p1 < 1.0 || mrr < 1.0 || empty > 0 {
		t.Errorf("the original judgement set scored precision@1 %.2f, MRR "+
			"%.2f, %d empty. It scored 1.00 and 1.00 under the conjunction, "+
			"so this is a regression rather than a trade", p1, mrr, empty)
	}
}

// A query with nothing in it still returns nothing.
//
// The thing a disjunctive ranker is supposed to get wrong. Without the
// conjunction, a query of nothing but ordinary words has a positive score
// against most of the corpus — and a list of pages that do not answer the
// question is worse than being told the site does not cover it.
func TestAQueryOfOrdinaryWordsStillAnswersNothing(t *testing.T) {
	idx := search.Build("c", corpus())
	for _, q := range []string{
		"zzzznotaword",
		"quarterly revenue projections",
	} {
		if got := idx.Search(q, 10); len(got) > 0 {
			t.Errorf("%q returned %d page(s), starting with %s. None of "+
				"those words is in the corpus", q, len(got), got[0].Page)
		}
	}
}

// Matching every term still beats matching some of them.
//
// The conjunction is gone as a filter and kept as an ordering. A page that
// answers the whole query outranks one that answers part of it however well,
// which is what preserves the precision the conjunction was there for.
func TestMatchingTheWholeQueryOutranksMatchingPartOfIt(t *testing.T) {
	idx := search.Build("c", corpus())
	got := idx.Search("indigo vat", 10)
	if len(got) < 2 {
		t.Skipf("only %d result(s); nothing to compare", len(got))
	}
	if got[0].Matched != 2 {
		t.Fatalf("the top result matched %d of 2 terms", got[0].Matched)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Matched > got[0].Matched {
			t.Fatalf("%s matched %d terms and is below %s, which matched %d",
				got[i].Page, got[i].Matched, got[0].Page, got[0].Matched)
		}
	}
}

// What dropping the conjunction costs, recorded rather than asserted away.
//
// The same treatment TestMorphologyGap gives the "dye"/"dyed" gap: a limit
// that is real, measured, and left visible so that whoever changes the ranker
// next can see what the last change traded.
//
// Requiring every term meant a query nobody could answer returned nothing.
// Scoring a disjunction means it returns the pages that share its ordinary
// words. Three attempts were made at removing that, and each was measured:
//
//	a floor on cosine similarity from the second index
//	    Rejected. On the demo corpus a query of nothing but stopwords scored
//	    0.2536 and a real question scored 0.1097, so the floor would have cut
//	    the question and kept the noise.
//
//	ranking by how many query terms a page matched
//	    Rejected. It puts the About page above the Delivery page for "how long
//	    does delivery take", because About holds "how", "does" and "take".
//
//	dropping terms most of the corpus contains
//	    Kept, and it is not enough on its own: a query made entirely of such
//	    terms has nothing left to drop, and returning its pages is better than
//	    returning none, since somebody searching one common word meant it.
//
// What is left is that an unanswerable question gets an answer-shaped reply.
// It is the price of answering the answerable ones, which previously returned
// nothing at all, and it is worth paying — but it is a price and this says so.
func TestWhatTheDisjunctionCosts(t *testing.T) {
	idx := search.Build("c", corpus())
	for _, q := range []string{
		"the and of it is",
		"what do you use for accounting software",
	} {
		got := idx.Search(q, 10)
		t.Logf("  %-38q returns %d page(s)", q, len(got))
	}
	t.Log("  recorded rather than asserted: an unanswerable query returns " +
		"pages that share its ordinary words, which the conjunction used to " +
		"prevent by returning nothing to every query like it")
}
