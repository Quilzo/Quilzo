package search

import (
	"encoding/json"
	"strings"
	"testing"
)

func site() map[string]any {
	return map[string]any{
		"index": map[string]any{
			"title": "Home", "body": "Welcome to the company site.",
		},
		"pricing": map[string]any{
			"title": "Pricing", "slug": "pricing",
			"body": "Our pricing is simple. Pricing starts at ten pounds.",
		},
		"faq": map[string]any{
			"title": "Frequently asked questions",
			"body": "People ask about pricing, about delivery, and about " +
				"returns. Pricing is covered on its own page.",
		},
		"about": map[string]any{
			"title": "About us", "body": "We make things carefully.",
			"tags": []any{"company", "team"},
		},
	}
}

func TestFindsThePageSomebodyWanted(t *testing.T) {
	idx := Build("abc", site())
	results := idx.Search("pricing", 10)

	if len(results) == 0 {
		t.Fatal("no results for a word that appears on two pages")
	}
	// The pricing page, not the FAQ that mentions it. That is the whole
	// difference between a search box people use and one they stop using.
	if results[0].Page != "pricing" {
		t.Errorf("the top result is %q, not the pricing page. Results: %#v",
			results[0].Page, results)
	}
}

// A title match is worth more than a body match, because somebody searching for
// a page name wants that page.
func TestATitleMatchOutranksABodyMatch(t *testing.T) {
	idx := Build("abc", map[string]any{
		"a": map[string]any{"title": "Delivery", "body": "How things arrive."},
		"b": map[string]any{"title": "Other", "body": "delivery delivery delivery delivery"},
	})
	results := idx.Search("delivery", 10)
	if len(results) != 2 {
		t.Fatalf("got %d results", len(results))
	}
	if results[0].Page != "a" {
		t.Errorf("a page repeating the word in its body outranked the page "+
			"named after it: %#v", results)
	}
}

// An "any term" search on a two-word query returns most of the site and buries
// the page somebody wanted.
func TestEveryTermMustAppear(t *testing.T) {
	idx := Build("abc", site())

	both := idx.Search("pricing delivery", 10)
	for _, r := range both {
		if r.Page != "faq" {
			t.Errorf("%q matched a two-word query it does not fully contain",
				r.Page)
		}
	}
	if len(both) != 1 {
		t.Errorf("got %d results for a query only one page contains: %#v",
			len(both), both)
	}

	// A term nothing has means no results, not everything.
	if got := idx.Search("pricing xyzzy", 10); len(got) != 0 {
		t.Errorf("a query containing an unknown word returned %d results", len(got))
	}
}

// A word appearing on every page says nothing about which page is wanted.
// Without this the ranking is a word count.
func TestCommonWordsDoNotDominate(t *testing.T) {
	pages := map[string]any{}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		pages[n] = map[string]any{
			"title": "Page " + n,
			"body":  "the company the company the company",
		}
	}
	pages["target"] = map[string]any{
		"title": "Page target",
		"body":  "the company sells widgets",
	}

	idx := Build("abc", pages)
	results := idx.Search("widgets", 10)
	if len(results) != 1 || results[0].Page != "target" {
		t.Errorf("a rare word did not isolate its page: %#v", results)
	}

	// And a term on every page still returns them, just without ranking noise.
	if got := idx.Search("company", 10); len(got) != 6 {
		t.Errorf("a common term returned %d of 6 pages", len(got))
	}
}

// The tenth occurrence of a word says much less than the second, and without
// diminishing returns a page that repeats a term wins every time.
func TestRepetitionHasDiminishingReturns(t *testing.T) {
	idx := Build("abc", map[string]any{
		"spam": map[string]any{
			"title": "Other",
			"body":  strings.Repeat("widgets ", 200),
		},
		"real": map[string]any{
			"title": "Widgets", "body": "We sell widgets.",
		},
	})
	results := idx.Search("widgets", 10)
	if results[0].Page != "real" {
		t.Errorf("two hundred repetitions outranked the page named after the "+
			"word: %#v", results)
	}
}

// -- tokenising --------------------------------------------------------------

func TestTokenisingKeepsWordsWhole(t *testing.T) {
	got := Tokenise("Don't split contractions; do split hyphen-words. Numbers: 2026.")
	want := map[string]bool{
		"dont": true, "split": true, "contractions": true, "do": true,
		"hyphen": true, "words": true, "numbers": true, "2026": true,
	}
	// A set comparison, not a length one: the tokeniser returns positional
	// tokens, so a word appearing twice appears twice. That is the point —
	// the index needs occurrence counts, and deduplicating here would throw
	// away the signal the ranker uses.
	seen := map[string]bool{}
	for _, term := range got {
		if !want[term] {
			t.Errorf("unexpected term %q from %v", term, got)
		}
		seen[term] = true
	}
	for term := range want {
		if !seen[term] {
			t.Errorf("%q was not produced; got %v", term, got)
		}
	}
}

// Sites here can be in more than one language, and an English stemmer applied
// to German produces confident nonsense — so there is no stemmer, and the
// tokeniser has to at least not mangle non-Latin text.
func TestNonLatinTextIsTokenised(t *testing.T) {
	for _, text := range []string{
		"Über uns", "关于我们", "من نحن", "Ελληνικά",
	} {
		if got := Tokenise(text); len(got) == 0 {
			t.Errorf("%q produced no terms", text)
		}
	}
	// And case folding must work beyond ASCII.
	if got := Tokenise("ÜBER"); len(got) != 1 || got[0] != "über" {
		t.Errorf("case folding failed: %v", got)
	}
}

// -- bounds ------------------------------------------------------------------

// Without a limit, one enormous page decides how much memory the index takes,
// and whoever wrote that page did not know they were making that decision.
func TestOneHugePageCannotDominateTheIndex(t *testing.T) {
	var huge strings.Builder
	for i := range 200000 {
		huge.WriteString("word")
		huge.WriteString(string(rune('a' + i%26)))
		huge.WriteByte(' ')
	}
	idx := Build("abc", map[string]any{
		"huge": map[string]any{"title": "Huge", "body": huge.String()},
	})
	total := 0
	for _, postings := range idx.Terms {
		total += len(postings)
	}
	if total > MaxTermsPerPage+100 {
		t.Errorf("one page produced %d postings, past the %d limit",
			total, MaxTermsPerPage)
	}
}

func TestAbsurdTokensAreDropped(t *testing.T) {
	long := strings.Repeat("a", MaxTermLength+50)
	got := Tokenise(long + " ok")
	for _, term := range got {
		if len(term) > MaxTermLength {
			t.Errorf("a %d-character term was indexed", len(term))
		}
	}
	// Single characters are noise in an index and match everything.
	if len(Tokenise("a b c")) != 0 {
		t.Errorf("single characters were indexed: %v", Tokenise("a b c"))
	}
}

// -- what the index is of ----------------------------------------------------

// A search box that returns unpublished pages is a search box that leaks
// unpublished content, however it is labelled.
func TestTheIndexRecordsWhatItWasBuiltFrom(t *testing.T) {
	idx := Build("commit-abc", site())
	if idx.Commit != "commit-abc" {
		t.Errorf("the index does not say which content it covers: %q", idx.Commit)
	}
}

// Two builds of the same content must produce the same index, so it can be
// content-addressed like everything else here.
func TestBuildingIsDeterministic(t *testing.T) {
	a := Build("abc", site())
	b := Build("abc", site())

	if len(a.Terms) != len(b.Terms) {
		t.Fatalf("%d terms then %d", len(a.Terms), len(b.Terms))
	}
	for term, pa := range a.Terms {
		pb := b.Terms[term]
		if len(pa) != len(pb) {
			t.Fatalf("%q has %d postings then %d", term, len(pa), len(pb))
		}
		for i := range pa {
			if pa[i] != pb[i] {
				t.Errorf("%q posting %d differs between builds", term, i)
			}
		}
	}
}

// A result should say why it matched rather than appearing by magic.
func TestAResultSaysWhereItMatched(t *testing.T) {
	idx := Build("abc", site())
	r := idx.Search("pricing", 10)[0]
	if len(r.Fields) == 0 {
		t.Error("the result does not say which fields matched")
	}
	if r.Matched != 1 {
		t.Errorf("matched %d of 1 term", r.Matched)
	}
	if r.Title == "" {
		t.Error("the result carries no title, so it cannot be displayed " +
			"without loading the page")
	}
}

func TestAnEmptyQueryReturnsNothing(t *testing.T) {
	idx := Build("abc", site())
	for _, q := range []string{"", "   ", "!!!", "a"} {
		if got := idx.Search(q, 10); len(got) != 0 {
			t.Errorf("%q returned %d results", q, len(got))
		}
	}
	var nilIdx *Index
	if got := nilIdx.Search("anything", 10); got != nil {
		t.Error("a nil index returned results")
	}
}

// The words on a page are the words in the index.
//
// The indexer read a string and a list of strings and stopped, and a page built
// the way the shipped layouts want has almost no text at that level: the words
// are in a hero object and in a list of section objects. So a site's index
// covered its titles and its footer, a search for a word printed twice on the
// front page found nothing, and neither side was wrong about its own job.
func TestNestedContentIsIndexed(t *testing.T) {
	page := map[string]any{
		"title": "Aster & Alum",
		"hero": map[string]any{
			"title": "Colour that comes out of a bucket",
			"lead":  "We dye cloth with madder and weld.",
			// An address, not prose: indexing it would put a hash in the term
			// list and match nothing anybody types.
			"image": "/media/" + strings.Repeat("a", 64),
		},
		"sections": []any{
			map[string]any{"features": map[string]any{
				"title": "Three things",
				"items": []any{
					map[string]any{"title": "Stationery",
						"body": "Letterpress cards on cotton stock."},
				},
			}},
			map[string]any{"prose": map[string]any{
				"paragraphs": []any{"Indigo does not dissolve in water."},
			}},
		},
	}
	idx := Build("commit", map[string]any{"index": page})

	for _, term := range []string{"madder", "weld", "letterpress", "cotton",
		"indigo", "dissolve"} {
		if len(idx.Search(term, 5)) == 0 {
			t.Errorf("%q is on the page and not in the index", term)
		}
	}
	// A path is not prose.
	if len(idx.Search(strings.Repeat("a", 64), 5)) != 0 {
		t.Error("a media path was indexed, which fills the term list with " +
			"hashes nobody searches for")
	}
	// And a phrase spanning two nested fields still needs every word present
	// somewhere on the page, which is the ranking rule this package documents.
	if len(idx.Search("madder letterpress", 5)) == 0 {
		t.Error("two words from different sections of one page did not match it")
	}

	// Deterministic: two builds of the same content produce the same index,
	// which is what lets it be addressed like everything else here.
	again := Build("commit", map[string]any{"index": page})
	first, _ := json.Marshal(idx)
	second, _ := json.Marshal(again)
	if string(first) != string(second) {
		t.Error("two builds of one page produced different indexes")
	}
}
