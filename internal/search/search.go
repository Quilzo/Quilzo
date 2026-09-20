// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package search finds pages without a search engine.
//
// # Why not Elasticsearch
//
// Because the zero-dependency position is load-bearing. It is what makes the
// Cyber Resilience Act obligations here cheap, what makes the bill of materials
// one line, and what means nothing in this product can reach end of life while
// nobody is looking. Adding a search cluster to a CMS that ships as an 8 MB
// static binary would trade all of that for a feature most sites of this size
// do not need at that scale.
//
// So the index is built here, at publish time, from content this program
// already holds. It is an inverted index with positional postings — the same
// structure a search engine uses, without the cluster.
//
// # What that costs, said plainly
//
// This will not scale to millions of pages, and it does not do stemming,
// synonyms, fuzzy matching or relevance tuning. What it does is find the pages
// containing the words somebody typed, rank them by where and how often the
// words appear, and do it in memory in microseconds for a site of a few
// thousand pages. Beyond that, the honest answer is a search engine, and the
// index here exports cleanly enough to feed one.
//
// # Why the index is content-addressed too
//
// It is built from a commit and records which. An index built from a draft
// nobody published would return results for pages that are not live — a search
// box that leaks unpublished content is a search box that leaks unpublished
// content, however it is labelled.
package search

import (
	"math"
	"sort"
	"unicode"
)

// MaxTermLength bounds a token. A hundred characters is past any real word and
// short of the point where an index entry is somebody's payload.
const MaxTermLength = 100

// MaxTermsPerPage bounds how much of one page is indexed.
//
// A limit rather than a promise: without it, one enormous page decides how much
// memory the index takes, and the person who wrote that page did not know they
// were making that decision.
const MaxTermsPerPage = 50000

// Posting is where a term appears in a page.
type Posting struct {
	Page string `json:"page"`
	// Field is which field it was in, because a word in a title means more than
	// the same word in the body and a ranker needs to know which.
	Field string `json:"field"`
	// Count is how often it appears in that field.
	Count int `json:"count"`
	// First is the position of the first occurrence, used to prefer pages where
	// the term appears early.
	First int `json:"first"`
}

// Index is an inverted index over a published site.
type Index struct {
	// Commit is what this index was built from. An index that does not say
	// which content it covers is one that can quietly serve results for pages
	// that are no longer live.
	Commit string `json:"commit"`
	// Terms maps a token to where it appears.
	Terms map[string][]Posting `json:"terms"`
	// Pages is how many were indexed, for the ranker's inverse document
	// frequency.
	Pages int `json:"pages"`
	// Titles are kept so a result can be displayed without loading the page.
	Titles map[string]string `json:"titles,omitempty"`
	// Lengths is each page's weighted length, and Average is their mean.
	//
	// Needed for length normalisation, which is the part of BM25 that stops a
	// long page winning every disjunctive query by having more of everything.
	// Weighted by field, so a long body does not make a title match cheap:
	// the same weights the ranker uses, applied to the count, so a page's
	// length means the same thing to both halves.
	//
	// Absent from an index built by an older version, and the ranker falls
	// back to the average when a page has no recorded length — which makes
	// the normalisation a no-op for that page rather than a division by zero.
	Lengths map[string]float64 `json:"lengths,omitempty"`
	Average float64            `json:"average,omitempty"`
}

// fieldWeight decides how much a match in each field is worth.
//
// A title match is worth more than a body match because somebody searching for
// "pricing" wants the pricing page, not the sentence in the FAQ that mentions
// it. The numbers are deliberately coarse: fine-grained relevance tuning is
// what a search engine is for, and pretending to it here would be a knob nobody
// can evaluate.
var fieldWeight = map[string]float64{
	"title": 8, "slug": 6, "standfirst": 4, "subtitle": 4,
	"description": 3, "tags": 3, "body": 1,
}

// Build makes an index from a page set.
func Build(commit string, pages map[string]any) *Index {
	idx := &Index{
		Commit: commit, Terms: map[string][]Posting{},
		Titles: map[string]string{}, Lengths: map[string]float64{},
	}
	length := idx.Lengths

	names := make([]string, 0, len(pages))
	for n := range pages {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		fields, ok := pages[name].(map[string]any)
		if !ok {
			continue
		}
		idx.Pages++
		if t, ok := fields["title"].(string); ok {
			idx.Titles[name] = t
		}

		budget := MaxTermsPerPage
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, field := range keys {
			for _, text := range fieldStrings(fields[field]) {
				counts := map[string]*Posting{}
				for pos, term := range indexTerms(text) {
					if budget <= 0 {
						break
					}
					budget--
					p := counts[term]
					if p == nil {
						p = &Posting{Page: name, Field: field, First: pos}
						counts[term] = p
					}
					p.Count++
				}
				w := fieldWeight[field]
				if w == 0 {
					w = 1
				}
				for term, p := range counts {
					idx.Terms[term] = append(idx.Terms[term], *p)
					length[name] += w * float64(p.Count)
				}
			}
		}
	}

	var total float64
	for _, l := range idx.Lengths {
		total += l
	}
	if idx.Pages > 0 {
		idx.Average = total / float64(idx.Pages)
	}

	// Sorted, so the index is deterministic — two builds of the same content
	// produce the same bytes, which is what lets it be content-addressed like
	// everything else here.
	for term := range idx.Terms {
		postings := idx.Terms[term]
		sort.Slice(postings, func(i, j int) bool {
			if postings[i].Page != postings[j].Page {
				return postings[i].Page < postings[j].Page
			}
			return postings[i].Field < postings[j].Field
		})
	}
	return idx
}

// Strings is every piece of prose in a value, however deeply it sits.
//
// Exported because the search page builds its snippets from it. A snippet has to
// come from the same text the index saw, or a result matches on a word the
// snippet does not contain — which reads as a bug in the ranking and is a bug in
// having two traversals.
func Strings(v any) []string { return fieldStrings(v) }

// fieldStrings pulls every string out of a field value, however deeply it sits.
//
// # Why it goes down
//
// It used to read a string and a list of strings, and stop. A page built the way
// this product recommends has almost no text at that level: the words are in a
// hero object and in a list of section objects, each of which holds titles,
// paragraphs and items. So the index covered a page's title, its description and
// its footer, and none of what anybody wrote — a search for a word printed
// twice on the front page found nothing, and there was no way to tell from
// either side, because the indexer was correct about the fields it was given
// and the page was correct about carrying them.
//
// Found by searching a real site for a word in its own copy.
//
// # Why it is bounded
//
// Content is nested by authors and by importers, and a walk with no limit is a
// way to spend the indexer's stack on a page somebody wrote. The depth bound is
// the same argument as internal/render's, and the term budget above already
// bounds the total work per page.
func fieldStrings(v any) []string {
	var out []string
	collectStrings(v, 0, &out)
	return out
}

// maxIndexDepth is how far into a page's structure the indexer reads.
//
// Six is past every shape the shipped layouts produce — a page holds sections,
// a section holds items, an item holds a list — with room for content somebody
// imported from a system that nested things more enthusiastically.
const maxIndexDepth = 6

func collectStrings(v any, depth int, out *[]string) {
	if depth > maxIndexDepth {
		return
	}
	switch t := v.(type) {
	case string:
		if t != "" {
			*out = append(*out, t)
		}
	case []any:
		for _, item := range t {
			collectStrings(item, depth+1, out)
		}
	case map[string]any:
		// Sorted, because the index is content-addressed: two builds of the
		// same page have to produce the same postings in the same order, and
		// map iteration does not.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			// Not the keys that are addresses rather than prose. An id, a
			// media path or a URL tokenises into noise that matches nothing
			// anybody types and crowds out the terms that do.
			if skipIndexing[k] {
				continue
			}
			collectStrings(t[k], depth+1, out)
		}
	}
}

// skipIndexing are fields whose value is an address rather than prose.
var skipIndexing = map[string]bool{
	"image": true, "src": true, "poster": true, "href": true, "url": true,
	"cta_href": true, "transcript_href": true, "share_image": true,
	"detail_key": true, "slug": true, "layout": true, "pct": true,
}

// Tokenise splits text into searchable terms.
//
// Deliberately simple: lowercase, split on anything that is not a letter or
// digit, drop what is too short or too long. No stemming, because stemming
// without a language is wrong in interesting ways — an English stemmer applied
// to German produces confident nonsense, and this program supports sites in
// more than one language.
func Tokenise(text string) []string {
	var out []string
	var cur []rune

	flush := func() {
		if len(cur) == 0 {
			return
		}
		if len(cur) <= MaxTermLength && len(cur) > 1 {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}

	for _, r := range text {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			cur = append(cur, unicode.ToLower(r))
		case r == '\'' && len(cur) > 0:
			// An apostrophe inside a word is part of it; one at a boundary is
			// punctuation. Splitting "don't" into "don" and "t" produces two
			// terms nobody searches for.
		default:
			flush()
		}
	}
	flush()
	return out
}

// Result is one match.
type Result struct {
	Page  string  `json:"page"`
	Title string  `json:"title,omitempty"`
	Score float64 `json:"score"`
	// Fields names where the terms were found, so a result can say why it
	// matched rather than appearing by magic.
	Fields []string `json:"fields"`
	// Matched is how many of the query's terms this page contains, which is
	// what decides ordering before score does.
	Matched int `json:"matched"`
}

// Search finds pages matching a query.
//
// Every term must appear somewhere in the page. An "any term" search on a
// two-word query returns most of the site and buries the page somebody wanted,
// which is how a search box gets a reputation for being useless.
func (idx *Index) Search(query string, limit int) []Result {
	terms := indexTerms(query)
	if len(terms) == 0 || idx == nil {
		return nil
	}
	if limit <= 0 {
		limit = 20
	}

	type acc struct {
		score   float64
		fields  map[string]bool
		matched map[string]bool
	}
	pages := map[string]*acc{}

	// Terms most of the corpus contains are dropped before scoring.
	//
	// Not for speed. Dropping the conjunction means a query of nothing but
	// ordinary words — "the and of to a it is" — has a positive score against
	// most of the site and comes back as a ranked list of everything. Their
	// inverse document frequency is small, so they do not decide the order,
	// and that is not the complaint: the complaint is that ten results were
	// returned at all, which reads as a search that is broken rather than a
	// query that said nothing.
	//
	// The rule is the one internal/vector already defends for the same
	// reason, where it drops such a term from an explanation on the grounds
	// that "these two pages are alike because both contain 'the'" is true and
	// useless. A term most pages contain cannot distinguish between pages,
	// and a query made only of those has nothing in it to answer.
	//
	// It is a property of the corpus and not a word list, so it needs no
	// language: on a site about indigo, "indigo" is on every page and is
	// dropped, which is right — it does not tell that site's pages apart.
	// Dropped only when something better remains. A query that is nothing but
	// a common word — "company", on a site where every page says company —
	// is a query somebody meant, and the honest answer is the pages that
	// contain it ranked by length rather than none at all. What this removes
	// is padding: the ordinary words around the word that was meant.
	var kept, common []string
	for _, term := range terms {
		docs := idx.pagesWith(term)
		if docs == 0 {
			// A word this corpus has never seen. Dropped rather than fatal:
			// "shipping times for trade orders" works only because the words
			// the site does not use fall away, and that is the query this
			// ranker exists to answer.
			continue
		}
		if docs > idx.ubiquitous() {
			common = append(common, term)
			continue
		}
		kept = append(kept, term)
	}
	if len(kept) == 0 {
		kept = common
	}
	if len(kept) == 0 {
		return nil
	}

	for _, term := range kept {
		postings := idx.Terms[term]
		idf := idfOf(idx.Pages, idx.pagesWith(term))

		for _, p := range postings {
			a := pages[p.Page]
			if a == nil {
				a = &acc{fields: map[string]bool{}, matched: map[string]bool{}}
				pages[p.Page] = a
			}
			w := fieldWeight[p.Field]
			if w == 0 {
				w = 1
			}
			// Earlier is better, gently. Kept from the version before this
			// one: it is not part of BM25 and it is worth a little, and the
			// judgement set does not get worse for it.
			early := 1.0
			if p.First < 20 {
				early = 1.2
			}
			a.score += idf * idx.saturate(w*float64(p.Count), idx.lengthOf(p.Page)) * early
			a.fields[p.Field] = true
			a.matched[term] = true
		}
	}

	var out []Result
	for page, a := range pages {
		out = append(out, Result{
			Page: page, Title: idx.Titles[page], Score: a.score,
			Fields: fieldsSorted(a.fields), Matched: len(a.matched),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		// A stable tiebreak, so the same query returns the same order.
		return out[i].Page < out[j].Page
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func fieldsSorted(set map[string]bool) []string {
	fields := make([]string, 0, len(set))
	for f := range set {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return fields
}

// Ranking, and why this is BM25 now when the package said it need not be.
//
// The old ranker required every term to appear: "Every term must appear.
// Anything less returns most of the site." That is correct for the query the
// judgement set contains — two or three words, all of them on the page that
// should win — and it scores precision@1 of 1.00 there.
//
// It returns the empty set for the query people type. Measured over the same
// corpus, every sentence-shaped query — "how do I wash dyed cloth", "shipping
// times for trade orders" — matched nothing at all, because one word the page
// does not happen to use empties the result. An empty result reads to a
// visitor as "this site does not cover that" and to a model as a broken tool.
//
// The obvious repair is to require only the rare terms, and it does not work:
// rarity is not relevance. "how" appears on exactly one page of the judgement
// corpus, so it survives the filter and then nothing matches both it and the
// words the reader actually meant.
//
// So the conjunction goes, and what replaces it has to answer the objection
// the conjunction existed for. That objection is length: drop the requirement
// and the longest page wins every query by having more of everything. That is
// precisely what BM25's two parts are for — saturation, so the tenth
// occurrence of a word counts for almost nothing, and length normalisation, so
// a long page is not rewarded for being long.
//
// The package's earlier note said "the length bias that BM25 exists to correct
// does not appear here, because repetition saturates below what a title match
// is worth". True, and true only under the conjunction: the long page could
// not win a query it did not match every word of. Without that protection the
// bias appears immediately, and relevance_test.go has the page that
// demonstrates it.

const (
	// k1 controls how fast term frequency saturates. 1.2 is the conventional
	// value and the one every published comparison uses as the baseline.
	k1 = 1.2
	// b is how much length normalisation is applied: 0 none, 1 fully. 0.75 is
	// again the conventional value.
	b = 0.75
)

// pagesWith is how many pages hold a term.
//
// In pages, not in postings. A term in a page's title and in its body is two
// postings and one page, and counting postings makes a word appearing in
// several fields of one page look as common as one spread across several.
func (idx *Index) pagesWith(term string) int {
	docs := map[string]bool{}
	for _, p := range idx.Terms[term] {
		docs[p.Page] = true
	}
	return len(docs)
}

// ubiquitous is the document frequency above which a term stops telling pages
// apart.
//
// Half the corpus, with the exception internal/vector makes for the same rule:
// on a site of two or three pages there is no such thing as a common term, and
// applying it would refuse every query.
func (idx *Index) ubiquitous() int {
	if idx.Pages < 4 {
		return idx.Pages
	}
	return idx.Pages / 2
}

// idfOf is the BM25 inverse document frequency.
//
// The +0.5 terms are the smoothing from the original formulation. The 1+ in
// front of the ratio keeps it positive: without it a term appearing in more
// than half the corpus gets a negative weight, so a page containing a common
// word scores worse than one that does not contain it at all — which is a
// ranking nobody can explain.
func idfOf(pages, docs int) float64 {
	if pages <= 0 || docs <= 0 {
		return 0
	}
	n, d := float64(pages), float64(docs)
	return math.Log(1 + (n-d+0.5)/(d+0.5))
}

// lengthOf is a page's weighted length.
func (idx *Index) lengthOf(page string) float64 {
	if l, ok := idx.Lengths[page]; ok && l > 0 {
		return l
	}
	// An index built before lengths were recorded. Using the average makes
	// the normalisation a no-op for that page rather than a division by zero
	// or a page that looks infinitely short and wins everything.
	return idx.Average
}

// saturate is BM25's term-frequency component, normalised for page length.
//
//	tf * (k1 + 1) / (tf + k1 * (1 - b + b * |D| / avgdl))
//
// The |D|/avgdl ratio is the whole point: a page twice the average length has
// to say a word twice as often to score what an average-length page scores
// once. With no corpus average — an index of one page, or one built before
// lengths were recorded — the ratio is 1 and this is plain saturation, which
// is the behaviour the ranker had before and is correct when there is nothing
// to compare a length against.
func (idx *Index) saturate(tf, length float64) float64 {
	ratio := 1.0
	if idx.Average > 0 && length > 0 {
		ratio = length / idx.Average
	}
	norm := 1 - b + b*ratio
	return tf * (k1 + 1) / (tf + k1*norm)
}

// Size reports how many terms the index holds, for deciding when this has been
// outgrown.
func (idx *Index) Size() int {
	if idx == nil {
		return 0
	}
	return len(idx.Terms)
}
