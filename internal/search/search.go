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
		Titles: map[string]string{},
	}

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
				for pos, term := range Tokenise(text) {
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
				for term, p := range counts {
					idx.Terms[term] = append(idx.Terms[term], *p)
				}
			}
		}
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

// fieldStrings pulls every string out of a field value, including list items.
func fieldStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
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
	terms := Tokenise(query)
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

	for _, term := range terms {
		postings := idx.Terms[term]
		if len(postings) == 0 {
			continue
		}
		// Inverse document frequency, roughly: a term appearing on every page
		// says nothing about which page is wanted, and one appearing on three
		// says a great deal. Without this, common words dominate and the
		// ranking is a word count.
		rarity := float64(idx.Pages) / float64(len(postings))
		if rarity < 1 {
			rarity = 1
		}

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
			// Diminishing returns on repetition: the tenth occurrence of a word
			// says much less than the second, and without this a page that
			// repeats a term wins every time.
			repeat := 1 + float64(p.Count)/(float64(p.Count)+3)
			// Earlier is better, gently.
			early := 1.0
			if p.First < 20 {
				early = 1.2
			}
			a.score += w * rarity * repeat * early
			a.fields[p.Field] = true
			a.matched[term] = true
		}
	}

	var out []Result
	for page, a := range pages {
		// Every term must appear. Anything less returns most of the site.
		if len(a.matched) < len(terms) {
			continue
		}
		var fields []string
		for f := range a.fields {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		out = append(out, Result{
			Page: page, Title: idx.Titles[page], Score: a.score,
			Fields: fields, Matched: len(a.matched),
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

// Size reports how many terms the index holds, for deciding when this has been
// outgrown.
func (idx *Index) Size() int {
	if idx == nil {
		return 0
	}
	return len(idx.Terms)
}
