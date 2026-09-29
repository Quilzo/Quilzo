// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assistant

import (
	"math"
	"sort"

	"github.com/quilzo/quilzo/internal/search"
	"github.com/quilzo/quilzo/internal/vector"
)

// Index is the passages an assistant may answer from, ranked two ways.
type Index struct {
	Passages []Passage
	// BM25 statistics over the passages.
	terms  []map[string]int
	lens   []float64
	avgLen float64
	df     map[string]int
	// The TF-IDF leg, through internal/vector so a dense provider can
	// replace it without this file changing.
	vec *vector.Index
}

// BM25 parameters, at their textbook values. Tuned values exist for every
// benchmark and none of them is this site.
const (
	bm25K1 = 1.2
	bm25B  = 0.75
	// rrfK is reciprocal rank fusion's constant, from Cormack et al. (2009),
	// and the value everybody who uses RRF uses.
	rrfK = 60
)

// tokens is search's tokeniser with plurals folded.
//
// Search's, so the assistant and site search agree about what a word is,
// with one addition: a trailing plural s is dropped, so "return" finds
// "returns" and "bottle" finds "bottles". Only that — a real stemmer is an
// English stemmer, and search's note about applying one to German stands.
// A plural s is common across the languages this is likely to meet, and the
// guards (four letters or more, not -ss, -us or -is) keep "bus", "this" and
// "glass" whole.
func tokens(s string) []string {
	ts := search.Tokenise(s)
	for i, t := range ts {
		ts[i] = fold(t)
	}
	return ts
}

func fold(t string) string {
	if len(t) < 4 || t[len(t)-1] != 's' {
		return t
	}
	switch t[len(t)-2] {
	case 's', 'u', 'i':
		return t
	}
	return t[:len(t)-1]
}

// NewIndex builds an index over passages.
func NewIndex(ps []Passage) *Index {
	idx := &Index{Passages: ps, df: map[string]int{}}
	docs := make(map[string]any, len(ps))
	var total float64
	for i, p := range ps {
		tf := map[string]int{}
		n := 0
		for _, t := range tokens(p.Header() + " " + p.Text) {
			tf[t]++
			n++
		}
		idx.terms = append(idx.terms, tf)
		idx.lens = append(idx.lens, float64(n))
		total += float64(n)
		for t := range tf {
			idx.df[t]++
		}
		docs[passageKey(i)] = map[string]any{"text": p.Header() + " " + p.Text}
	}
	if len(ps) > 0 {
		idx.avgLen = total / float64(len(ps))
	}
	idx.vec = vector.Build("", docs, tokens)
	return idx
}

func passageKey(i int) string { return string(rune('a'+i%26)) + itoa(i) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// Hit is one retrieved passage and why it ranked where it did.
type Hit struct {
	Passage
	// Score is the fused score; only its order means anything.
	Score float64 `json:"score"`
	// BM25Rank and VectorRank are 1-based, 0 when that ranker did not return
	// it. Shown on the owner's test screen so a surprising answer can be
	// traced to the ranker that produced it.
	BM25Rank   int     `json:"bm25_rank,omitempty"`
	VectorRank int     `json:"vector_rank,omitempty"`
	Cosine     float64 `json:"cosine,omitempty"`
	// Matched are the query's informative terms this passage contains.
	Matched []string `json:"matched,omitempty"`
}

// Retrieve returns up to k passages for a question, best first.
//
// Nothing is returned for a question none of the passages is about. The
// floor is that a passage shares at least one informative term with the
// question — a term that is not in most of the corpus — which is what
// stops "what is the meaning of life" retrieving the page with the most
// words on it and the model then answering from it.
func (idx *Index) Retrieve(question string, k int) []Hit {
	if idx == nil || len(idx.Passages) == 0 || k <= 0 {
		return nil
	}
	q := informative(tokens(question), idx.df, len(idx.Passages))
	if len(q) == 0 {
		return nil
	}

	// BM25, disjunctive: a question is phrased the way a person talks, and
	// requiring every word — which site search rightly does for a search
	// box — would miss the passage that answers "can I send back opened
	// ink" because it says "returns" and not "send back".
	type scored struct {
		i int
		s float64
	}
	var bm []scored
	n := float64(len(idx.Passages))
	for i, tf := range idx.terms {
		var s float64
		for _, t := range q {
			f := float64(tf[t])
			if f == 0 {
				continue
			}
			df := float64(idx.df[t])
			idf := math.Log(1 + (n-df+0.5)/(df+0.5))
			norm := f * (bm25K1 + 1) /
				(f + bm25K1*(1-bm25B+bm25B*idx.lens[i]/idx.avgLen))
			s += idf * norm
		}
		if s > 0 {
			bm = append(bm, scored{i, s})
		}
	}
	sort.Slice(bm, func(a, b int) bool {
		if bm[a].s != bm[b].s {
			return bm[a].s > bm[b].s
		}
		return bm[a].i < bm[b].i
	})

	fused := map[int]*Hit{}
	get := func(i int) *Hit {
		h, ok := fused[i]
		if !ok {
			h = &Hit{Passage: idx.Passages[i]}
			fused[i] = h
		}
		return h
	}
	const depth = 50
	for r, x := range bm {
		if r == depth {
			break
		}
		h := get(x.i)
		h.BM25Rank = r + 1
		h.Score += 1 / float64(rrfK+r+1)
	}
	if near, err := idx.vec.Nearest(idx.vec.Embed(question, tokens), depth, ""); err == nil {
		for r, nb := range near {
			i := keyIndex(nb.Page)
			if i < 0 || i >= len(idx.Passages) {
				continue
			}
			h := get(i)
			h.VectorRank = r + 1
			h.Cosine = nb.Score
			h.Score += 1 / float64(rrfK+r+1)
		}
	}

	var out []Hit
	for i, h := range fused {
		for _, t := range q {
			if idx.terms[i][t] > 0 {
				h.Matched = append(h.Matched, t)
			}
		}
		// The floor, in two parts. A passage the vector leg liked for sharing
		// only common words is not about the question. And a passage that
		// shares one word of several is about that word, not the question:
		// "what is the weather in Leeds tomorrow" shares "leeds" with the
		// page that says where the workshop is, and answering from it is
		// how a site's assistant ends up giving a weather forecast. So a
		// passage has to cover at least half of what the question asks
		// about.
		if len(h.Matched) == 0 || float64(len(h.Matched)) < Coverage*float64(len(q)) {
			continue
		}
		out = append(out, *h)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Score != out[b].Score {
			return out[a].Score > out[b].Score
		}
		return out[a].ID < out[b].ID
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}

func keyIndex(key string) int {
	if len(key) < 2 {
		return -1
	}
	n := 0
	for _, c := range key[1:] {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// Coverage is the share of a question's informative terms a passage must
// contain to be retrieved at all.
const Coverage = 0.5

// informative drops the question's words that most passages contain.
//
// A stop list would be English; this is whatever language the site is in.
// A term in over half the passages says nothing about which one answers.
// On a corpus too small for that to mean anything, every term is kept.
func informative(ts []string, df map[string]int, n int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range ts {
		if seen[t] {
			continue
		}
		seen[t] = true
		if n >= 6 && float64(df[t]) > 0.5*float64(n) {
			continue
		}
		if stopword[t] {
			continue
		}
		out = append(out, t)
	}
	return out
}

// stopword is the handful of question words that carry no topic in any
// corpus. Kept deliberately tiny: it exists for the small site where the
// document-frequency rule cannot tell, and a long list is a list of words
// somebody one day needs to search for.
var stopword = map[string]bool{
	"what": true, "how": true, "who": true, "when": true, "where": true,
	"why": true, "which": true, "the": true, "is": true, "are": true,
	"do": true, "does": true, "can": true, "you": true, "your": true,
	"my": true, "an": true, "of": true, "to": true, "in": true, "on": true,
	"for": true, "and": true, "or": true, "it": true, "be": true,
	"with": true, "me": true, "we": true, "us": true, "if": true,
	"about": true, "tell": true, "please": true, "there": true,
	"have": true, "has": true, "had": true, "get": true, "much": true,
	"many": true, "some": true, "something": true, "any": true,
	"would": true, "could": true, "should": true, "will": true, "want": true,
	"need": true, "know": true, "this": true, "that": true, "at": true,
	"from": true, "by": true, "was": true, "were": true, "am": true,
}
