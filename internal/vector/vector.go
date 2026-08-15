// Package vector gives every published page a vector and answers
// nearest-neighbour queries over them.
//
// The request was for "vector embeddings natively, vector-search ready out of
// the box". The word doing the work is *natively*, and it is worth being exact
// about what that can mean, because the industry uses "embeddings" to mean one
// specific thing and this cannot be that thing for free.
//
// A semantic embedding — the kind where "car" and "automobile" land near each
// other — comes from a trained model. There are two ways to have one:
//
//	Run it in-process. Needs an inference runtime and a few hundred megabytes
//	of weights. Both are dependencies, and this program has none.
//
//	Call somebody's API. Then every published article leaves the building, to a
//	processor the customer has not contracted with, in a jurisdiction they have
//	not chosen. For a CMS whose whole argument is that content stays where you
//	put it, defaulting to that would contradict the product.
//
// So the default is a lexical vector: TF-IDF over the same tokeniser the search
// index uses, L2-normalised, compared by cosine. It is not semantic and this
// package does not pretend it is. What it is: deterministic, explainable,
// instant, free, works air-gapped, and genuinely good at the job people
// actually want — "more like this", "related articles", "did we already write
// about this". Those are similarity questions, not comprehension questions.
//
// And the API is the same either way. A Provider can supply real embeddings —
// from a model an operator runs themselves, or a service they have chosen — and
// the query path, the storage and the results are unchanged. Turning it on is a
// decision with a data-protection consequence, so it is a decision somebody
// makes, not a default they inherit.
//
// The honest comparison with a dedicated vector database: this is exact
// nearest-neighbour by brute force. No ANN index, no quantisation, no sharding.
// For the tens of thousands of pages a CMS holds that is the correct
// engineering answer — an exhaustive scan over 50,000 sparse vectors is a few
// milliseconds, and it returns the true nearest neighbours rather than an
// approximation. At ten million it would be the wrong answer, and a CMS with
// ten million pages has other problems.
package vector

import (
	"fmt"
	"math"
	"sort"
)

// Vector is one page's position, held sparsely.
//
// Sparse because a lexical vector over a real vocabulary is almost entirely
// zeros: a page uses a few hundred distinct terms out of tens of thousands.
// Dense storage would be a hundred kilobytes per page to hold nothing.
type Vector struct {
	// Weights maps a term to its weight. Already L2-normalised, so cosine
	// similarity is a dot product and nothing has to remember to divide.
	Weights map[string]float64
	// Dims is the source dimensionality, for a dense provider's vectors.
	Dims int
	// Model names what produced this. "tfidf" for the native one; a provider
	// names itself. Stored per vector rather than per index because vectors
	// from different models are not comparable, and mixing them silently
	// produces results that look plausible and are meaningless.
	Model string
}

// Cosine is the similarity of two vectors, in [-1, 1].
//
// Iterates the shorter side. Both are normalised, so this is a dot product;
// the guard against differing models is the important part, because comparing
// a TF-IDF vector to a neural one produces a number rather than an error, and
// a number is what somebody will ship.
func Cosine(a, b Vector) (float64, error) {
	if a.Model != b.Model {
		return 0, fmt.Errorf(
			"cannot compare a %s vector to a %s one: they are positions in "+
				"different spaces, and the number that falls out means nothing",
			orUnknown(a.Model), orUnknown(b.Model))
	}
	x, y := a.Weights, b.Weights
	if len(x) > len(y) {
		x, y = y, x
	}
	var dot float64
	for term, w := range x {
		if other, ok := y[term]; ok {
			dot += w * other
		}
	}
	return dot, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "an unlabelled"
	}
	return s
}

// Index holds the vectors for a commit.
type Index struct {
	// Commit ties this to exactly one version of the content. A vector index
	// that outlives the content it describes returns neighbours for pages that
	// no longer say what the vector says they say.
	Commit  string
	Model   string
	Vectors map[string]Vector
	// Terms is the vocabulary with its document frequencies, needed to embed a
	// *query* into the same space the documents live in. Without it a query
	// vector is built with different weights and the results are subtly wrong
	// in a way that never produces an error.
	Terms map[string]int
	Docs  int
}

// Tokeniser is supplied by the caller so this package and the search index
// cannot drift into two different ideas of what a word is.
type Tokeniser func(string) []string

// Build produces a lexical index over pages.
func Build(commit string, pages map[string]any, tok Tokeniser) *Index {
	idx := &Index{
		Commit: commit, Model: "tfidf",
		Vectors: map[string]Vector{}, Terms: map[string]int{},
	}

	counts := map[string]map[string]int{}
	for name, page := range pages {
		terms := map[string]int{}
		for _, text := range textOf(page) {
			for _, t := range tok(text) {
				terms[t]++
			}
		}
		if len(terms) == 0 {
			// A page with no text has no position. Omitted rather than given
			// the zero vector, which would be equidistant from everything and
			// would show up as a neighbour of every query.
			continue
		}
		counts[name] = terms
		for t := range terms {
			idx.Terms[t]++
		}
	}
	idx.Docs = len(counts)

	for name, terms := range counts {
		idx.Vectors[name] = weigh(terms, idx.Terms, idx.Docs, "tfidf")
	}
	return idx
}

// weigh turns term counts into a normalised TF-IDF vector.
func weigh(terms, df map[string]int, docs int, model string) Vector {
	v := Vector{Weights: make(map[string]float64, len(terms)), Model: model}
	var norm float64
	for t, n := range terms {
		// Sublinear term frequency: a word used forty times is not forty
		// times as relevant as one used once, and without the log a page
		// that repeats a word dominates every query containing it.
		tf := 1 + math.Log(float64(n))
		// Smoothed inverse document frequency. The +1s keep a term that
		// appears in every document from producing a zero or a negative
		// weight, which would make common words actively repel.
		idf := math.Log(float64(docs+1)/float64(df[t]+1)) + 1
		w := tf * idf
		v.Weights[t] = w
		norm += w * w
	}
	if norm > 0 {
		norm = math.Sqrt(norm)
		for t := range v.Weights {
			v.Weights[t] /= norm
		}
	}
	return v
}

// Embed places arbitrary text in the same space as the index.
//
// Uses the index's document frequencies, not the query's own, which is the
// step that is easy to skip and produces results that are wrong without ever
// being an error.
func (idx *Index) Embed(text string, tok Tokeniser) Vector {
	terms := map[string]int{}
	for _, t := range tok(text) {
		terms[t]++
	}
	return weigh(terms, idx.Terms, idx.Docs, idx.Model)
}

// Neighbour is one result.
type Neighbour struct {
	Page  string  `json:"page"`
	Score float64 `json:"score"`
	// Shared names the terms that drove the match, strongest first.
	//
	// A vector search that returns a page and a number is a vector search
	// nobody can debug. This is what a neural embedding cannot give you and
	// the lexical one can, and it is worth more day to day than the semantic
	// reach it trades away: an editor can see *why* two articles were called
	// similar and tell a real match from a coincidence.
	Shared []string `json:"shared,omitempty"`
}

// Nearest returns the pages closest to a vector.
//
// Exhaustive rather than approximate. For a CMS-sized corpus this is a few
// milliseconds and returns the true neighbours; an ANN index would return
// almost the same answers, sometimes, after a build step, with a recall figure
// somebody has to reason about.
func (idx *Index) Nearest(q Vector, limit int, exclude string) ([]Neighbour, error) {
	if limit <= 0 {
		limit = 10
	}
	out := make([]Neighbour, 0, len(idx.Vectors))
	for name, v := range idx.Vectors {
		if name == exclude {
			continue
		}
		score, err := Cosine(q, v)
		if err != nil {
			return nil, err
		}
		if score <= 0 {
			// Nothing in common. Omitted rather than returned with a zero,
			// because a caller asking for ten neighbours of an unrelated query
			// should get none rather than ten arbitrary pages.
			continue
		}
		out = append(out, Neighbour{Page: name, Score: score,
			Shared: idx.overlap(q, v, 5)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		// Ties broken by name, so the same query returns the same order twice
		// running. Map iteration would not.
		return out[i].Page < out[j].Page
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// overlap names the terms that explain a match.
//
// Ranked by contribution and then filtered by how common the term is, because
// the two are not the same thing. On a small corpus "the" appears in every
// document, so its inverse document frequency barely penalises it and it can
// out-contribute the word that actually made the pages similar — which
// produces an explanation reading "these two articles are alike because both
// contain 'the'". True, and useless.
//
// A term in more than half the corpus is dropped from the explanation. It
// still counts towards the score, where the weighting handles it correctly;
// this is only about what a human is shown.
func (idx *Index) overlap(a, b Vector, n int) []string {
	common := idx.Docs / 2
	if common < 2 {
		// On a corpus of two or three there is no such thing as a common
		// term, and filtering would leave nothing to show.
		common = idx.Docs + 1
	}
	return overlapFiltered(a, b, n, func(term string) bool {
		return idx.Terms[term] <= common
	})
}

func overlapFiltered(a, b Vector, n int, keep func(string) bool) []string {
	type pair struct {
		term string
		w    float64
	}
	var shared []pair
	for t, w := range a.Weights {
		if o, ok := b.Weights[t]; ok && (keep == nil || keep(t)) {
			shared = append(shared, pair{t, w * o})
		}
	}
	sort.Slice(shared, func(i, j int) bool {
		if shared[i].w != shared[j].w {
			return shared[i].w > shared[j].w
		}
		return shared[i].term < shared[j].term
	})
	if len(shared) > n {
		shared = shared[:n]
	}
	out := make([]string, 0, len(shared))
	for _, p := range shared {
		out = append(out, p.term)
	}
	return out
}

// Size reports the vocabulary, for display.
func (idx *Index) Size() (pages, terms int) {
	return len(idx.Vectors), len(idx.Terms)
}

// strings pulls every string out of a page's fields.
func textOf(v any) []string {
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			for _, vv := range t {
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		}
	}
	walk(v)
	return out
}

// -- providers ----------------------------------------------------------------

// Provider produces embeddings from somewhere other than this process.
//
// The interface exists so the native index is not a dead end. An operator who
// runs a model themselves, or has chosen a service and signed the paperwork,
// implements this and everything downstream — storage, query, results — is
// unchanged.
//
// It is deliberately not implemented here. Shipping a default provider that
// posts content to a named vendor would make that vendor the default answer to
// "where does our content go", which is not a decision this program gets to
// make on a customer's behalf.
type Provider interface {
	// Name identifies the model, and is stored on every vector it produces so
	// that vectors from different models cannot be silently compared.
	Name() string
	// Embed returns a dense vector for each text, in order.
	Embed(texts []string) ([][]float64, error)
}

// FromDense converts a provider's dense vector into the sparse form used here.
//
// The keys are positional indices rather than terms. It costs more memory than
// a dense slice for a fully-populated vector, and it means one code path for
// storage, cosine and querying instead of two — which is worth more than the
// bytes, because two paths is where the bug that compares them wrongly lives.
func FromDense(model string, values []float64) Vector {
	v := Vector{Weights: make(map[string]float64, len(values)),
		Dims: len(values), Model: model}
	var norm float64
	for _, x := range values {
		norm += x * x
	}
	if norm > 0 {
		norm = math.Sqrt(norm)
	} else {
		norm = 1
	}
	for i, x := range values {
		if x == 0 {
			continue
		}
		v.Weights[dim(i)] = x / norm
	}
	return v
}

func dim(i int) string { return "d" + itoa(i) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

var _ = fmt.Sprintf
