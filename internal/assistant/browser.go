// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assistant

import (
	"sort"

	"github.com/quilzo/quilzo/internal/search"
)

// An assistant that answers in the visitor's browser.
//
// # Why
//
// A static copy of a site — `ipfs write`, `export`, the demo on GitHub
// Pages — has no server behind it, so a chatbot that posts its question
// somewhere has nowhere to post. The extractive mode needs no model and no
// secret: it is ranking and quoting, which a browser can do as well as this
// process can, given the passages and the counts.
//
// # What ships, and what does not
//
// The passages of published pages, with each one's term counts already
// worked out, and the constants the ranking uses. Not documents from the
// media library: the live assistant quotes from those a passage at a time,
// and a static copy would publish them whole. Not a model, and not
// instructions, which only mean something to a model.
//
// # Why the counts are computed here
//
// So the browser tokenises only the question. The passages are tokenised
// by this package's own tokens(), which is what the live assistant uses, so
// the one place the two implementations can disagree is how a question is
// split into words — and a test runs the browser's code against this
// package's answers to make sure they do not.

// BrowserKnowledge is what a static copy's conversation page reads.
type BrowserKnowledge struct {
	Version  int    `json:"v"`
	Name     string `json:"name"`
	Title    string `json:"title"`
	Greeting string `json:"greeting,omitempty"`
	Refusal  string `json:"refusal"`
	// The ranking's parameters, so the browser's copy cannot drift from
	// this one's without a test noticing.
	Depth       int              `json:"depth"`
	K1          float64          `json:"k1"`
	B           float64          `json:"b"`
	RRF         int              `json:"rrf"`
	Coverage    float64          `json:"coverage"`
	Short       int              `json:"short"`
	MaxQuestion int              `json:"max_question"`
	MaxTerm     int              `json:"max_term"`
	Stopwords   []string         `json:"stopwords"`
	Passages    []BrowserPassage `json:"passages"`
}

// BrowserPassage is one passage with its term counts.
type BrowserPassage struct {
	ID     string         `json:"id"`
	Header string         `json:"header"`
	Href   string         `json:"href"`
	Text   string         `json:"text"`
	Terms  map[string]int `json:"tf"`
	Len    int            `json:"len"`
	// Head are the heading's terms, for the third ranker.
	Head []string `json:"ht,omitempty"`
}

// BrowserVersion changes when the file's shape does, so a page and a file
// from different builds refuse each other rather than answer wrongly.
const BrowserVersion = 1

// Browser builds what a static copy answers from.
//
// href turns a passage into the address its citation links to. Passages
// from documents are dropped whatever href says; see above.
func Browser(a Assistant, ps []Passage, href func(Passage) string) BrowserKnowledge {
	k := BrowserKnowledge{
		Version: BrowserVersion, Name: a.Name, Title: a.Title,
		Greeting: a.Greeting, Refusal: a.refusal(), Depth: a.depth(),
		K1: bm25K1, B: bm25B, RRF: rrfK, Coverage: Coverage,
		Short: shortPassage, MaxQuestion: MaxQuestion,
		MaxTerm: search.MaxTermLength,
	}
	for w := range stopword {
		k.Stopwords = append(k.Stopwords, w)
	}
	sort.Strings(k.Stopwords)
	k.Passages = []BrowserPassage{}
	for _, p := range ps {
		if p.Doc != "" {
			continue
		}
		tf := map[string]int{}
		n := 0
		for _, t := range tokens(p.Header() + " " + p.Text) {
			tf[t]++
			n++
		}
		var head []string
		seen := map[string]bool{}
		for _, t := range tokens(p.Heading) {
			if !seen[t] {
				seen[t] = true
				head = append(head, t)
			}
		}
		k.Passages = append(k.Passages, BrowserPassage{
			ID: p.ID, Header: p.Header(), Href: href(p), Text: p.Text,
			Terms: tf, Len: n, Head: head,
		})
	}
	return k
}

// BrowserIndex is the index the browser builds from the same passages.
//
// The live assistant may read documents too; this is the index over what a
// static copy carries, so a test can ask both the same question.
func BrowserIndex(ps []Passage) *Index {
	var kept []Passage
	for _, p := range ps {
		if p.Doc == "" {
			kept = append(kept, p)
		}
	}
	return NewIndex(kept)
}
