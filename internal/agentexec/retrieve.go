// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/search"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/vector"
)

// Letting an agent find a page instead of listing every page it holds.
//
// # What was there before
//
// list_pages and read_page. Two working indexes — a lexical one in
// internal/search and a TF-IDF one in internal/vector — were built at publish,
// handed to the public API, and reachable from no agent at all. An agent asked
// "which page covers returns" had one move: list every page and read them one
// at a time, spending a step and a body's worth of context on each, until the
// budget ran out or it guessed right.
//
// That is not a missing feature so much as a missing connection. Neither index
// is new here; what is new is that an agent can ask.
//
// # The corpus is filtered before it is indexed, not after
//
// This is the part worth reading twice. A scoped agent may read some pages and
// not others, and the obvious implementation indexes everything and drops the
// results it should not show. That leaks in two ways.
//
// The first is ordering: inverse document frequency is computed across the
// corpus, so a term's weight depends on how many pages contain it — including
// the ones being hidden. Scores would then carry information about content the
// agent was never granted, and the same query against two differently-scoped
// agents would rank differently for a reason neither can see.
//
// The second is the obvious one: a filter is a thing somebody removes. This
// follows listPages, which already refuses to name a page the agent could not
// read, and for the reason stated there — listing it is a disclosure of
// structure, which is how somebody learns that /legal/redundancies is a page.
//
// So the index is built over exactly the pages this agent may read. A page out
// of scope cannot appear, cannot influence a score, and cannot be counted.
//
// # Why the index is memoised on the commit
//
// Because building one is O(pages) and a run asks several questions. The key
// is the commit and the scope: content is immutable and addressed by its hash,
// so the same commit is the same pages by construction, and a publish is a
// different commit. There is nothing to invalidate. This is the same argument
// internal/public makes for the same reason.

// MaxHits bounds what one retrieval returns.
//
// Twenty, not a hundred. A model handed a hundred candidates spends its
// context on the tail and answers from the head anyway; the point of a search
// operation is that the next step is a read of one page.
const MaxHits = 20

// corpus is one scoped, indexed view of the content at a ref.
type corpus struct {
	commit string
	pages  map[string]any
	// text and near are built on first use. A run that only searches never
	// pays for the vector index, and one that only asks for neighbours never
	// pays for the lexical one.
	once sync.Once
	text *search.Index
	near *vector.Index
}

// indexes memoises the scoped corpus for one run.
//
// Keyed on the commit, so a publish between two steps of the same run is
// picked up rather than served stale. Held per Perform closure, which is per
// session, so one agent's scoped view can never be handed to another.
type indexes struct {
	mu  sync.Mutex
	cur *corpus
}

func (ix *indexes) at(r Reader, s *agent.Session, ref string) (*corpus, error) {
	commit := r.Store.GetRef(ref)
	if commit == "" {
		return nil, fmt.Errorf("nothing is published at %s", ref)
	}

	ix.mu.Lock()
	if ix.cur != nil && ix.cur.commit == commit {
		c := ix.cur
		ix.mu.Unlock()
		return c, nil
	}
	ix.mu.Unlock()

	all, err := site.PagesAt(r.Store, ref)
	if err != nil {
		return nil, err
	}
	// The scope, applied to the corpus rather than to the answer. See above.
	mine := make(map[string]any, len(all))
	for name, page := range all {
		if r.allowed(s, ref, name) {
			mine[name] = page
		}
	}
	c := &corpus{commit: commit, pages: mine}

	ix.mu.Lock()
	ix.cur = c
	ix.mu.Unlock()
	return c, nil
}

// lexical returns the keyword index, building it once.
func (c *corpus) lexical() *search.Index {
	c.build()
	return c.text
}

// vectors returns the similarity index, building it once.
func (c *corpus) vectors() *vector.Index {
	c.build()
	return c.near
}

// build makes both indexes together.
//
// Together, because they share a tokeniser on purpose — internal/vector takes
// one as an argument specifically so it and the search index cannot drift into
// two different ideas of what a word is — and building them in one place is
// what keeps that true here too.
func (c *corpus) build() {
	c.once.Do(func() {
		c.text = search.Build(c.commit, c.pages)
		c.near = vector.Build(c.commit, c.pages, search.Tokenise)
	})
}

// searchPages answers a keyword query over what this agent may read.
func (r Reader) searchPages(s *agent.Session, ix *indexes, ref string, a agent.Action) (string, error) {
	query := strings.TrimSpace(textFrom(a, "query", "q", "text"))
	if query == "" {
		return "", fmt.Errorf("no query was given")
	}
	// The scope check before the read, as everywhere else in this package.
	// Type and locale are empty because a search is not one typed thing; the
	// per-page decision is in the corpus filter.
	if err := s.Retrieve(ref, "", ""); err != nil {
		return "", err
	}
	c, err := ix.at(r, s, ref)
	if err != nil {
		return "", err
	}
	hits := c.lexical().Search(query, limitFrom(a))
	if len(hits) == 0 {
		// Said as a fact rather than returned empty. An empty string reads to
		// a model as a broken tool, and the next thing it does is call it
		// again with the same words.
		return fmt.Sprintf(
			"nothing this agent may read matches %q", query), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d page(s) match, best first:\n", len(hits))
	for _, h := range hits {
		title := h.Title
		if strings.TrimSpace(title) == "" {
			title = h.Page
		}
		fmt.Fprintf(&b, "%s\t%s\tmatched %d term(s)", h.Page, title, h.Matched)
		if len(h.Fields) > 0 {
			// Where it matched, so a result can say why it is here. A hit
			// with a score and no reason is one a model cannot sanity-check,
			// and neither can whoever reads the trace afterwards.
			fmt.Fprintf(&b, " in %s", strings.Join(fieldsOf(h.Fields), ", "))
		}
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String()), nil
}

// similarPages answers "what else is like this one".
func (r Reader) similarPages(s *agent.Session, ix *indexes, ref string, a agent.Action) (string, error) {
	name := nameFrom(a)
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("no page was named")
	}
	// A named page is one typed thing, so it gets the per-page check that
	// readPage gets — asking for neighbours of a page out of scope must be
	// refused the same way as reading it.
	if err := s.Retrieve(ref, r.typeOf(name), r.localeOf(name)); err != nil {
		return "", err
	}
	c, err := ix.at(r, s, ref)
	if err != nil {
		return "", err
	}
	idx := c.vectors()
	v, ok := idx.Vectors[name]
	if !ok {
		// The same answer whether it does not exist or is out of scope, for
		// the reason readPage gives: distinguishing them turns this into an
		// oracle for what is in the store.
		return "", fmt.Errorf("no page %q that this agent may read", name)
	}
	near, err := idx.Nearest(v, limitFrom(a), name)
	if err != nil {
		return "", err
	}
	if len(near) == 0 {
		return fmt.Sprintf(
			"nothing else this agent may read is close to %q", name), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "closest to %s, nearest first:\n", name)
	for _, n := range near {
		fmt.Fprintf(&b, "%s\t%.3f", n.Page, n.Score)
		if len(n.Shared) > 0 {
			// The terms the two pages share, which is what the lexical model
			// gives that a neural embedding cannot: a reason, not just a
			// number.
			//
			// A hint rather than an explanation, and the difference is
			// measurable. internal/vector drops a term appearing in more
			// than half the corpus, and on the eleven-page demo that means
			// "in", "that" and "to" all survive, ranking above the subject
			// words. Worth its own change with its own measurement rather
			// than a scoring tweak smuggled in here — so this says what it
			// is, and the operation's own description says so too.
			fmt.Fprintf(&b, "\tshared: %s", strings.Join(n.Shared, " "))
		}
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String()), nil
}

// fieldsOf keeps a field list short and stable.
func fieldsOf(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// textFrom reads the first of several spellings an action might use.
//
// Several, because the name of an argument is something a model produces and
// refusing "q" when the manifest said "query" costs a step to teach it a
// synonym it will forget. The set is closed: anything else is absent.
func textFrom(a agent.Action, keys ...string) string {
	for _, k := range keys {
		if v, ok := a.Input[k].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// limitFrom reads how many results were asked for, bounded.
//
// A model that asks for a thousand gets twenty. The cap is not a preference:
// without one the model decides how much of its own context this operation
// consumes, and it is not good at that.
func limitFrom(a agent.Action) int {
	n := 0
	switch v := a.Input["limit"].(type) {
	case float64:
		n = int(v)
	case int:
		n = v
	}
	if n <= 0 || n > MaxHits {
		return MaxHits
	}
	return n
}
