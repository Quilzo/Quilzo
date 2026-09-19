// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A store with four published pages on two subjects and two content types,
// plus one page that exists only in the draft.
func searchStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"returns": map[string]any{
			"title": "Returns and refunds",
			"body": "Send the item back within thirty days and we refund " +
				"the purchase price. A refund reaches the card it was paid on.",
		},
		"shipping": map[string]any{
			"title": "Shipping and delivery",
			"body": "We post everything tracked. Delivery takes three days " +
				"inside the country and a fortnight outside it.",
		},
		"refund-policy": map[string]any{
			"title": "Refund policy in full",
			"body": "The full terms of a refund, including the thirty day " +
				"window and what happens to a refund on a closed card.",
		},
		"about": map[string]any{
			"title": "About the workshop",
			"body":  "Two people, a lathe and a kiln, in a railway arch.",
		},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	// Draft-only, and it is the best match for the query used below. An agent
	// scoped to live must not find it by any phrasing.
	pages["embargo"] = map[string]any{
		"title": "Refund refund refund",
		"body":  "Refund refund refund refund refund. Not published.",
	}
	if _, err := site.SaveDraft(s, pages, "second", "test"); err != nil {
		t.Fatal(err)
	}
	return s
}

// searcher is a session holding the two retrieval capabilities.
func searcher(t *testing.T, types []string) *agent.Session {
	t.Helper()
	m := agent.Manifest{
		Name: "librarian", Kind: agent.KindRetrieval,
		Purpose: "find the page that answers a question",
		Capabilities: []string{
			"list_pages", "read_page", "search_pages", "similar_pages"},
		Autonomy:  agent.AutonomyPropose,
		Retrieval: agent.Retrieval{Ref: site.RefLive, Types: types},
		Budget: agent.Budget{
			Steps: 40, Tools: 5, Duration: agent.Duration(time.Hour)},
	}
	return agent.NewSession(m, nil)
}

func ask(t *testing.T, r Reader, s *agent.Session, op string, in map[string]any) (string, error) {
	t.Helper()
	return r.Perform(s)(context.Background(), agent.Action{Op: op, Input: in})
}

// The capability an agent did not have. Before this, the only way to find the
// page that answers a question was to list every page and read them all.
func TestAnAgentCanSearchTheContentItMayRead(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	s := searcher(t, nil)

	out, err := ask(t, r, s, "search_pages", map[string]any{"query": "refund"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"returns", "refund-policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is not in the results:\n%s", want, out)
		}
	}
	// A page on another subject must not be dragged in. Every term has to
	// appear somewhere in the page.
	if strings.Contains(out, "about") {
		t.Errorf("an unrelated page matched:\n%s", out)
	}
}

// A result has to say why it is a result. A hit with a score and no reason is
// one nobody can sanity-check, model or human.
func TestAResultSaysWhereItMatched(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	out, err := ask(t, r, searcher(t, nil), "search_pages",
		map[string]any{"query": "refund"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "matched") {
		t.Errorf("no match count in the results:\n%s", out)
	}
	if !strings.Contains(out, "title") && !strings.Contains(out, "body") {
		t.Errorf("no field named in the results:\n%s", out)
	}
}

// The property this exists to hold: a scoped agent's search cannot reach the
// draft, and the draft page here is deliberately the strongest match for the
// query.
func TestSearchCannotReachTheDraft(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	out, err := ask(t, r, searcher(t, nil), "search_pages",
		map[string]any{"query": "refund"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "embargo") {
		t.Fatalf("an unpublished page was found by an agent scoped to live:\n%s", out)
	}
}

// And the same for similarity, which asks a different question of a different
// index.
func TestSimilarityCannotReachTheDraft(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	s := searcher(t, nil)

	out, err := ask(t, r, s, "similar_pages", map[string]any{"page": "returns"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "embargo") {
		t.Fatalf("an unpublished page was returned as a neighbour:\n%s", out)
	}
	// It should still find the real neighbour, or the test above proved
	// nothing except that the index is empty.
	if !strings.Contains(out, "refund-policy") {
		t.Errorf("the obvious neighbour is missing:\n%s", out)
	}
}

// Asking for the neighbours of a page the agent cannot read is refused the
// same way reading it is, and with the same wording — so the error is not an
// oracle for what exists.
func TestNeighboursOfAnUnreadablePageAreRefused(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	_, err := ask(t, r, searcher(t, nil), "similar_pages",
		map[string]any{"page": "embargo"})
	if err == nil {
		t.Fatal("neighbours of an unpublished page were returned")
	}
	if !strings.Contains(err.Error(), "may read") {
		t.Errorf("the refusal reads %q, which is a different answer from the "+
			"one read_page gives for the same page", err)
	}
	_, missing := ask(t, r, searcher(t, nil), "similar_pages",
		map[string]any{"page": "no-such-page"})
	if missing == nil {
		t.Fatal("a page that does not exist returned neighbours")
	}
	if missing.Error() != strings.Replace(err.Error(), "embargo", "no-such-page", 1) {
		t.Errorf("a page out of scope and a page that does not exist give "+
			"different answers, which makes this an oracle:\n  %v\n  %v",
			err, missing)
	}
}

// A page out of scope must not be able to change the ordering of the pages
// that are in scope, which is what indexing the whole corpus and filtering the
// results afterwards would allow.
//
// Inverse document frequency is computed across the corpus, so a term's weight
// depends on how many pages contain it. Two agents with different scopes would
// then rank the same query differently for a reason neither can see.
func TestScopeChangesTheCorpusNotJustTheAnswer(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// "kiln" appears in one page of two, and in one page of six. Its inverse
	// document frequency therefore differs between the two corpora, and the
	// scores must differ with it.
	wide := map[string]any{
		"kiln":  map[string]any{"title": "The kiln", "body": "A kiln."},
		"about": map[string]any{"title": "About", "body": "A railway arch."},
	}
	for _, n := range []string{"a", "b", "c", "d"} {
		wide["note-"+n] = map[string]any{
			"title": "Note " + n, "body": "Nothing about a kiln here at all."}
	}
	if _, err := site.SaveDraft(s, wide, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	// Typed so a scope can exclude them: the notes are one type, the rest
	// another.
	types := func(page string) string {
		if strings.HasPrefix(page, "note-") {
			return "note"
		}
		return "page"
	}
	r := Reader{Store: s, Types: types}

	all, err := ask(t, r, searcher(t, nil), "search_pages",
		map[string]any{"query": "kiln"})
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := ask(t, r, searcher(t, []string{"page"}), "search_pages",
		map[string]any{"query": "kiln"})
	if err != nil {
		t.Fatal(err)
	}

	// The narrowed agent must not be told the notes exist.
	if strings.Contains(narrow, "note-") {
		t.Errorf("a page out of scope appeared in the results:\n%s", narrow)
	}
	// And both must still find the page they were looking for, or this
	// compared two empty answers.
	for _, out := range []string{all, narrow} {
		if !strings.Contains(out, "kiln") {
			t.Fatalf("the matching page is missing:\n%s", out)
		}
	}
}

// The cap is not a preference. Without one the model decides how much of its
// own context this operation consumes.
func TestTheResultCountIsBounded(t *testing.T) {
	for _, in := range []map[string]any{
		{"query": "refund", "limit": 1000.0},
		{"query": "refund", "limit": -1.0},
		{"query": "refund", "limit": 0.0},
		{"query": "refund"},
	} {
		if got := limitFrom(agent.Action{Input: in}); got != MaxHits {
			t.Errorf("limit %v gave %d, wanted %d", in["limit"], got, MaxHits)
		}
	}
	if got := limitFrom(agent.Action{Input: map[string]any{"limit": 3.0}}); got != 3 {
		t.Errorf("a reasonable limit was changed to %d", got)
	}
}

// Nothing matching is a fact, not an empty string. An empty answer reads to a
// model as a broken tool, and the next thing it does is call it again.
func TestNothingMatchingSaysSo(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	out, err := ask(t, r, searcher(t, nil), "search_pages",
		map[string]any{"query": "zygomorphic"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatal("an empty answer")
	}
	if !strings.Contains(out, "nothing") {
		t.Errorf("the answer is %q", out)
	}
}

func TestAQueryIsRequired(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	for _, in := range []map[string]any{nil, {}, {"query": "   "}, {"query": 7}} {
		if _, err := ask(t, r, searcher(t, nil), "search_pages", in); err == nil {
			t.Errorf("%v was accepted as a query", in)
		}
	}
}

// A model produces argument names. Refusing "q" when the manifest said
// "query" costs a step to teach it a synonym it will forget.
func TestTheQueryArgumentHasAFewSpellings(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	for _, key := range []string{"query", "q", "text"} {
		out, err := ask(t, r, searcher(t, nil), "search_pages",
			map[string]any{key: "refund"})
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if !strings.Contains(out, "refund-policy") {
			t.Errorf("%s: %s", key, out)
		}
	}
}

// An agent without the capability is refused before anything is read, by the
// same check every other operation goes through.
func TestAnAgentWithoutTheCapabilityIsRefused(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	m := agent.Manifest{
		Name: "reader-only", Kind: agent.KindRetrieval,
		Purpose:      "read one page",
		Capabilities: []string{"read_page"},
		Autonomy:     agent.AutonomyPropose,
		Retrieval:    agent.Retrieval{Ref: site.RefLive},
		Budget: agent.Budget{
			Steps: 10, Tools: 0, Duration: agent.Duration(time.Hour)},
	}
	s := agent.NewSession(m, nil)
	for _, op := range []string{"search_pages", "similar_pages"} {
		if _, err := ask(t, r, s, op, map[string]any{
			"query": "refund", "page": "returns"}); err == nil {
			t.Errorf("%s was performed for an agent that does not hold it", op)
		}
	}
}

// The corpus is memoised per session and keyed on the commit, so a publish
// between two steps of one run is picked up rather than served stale.
func TestAPublishDuringARunIsPickedUp(t *testing.T) {
	s := searchStore(t)
	r := Reader{Store: s}
	sess := searcher(t, nil)
	perform := r.Perform(sess)

	first, err := perform(context.Background(), agent.Action{
		Op: "search_pages", Input: map[string]any{"query": "refund"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(first, "embargo") {
		t.Fatal("the draft page was visible before it was published")
	}

	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	again, err := perform(context.Background(), agent.Action{
		Op: "search_pages", Input: map[string]any{"query": "refund"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(again, "embargo") {
		t.Errorf("the page was published and the memo kept the old corpus:\n%s", again)
	}
}

// Asking twice gives the same answer. A trace that differs between runs for no
// reason is a trace nobody can diff.
func TestTheSameQuestionGivesTheSameAnswer(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	s := searcher(t, nil)
	perform := r.Perform(s)
	var first string
	for i := 0; i < 5; i++ {
		out, err := perform(context.Background(), agent.Action{
			Op: "search_pages", Input: map[string]any{"query": "refund thirty"}})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = out
			continue
		}
		if out != first {
			t.Fatalf("call %d differs:\n%s\n---\n%s", i, first, out)
		}
	}
}

// Searching is reading, so it taints the session — which is what stops an
// agent that has looked at content from publishing.
//
// Worth its own test rather than assumed: a retrieval operation that built its
// index without going through Retrieve would return the same answers and
// quietly leave the session clean, and the symptom would be an agent allowed
// to publish after reading the whole site.
func TestSearchingTaintsTheSession(t *testing.T) {
	for _, tc := range []struct {
		op string
		in map[string]any
	}{
		{"search_pages", map[string]any{"query": "refund"}},
		{"similar_pages", map[string]any{"page": "returns"}},
	} {
		r := Reader{Store: searchStore(t)}
		s := searcher(t, nil)
		if s.Tainted() {
			t.Fatal("the session was tainted before reading anything")
		}
		if _, err := ask(t, r, s, tc.op, tc.in); err != nil {
			t.Fatal(err)
		}
		if !s.Tainted() {
			t.Errorf("%s read the store and did not taint the run", tc.op)
		}
	}
}

// And a refused search leaves nothing behind. An operation that tainted the
// session on the way to being refused would let a caller burn an agent's
// ability to publish by asking it something it may not do.
func TestARefusedSearchDoesNotTaint(t *testing.T) {
	r := Reader{Store: searchStore(t)}
	m := agent.Manifest{
		Name: "reader-only", Kind: agent.KindRetrieval,
		Purpose:      "read one page",
		Capabilities: []string{"read_page"},
		Autonomy:     agent.AutonomyPropose,
		Retrieval:    agent.Retrieval{Ref: site.RefLive},
		Budget: agent.Budget{
			Steps: 10, Tools: 0, Duration: agent.Duration(time.Hour)},
	}
	s := agent.NewSession(m, nil)
	if _, err := ask(t, r, s, "search_pages",
		map[string]any{"query": "refund"}); err == nil {
		t.Fatal("the search was performed")
	}
	if s.Tainted() {
		t.Error("a refused search tainted the session")
	}
}

// subtreeAgent is scoped to one part of the site.
func subtreeAgent(path string) *agent.Session {
	m := agent.Manifest{
		Name: "helpdesk", Kind: agent.KindRetrieval,
		Purpose: "answer from one part of the site",
		Capabilities: []string{
			"list_pages", "read_page", "search_pages", "similar_pages"},
		Autonomy:  agent.AutonomyPropose,
		Retrieval: agent.Retrieval{Ref: site.RefLive, Path: path},
		Budget: agent.Budget{
			Steps: 40, Tools: 0, Duration: agent.Duration(time.Hour)},
	}
	return agent.NewSession(m, nil)
}

// treeStore has pages in two subtrees, with the same word in both.
func treeStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"help/refunds": map[string]any{
			"title": "How a refund works",
			"body":  "A refund reaches the card it was paid on, within days.",
		},
		"help/shipping": map[string]any{
			"title": "Shipping", "body": "Everything goes tracked.",
		},
		"legal/refunds": map[string]any{
			"title": "Refund liability",
			"body":  "The statutory position on a refund, in full.",
		},
		"helpdesk": map[string]any{
			"title": "The helpdesk", "body": "A refund query goes here.",
		},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	return s
}

// A listing narrows rather than refusing, because a page the agent could not
// read is a page it should not be told exists — the same reasoning that
// already hides pages of another type.
func TestAListingIsNarrowedToTheSubtree(t *testing.T) {
	r := Reader{Store: treeStore(t)}
	out, err := ask(t, r, subtreeAgent("/help"), "list_pages", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"help/refunds", "help/shipping"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing:\n%s", want, out)
		}
	}
	if strings.Contains(out, "legal/refunds") {
		t.Errorf("a page outside the subtree was listed:\n%s", out)
	}
	// And the prefix trap: "helpdesk" is not inside "help".
	if strings.Contains(out, "helpdesk") {
		t.Errorf("a sibling whose name starts with the subtree was listed:\n%s", out)
	}
}

// Search is bounded by the same corpus filter, so a word that appears in both
// subtrees only finds the one the agent may read.
func TestSearchIsBoundedByTheSubtree(t *testing.T) {
	r := Reader{Store: treeStore(t)}
	out, err := ask(t, r, subtreeAgent("/help"), "search_pages",
		map[string]any{"query": "refund"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "help/refunds") {
		t.Errorf("the page inside the subtree is missing:\n%s", out)
	}
	if strings.Contains(out, "legal/refunds") {
		t.Errorf("a page outside the subtree was found:\n%s", out)
	}
	if strings.Contains(out, "helpdesk") {
		t.Errorf("a sibling whose name starts with the subtree was found:\n%s", out)
	}
}

// Reading it directly is refused, not merely omitted from a listing.
func TestReadingOutsideTheSubtreeIsRefused(t *testing.T) {
	r := Reader{Store: treeStore(t)}
	if _, err := ask(t, r, subtreeAgent("/help"), "read_page",
		map[string]any{"page": "legal/refunds"}); err == nil {
		t.Fatal("a page outside the subtree was read")
	}
	if _, err := ask(t, r, subtreeAgent("/help"), "read_page",
		map[string]any{"page": "helpdesk"}); err == nil {
		t.Fatal("a sibling whose name starts with the subtree was read")
	}
	if _, err := ask(t, r, subtreeAgent("/help"), "read_page",
		map[string]any{"page": "help/refunds"}); err != nil {
		t.Fatalf("a page inside the subtree was refused: %v", err)
	}
}

// An agent with no subtree still reads everything, or the fix above closed the
// hole by breaking the feature.
func TestNoSubtreeStillReadsEverything(t *testing.T) {
	r := Reader{Store: treeStore(t)}
	out, err := ask(t, r, subtreeAgent(""), "list_pages", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"help/refunds", "legal/refunds", "helpdesk"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing from an unscoped listing:\n%s", want, out)
		}
	}
}
