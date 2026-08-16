package taxonomy

import (
	"strings"
	"testing"
)

// A closed vocabulary is the whole point, so this is the first test.
//
// The documented failure mode is an organisation with two thousand tags and a
// dropdown of fourteen hundred mostly-duplicate entries. That happens because
// the cost of inventing a category is one keystroke. Here it is not available.
func TestAClosedVocabularyRefusesInventedTerms(t *testing.T) {
	v := &Vocabulary{Name: "topics", Terms: []Term{
		{ID: "marketing", Label: "Marketing"},
		{ID: "engineering", Label: "Engineering"},
	}}

	if _, err := v.Resolve("marketing"); err != nil {
		t.Errorf("refused a declared term: %v", err)
	}
	_, err := v.Resolve("mktg")
	if err == nil {
		t.Fatal("accepted a term nobody declared; this is how two thousand " +
			"tags happen")
	}
	if !strings.Contains(err.Error(), "closed") &&
		!strings.Contains(err.Error(), "Did you mean") {
		t.Errorf("the refusal does not explain what to do: %v", err)
	}
}

// Synonyms resolve rather than accumulate.
func TestSynonymsResolveToTheCanonicalTerm(t *testing.T) {
	v := &Vocabulary{Name: "topics", Terms: []Term{
		{ID: "marketing", Synonyms: []string{"mktg", "marketting"}},
	}}
	for _, spelling := range []string{"marketing", "mktg", "marketting", "  MKTG "} {
		got, err := v.Resolve(spelling)
		if err != nil {
			t.Fatalf("%q: %v", spelling, err)
		}
		if got != "marketing" {
			t.Errorf("%q resolved to %q, not the canonical term", spelling, got)
		}
	}
}

// An open vocabulary is possible, and is a decision rather than the default.
func TestAnOpenVocabularyAcceptsNewTerms(t *testing.T) {
	v := &Vocabulary{Name: "freeform", Open: true}
	got, err := v.Resolve("anything-goes")
	if err != nil {
		t.Fatalf("an open vocabulary refused a new term: %v", err)
	}
	if got != "anything-goes" {
		t.Errorf("got %q", got)
	}
	// Still validated: an open vocabulary is not a free-text field.
	if _, err := v.Resolve("Not A Term!"); err == nil {
		t.Error("an open vocabulary accepted something that is not a term id")
	}
}

// A term in use cannot be deleted.
//
// Drupal core leaves dangling references when an entity is deleted, and at
// least five contributed modules exist to patch it. Refusing is cheaper than
// recovering.
func TestATermInUseCannotBeRemoved(t *testing.T) {
	v := &Vocabulary{Name: "topics", Terms: []Term{{ID: "marketing"}}}

	err := v.Remove("marketing", []string{"about", "index"})
	if err == nil {
		t.Fatal("removed a term two pages still carry, leaving them " +
			"classified under something that does not exist")
	}
	if !strings.Contains(err.Error(), "about") {
		t.Errorf("the refusal does not name what is using it: %v", err)
	}
	if err := v.Remove("marketing", nil); err != nil {
		t.Errorf("refused to remove an unused term: %v", err)
	}
}

// A parent with children cannot be removed either.
func TestRemovingAParentWouldOrphanItsChildren(t *testing.T) {
	v := &Vocabulary{Name: "topics", Terms: []Term{
		{ID: "reports"}, {ID: "quarterly", Parent: "reports"},
	}}
	if err := v.Remove("reports", nil); err == nil {
		t.Error("removed a parent, orphaning its child")
	}
}

// Filtering by a parent finds everything beneath it.
func TestAFilterOnAParentMatchesItsDescendants(t *testing.T) {
	v := &Vocabulary{Name: "topics", Terms: []Term{
		{ID: "reports"},
		{ID: "quarterly", Parent: "reports"},
		{ID: "q3", Parent: "quarterly"},
		{ID: "unrelated"},
	}}
	if !Match(v, []string{"q3"}, "reports") {
		t.Error("content two levels down did not match a filter on the root; " +
			"a hierarchy nobody can filter through is a flat list with indentation")
	}
	if Match(v, []string{"unrelated"}, "reports") {
		t.Error("content outside the subtree matched")
	}
}

// The hierarchy has to be a tree.
func TestALoopInTheHierarchyIsRefused(t *testing.T) {
	v := &Vocabulary{Name: "topics", Terms: []Term{
		{ID: "a", Parent: "b"}, {ID: "b", Parent: "a"},
	}}
	if err := v.Validate(); err == nil {
		t.Error("accepted a cycle; filtering by a parent would never finish")
	}
}

// A synonym cannot point at two terms, or be a term itself.
func TestAmbiguousSynonymsAreRefused(t *testing.T) {
	both := &Vocabulary{Name: "topics", Terms: []Term{
		{ID: "one", Synonyms: []string{"shared"}},
		{ID: "two", Synonyms: []string{"shared"}},
	}}
	if err := both.Validate(); err == nil {
		t.Error("accepted a synonym of two different terms")
	}

	self := &Vocabulary{Name: "topics", Terms: []Term{
		{ID: "one", Synonyms: []string{"two"}}, {ID: "two"},
	}}
	if err := self.Validate(); err == nil {
		t.Error("accepted a synonym that is also a term")
	}
}

// Applying terms canonicalises and deduplicates, so the same classification
// always serialises identically.
func TestApplyProducesAStableCanonicalSet(t *testing.T) {
	set := &Set{}
	if err := set.Add(Vocabulary{Name: "topics", Terms: []Term{
		{ID: "marketing", Synonyms: []string{"mktg"}},
		{ID: "engineering"},
	}}); err != nil {
		t.Fatal(err)
	}

	a := map[string]any{}
	if err := Apply(set, a, "topics", []string{"mktg", "engineering", "marketing"}); err != nil {
		t.Fatal(err)
	}
	b := map[string]any{}
	if err := Apply(set, b, "topics", []string{"engineering", "MARKETING"}); err != nil {
		t.Fatal(err)
	}

	got, want := Of(a, "topics"), Of(b, "topics")
	if len(got) != 2 {
		t.Fatalf("three inputs naming two terms produced %v", got)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the same classification serialised two ways:\n  %v\n  %v",
			got, want)
	}
}

// Clearing removes the vocabulary's entry rather than leaving an empty list.
func TestClearingTermsLeavesNoResidue(t *testing.T) {
	set := &Set{}
	_ = set.Add(Vocabulary{Name: "topics", Terms: []Term{{ID: "a"}}})
	body := map[string]any{"title": "x"}
	_ = Apply(set, body, "topics", []string{"a"})
	if err := Apply(set, body, "topics", nil); err != nil {
		t.Fatal(err)
	}
	if _, still := body[Field]; still {
		t.Error("clearing the last term left an empty structure behind, which " +
			"changes the page's hash for no change in meaning")
	}
}

// Counting drives both the facet list and the deletion refusal.
func TestCountNamesWhatCarriesEachTerm(t *testing.T) {
	set := &Set{}
	_ = set.Add(Vocabulary{Name: "topics", Terms: []Term{{ID: "a"}, {ID: "b"}}})
	index := map[string]any{}
	about := map[string]any{}
	_ = Apply(set, index, "topics", []string{"a"})
	_ = Apply(set, about, "topics", []string{"a", "b"})

	u := Count(map[string]any{"index": index, "about": about}, "topics")
	if u.Count["a"] != 2 || u.Count["b"] != 1 {
		t.Errorf("counts are wrong: %v", u.Count)
	}
	if len(u.Items["a"]) != 2 || u.Items["a"][0] != "about" {
		t.Errorf("items are wrong or unsorted: %v", u.Items["a"])
	}
}

// Bounds are refused rather than accumulated.
func TestBoundsAreEnforced(t *testing.T) {
	deep := &Vocabulary{Name: "topics"}
	parent := ""
	for i := 0; i <= MaxDepth+1; i++ {
		id := string(rune('a' + i))
		deep.Terms = append(deep.Terms, Term{ID: id, Parent: parent})
		parent = id
	}
	if err := deep.Validate(); err == nil {
		t.Error("accepted a hierarchy deeper than anybody navigates")
	}

	set := &Set{}
	_ = set.Add(Vocabulary{Name: "topics", Open: true})
	many := make([]string, MaxPerItem+1)
	for i := range many {
		many[i] = "t" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if err := Apply(set, map[string]any{}, "topics", many); err == nil {
		t.Error("accepted more terms on one item than a filter can use")
	}
}
