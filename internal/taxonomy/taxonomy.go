// Package taxonomy is classification with a vocabulary somebody owns.
//
// # The problem this is shaped around
//
// Every CMS has tags, and every CMS with free-text tags eventually has a mess.
// The documented outcomes are not subtle: one organisation accumulated over two
// thousand tags; another ended up with fourteen hundred entries in a single
// dropdown, most of them duplicates. "Marketing", "marketing" and "mktg" become
// three unrelated things, a filter on any one of them returns a third of the
// content, and nobody can tell whether the gap is missing content or a spelling.
//
// That is not a discipline problem to be solved with training. It is what
// happens when the system's default is "type anything and it becomes a
// permanent category", because the cost of creating a term is one keystroke and
// the cost of the resulting fragmentation is paid by somebody else, later.
//
// # So the default is inverted
//
// A vocabulary here is closed. Terms are declared, and only declared terms can
// be applied. Opening one is possible, deliberate, and marked — some
// vocabularies genuinely should be open, and an editor adding a term to a
// closed one is told which vocabulary to ask about rather than silently
// creating a synonym of something that already exists.
//
// Three things follow from that, and each of them is a thing free-text tagging
// cannot do:
//
//	Synonyms resolve. "mktg" is not a term, it is a spelling of one, so
//	applying it applies the canonical term. The variants stop existing rather
//	than accumulating.
//
//	Terms nest. A vocabulary is a tree, so filtering by a parent finds
//	everything under it without anybody maintaining a list.
//
//	A term in use cannot vanish. Deleting one is refused while content
//	carries it, because the alternative is content classified under something
//	that no longer exists — the dangling-reference problem that Drupal core
//	still has and that five separate contributed modules exist to patch.
//
// # Where the data lives
//
// The vocabulary is configuration: a file in the store, versioned with
// everything else. The assignments are part of the content, so a page's terms
// are inside the page and travel with it through history, promotion and export.
// A classification that lived in a side table would be a classification that
// could disagree with the content it describes.
package taxonomy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Limits, chosen to be generous for a real vocabulary and small enough that a
// runaway one is caught rather than accumulated.
const (
	// MaxTerms in one vocabulary. Past this it is not a controlled vocabulary,
	// it is the free-text mess with extra steps — the fourteen-hundred-entry
	// dropdown is inside this bound and is already unusable, so the limit is a
	// backstop rather than the guidance.
	MaxTerms = 2000
	// MaxDepth of nesting. Deep hierarchies are how a taxonomy becomes
	// unnavigable, and every level past this is one nobody uses.
	MaxDepth = 6
	// MaxPerItem is how many terms one page may carry from one vocabulary.
	MaxPerItem = 32
)

var (
	reName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	reTerm = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// Term is one entry in a vocabulary.
type Term struct {
	// ID is the stable identifier. It appears in content, so renaming a label
	// must not break anything that carries the term — which is why the label
	// is separate and this is not derived from it.
	ID string `json:"id"`
	// Label is what a person reads.
	Label string `json:"label"`
	// Description is what the term means, and it is the field that decides
	// whether a vocabulary survives contact with a second person. A term list
	// without definitions is a list two people will apply differently.
	Description string `json:"description,omitempty"`
	// Parent is the term this sits under. Empty is a root.
	Parent string `json:"parent,omitempty"`
	// Synonyms are spellings that resolve to this term rather than becoming
	// terms of their own. This is where "mktg" goes.
	Synonyms []string `json:"synonyms,omitempty"`
}

// Vocabulary is one controlled list.
type Vocabulary struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	// Open allows applying a term that is not declared, which creates it.
	//
	// False by default, and that default is the whole point of this package.
	// Opening one is a decision somebody makes about a specific vocabulary,
	// not the state everything starts in.
	Open bool `json:"open,omitempty"`
	// Terms, in no particular order; Sorted returns them arranged.
	Terms []Term `json:"terms"`
}

// Set is every vocabulary a site has.
type Set struct {
	Vocabularies []Vocabulary `json:"vocabularies"`
}

// ValidName reports whether a vocabulary may be called this.
func ValidName(s string) error {
	if !reName.MatchString(s) {
		return fmt.Errorf(
			"%q is not a usable vocabulary name: lowercase letters, digits "+
				"and underscores, starting with a letter", s)
	}
	return nil
}

// ValidTerm reports whether a term identifier is usable.
func ValidTerm(s string) error {
	if !reTerm.MatchString(s) {
		return fmt.Errorf(
			"%q is not a usable term: lowercase letters, digits and hyphens", s)
	}
	return nil
}

// Get finds a vocabulary.
func (s *Set) Get(name string) (*Vocabulary, bool) {
	for i := range s.Vocabularies {
		if s.Vocabularies[i].Name == name {
			return &s.Vocabularies[i], true
		}
	}
	return nil, false
}

// Names lists the vocabularies.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.Vocabularies))
	for _, v := range s.Vocabularies {
		out = append(out, v.Name)
	}
	sort.Strings(out)
	return out
}

// Add declares a vocabulary.
func (s *Set) Add(v Vocabulary) error {
	if err := ValidName(v.Name); err != nil {
		return err
	}
	if _, exists := s.Get(v.Name); exists {
		return fmt.Errorf("%q already exists", v.Name)
	}
	if err := v.Validate(); err != nil {
		return err
	}
	s.Vocabularies = append(s.Vocabularies, v)
	return nil
}

// Validate checks a vocabulary is usable.
func (v *Vocabulary) Validate() error {
	if err := ValidName(v.Name); err != nil {
		return err
	}
	if len(v.Terms) > MaxTerms {
		return fmt.Errorf(
			"%d terms in %q, and the limit is %d. Past a few hundred this is "+
				"not a controlled vocabulary any more — it is free text with "+
				"extra steps, and nobody can find the right term in it",
			len(v.Terms), v.Name, MaxTerms)
	}

	seen := map[string]bool{}
	syn := map[string]string{}
	for _, t := range v.Terms {
		if err := ValidTerm(t.ID); err != nil {
			return fmt.Errorf("in %q: %w", v.Name, err)
		}
		if seen[t.ID] {
			return fmt.Errorf("%q declares the term %q twice", v.Name, t.ID)
		}
		seen[t.ID] = true

		for _, sy := range t.Synonyms {
			if err := ValidTerm(sy); err != nil {
				return fmt.Errorf("synonym in %q: %w", v.Name, err)
			}
			if other, clash := syn[sy]; clash {
				return fmt.Errorf(
					"%q is a synonym of both %q and %q, so applying it would "+
						"have two answers", sy, other, t.ID)
			}
			syn[sy] = t.ID
		}
	}
	// A synonym that is also a term is ambiguous in the other direction: the
	// resolver would have to choose between the term and what it points at.
	for sy, of := range syn {
		if seen[sy] {
			return fmt.Errorf(
				"%q is both a term and a synonym of %q", sy, of)
		}
	}

	// Parents must exist, and the hierarchy must be a tree.
	for _, t := range v.Terms {
		if t.Parent == "" {
			continue
		}
		if !seen[t.Parent] {
			return fmt.Errorf("%q sits under %q, which is not a term in %q",
				t.ID, t.Parent, v.Name)
		}
		depth, err := v.depth(t.ID, map[string]bool{})
		if err != nil {
			return err
		}
		if depth > MaxDepth {
			return fmt.Errorf(
				"%q nests %d deep in %q, and the limit is %d. Every level past "+
					"that is one nobody navigates", t.ID, depth, v.Name, MaxDepth)
		}
	}
	return nil
}

// depth walks up to the root, refusing a cycle.
func (v *Vocabulary) depth(id string, seen map[string]bool) (int, error) {
	if seen[id] {
		return 0, fmt.Errorf(
			"%q is its own ancestor in %q; the hierarchy is a loop and "+
				"filtering by a parent would never finish", id, v.Name)
	}
	seen[id] = true
	t, ok := v.Term(id)
	if !ok || t.Parent == "" {
		return 1, nil
	}
	up, err := v.depth(t.Parent, seen)
	return up + 1, err
}

// Term finds one.
func (v *Vocabulary) Term(id string) (Term, bool) {
	for _, t := range v.Terms {
		if t.ID == id {
			return t, true
		}
	}
	return Term{}, false
}

// Resolve turns what somebody typed into a canonical term.
//
// This is where "mktg" stops being a new category. The lookup is exact on the
// identifier first, then on synonyms, and a closed vocabulary refuses anything
// else with the list of what it does have — because "that is not a term" is
// only useful next to "these are".
func (v *Vocabulary) Resolve(input string) (string, error) {
	want := strings.ToLower(strings.TrimSpace(input))
	if want == "" {
		return "", fmt.Errorf("no term given")
	}
	if _, ok := v.Term(want); ok {
		return want, nil
	}
	for _, t := range v.Terms {
		for _, sy := range t.Synonyms {
			if sy == want {
				return t.ID, nil
			}
		}
	}
	if v.Open {
		if err := ValidTerm(want); err != nil {
			return "", err
		}
		return want, nil
	}

	// Named alternatives rather than the whole list, which for a real
	// vocabulary is hundreds of entries and helps nobody.
	if near := v.nearest(want); len(near) > 0 {
		return "", fmt.Errorf(
			"%q is not a term in %q. Did you mean %s? If it should be a new "+
				"term, add it to the vocabulary — this one is closed so that "+
				"three spellings of one idea cannot become three categories",
			input, v.Name, strings.Join(near, ", "))
	}
	return "", fmt.Errorf(
		"%q is not a term in %q, and that vocabulary is closed. Add the term "+
			"first, or open the vocabulary if it should accept anything",
		input, v.Name)
}

// nearest suggests terms sharing a prefix or containing the input.
//
// Deliberately not an edit-distance search. A fuzzy matcher that confidently
// suggests the wrong term is worse than one that suggests nothing, and the
// realistic mistake here is a shortening or a plural rather than a typo.
func (v *Vocabulary) nearest(want string) []string {
	var out []string
	for _, t := range v.Terms {
		id := t.ID
		if strings.HasPrefix(id, want) || strings.HasPrefix(want, id) ||
			strings.Contains(id, want) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// Sorted returns the terms as a depth-first tree, for display.
type Row struct {
	Term
	Depth int
}

func (v *Vocabulary) Sorted() []Row {
	byParent := map[string][]Term{}
	for _, t := range v.Terms {
		byParent[t.Parent] = append(byParent[t.Parent], t)
	}
	for k := range byParent {
		sort.Slice(byParent[k], func(i, j int) bool {
			return byParent[k][i].ID < byParent[k][j].ID
		})
	}
	var out []Row
	var walk func(parent string, depth int)
	walk = func(parent string, depth int) {
		if depth > MaxDepth {
			return
		}
		for _, t := range byParent[parent] {
			out = append(out, Row{Term: t, Depth: depth})
			walk(t.ID, depth+1)
		}
	}
	walk("", 0)
	return out
}

// Ancestors returns a term and everything above it, nearest first.
//
// Used when filtering: content tagged "quarterly-report" matches a filter on
// "reports" because the parent is in this list, and nobody had to maintain a
// mapping to make that true.
func (v *Vocabulary) Ancestors(id string) []string {
	var out []string
	seen := map[string]bool{}
	for id != "" && !seen[id] {
		seen[id] = true
		out = append(out, id)
		t, ok := v.Term(id)
		if !ok {
			break
		}
		id = t.Parent
	}
	return out
}

// Descendants returns a term and everything under it.
func (v *Vocabulary) Descendants(id string) []string {
	out := []string{id}
	for _, t := range v.Terms {
		if t.Parent == id {
			out = append(out, v.Descendants(t.ID)...)
		}
	}
	sort.Strings(out)
	return out
}

// Remove deletes a term, refusing while anything carries it.
//
// The refusal is the feature. Drupal core does not clean up references to a
// deleted entity, which leaves content pointing at something that no longer
// exists — there are at least five contributed modules whose entire purpose is
// patching that hole. Making it impossible is cheaper than making it
// recoverable.
func (v *Vocabulary) Remove(id string, usedBy []string) error {
	if _, ok := v.Term(id); !ok {
		return fmt.Errorf("%q has no term %q", v.Name, id)
	}
	if len(usedBy) > 0 {
		sort.Strings(usedBy)
		shown := usedBy
		if len(shown) > 8 {
			shown = append(shown[:8], fmt.Sprintf("and %d more", len(usedBy)-8))
		}
		return fmt.Errorf(
			"%d item(s) still carry %q: %s. Removing it would leave them "+
				"classified under something that does not exist. Retag them, "+
				"or make this a synonym of the term they should have",
			len(usedBy), id, strings.Join(shown, ", "))
	}
	for _, t := range v.Terms {
		if t.Parent == id {
			return fmt.Errorf(
				"%q sits under %q. Removing the parent would orphan it — move "+
					"it first", t.ID, id)
		}
	}
	kept := v.Terms[:0]
	for _, t := range v.Terms {
		if t.ID != id {
			kept = append(kept, t)
		}
	}
	v.Terms = kept
	return nil
}

// Field is the page field that carries classification.
//
// One field holding a map of vocabulary to terms, rather than one field per
// vocabulary. The reason is that a content type declares its own fields and a
// vocabulary is site-wide: adding a vocabulary must not require editing every
// type, and a type must not be able to hide a classification from a filter.
const Field = "terms"

// Apply resolves and records terms on a page body.
//
// Returns the canonical set, sorted and deduplicated, so the same
// classification always serialises identically and two pages tagged the same
// way hash the same way.
func Apply(set *Set, body map[string]any, vocab string, inputs []string) error {
	v, ok := set.Get(vocab)
	if !ok {
		return fmt.Errorf("there is no vocabulary %q", vocab)
	}
	if len(inputs) > MaxPerItem {
		return fmt.Errorf(
			"%d terms from %q on one item, and the limit is %d. Past that the "+
				"classification is not saying anything a filter can use",
			len(inputs), vocab, MaxPerItem)
	}

	seen := map[string]bool{}
	var canonical []string
	for _, in := range inputs {
		if strings.TrimSpace(in) == "" {
			continue
		}
		id, err := v.Resolve(in)
		if err != nil {
			return err
		}
		if !seen[id] {
			seen[id] = true
			canonical = append(canonical, id)
		}
	}
	sort.Strings(canonical)

	all, _ := body[Field].(map[string]any)
	if all == nil {
		all = map[string]any{}
	}
	if len(canonical) == 0 {
		delete(all, vocab)
	} else {
		list := make([]any, 0, len(canonical))
		for _, id := range canonical {
			list = append(list, id)
		}
		all[vocab] = list
	}
	if len(all) == 0 {
		delete(body, Field)
		return nil
	}
	body[Field] = all
	return nil
}

// Of reads the terms on a page body for one vocabulary.
func Of(body any, vocab string) []string {
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	all, ok := m[Field].(map[string]any)
	if !ok {
		return nil
	}
	list, ok := all[vocab].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Usage counts how many items carry each term, and names them.
//
// Both, because the two answer different questions: the count drives a facet
// list, and the names are what a person needs when a term cannot be deleted.
type Usage struct {
	Count map[string]int
	Items map[string][]string
}

// Count walks a page set.
func Count(pages map[string]any, vocab string) Usage {
	u := Usage{Count: map[string]int{}, Items: map[string][]string{}}
	for name, body := range pages {
		for _, id := range Of(body, vocab) {
			u.Count[id]++
			u.Items[id] = append(u.Items[id], name)
		}
	}
	for id := range u.Items {
		sort.Strings(u.Items[id])
	}
	return u
}

// Match reports whether an item's terms satisfy a filter, following the tree.
//
// A page tagged with a child matches a filter on its parent. That is what makes
// a hierarchy worth having: "everything under reports" needs no list of what is
// under reports, and it stays correct when somebody adds one.
func Match(v *Vocabulary, itemTerms []string, want string) bool {
	for _, have := range itemTerms {
		for _, up := range v.Ancestors(have) {
			if up == want {
				return true
			}
		}
	}
	return false
}
