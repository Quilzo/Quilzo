package listing

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/store"
)

func index(t *testing.T) *collection.Index {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recs := []collection.Record{
		{Fields: map[string]any{"title": "Access control", "status": "met",
			"owner": "kit", "score": 9.0, "secret": "internal only"}},
		{Fields: map[string]any{"title": "Change management", "status": "unmet",
			"owner": "sam", "score": 4.0, "secret": "internal only"}},
		{Fields: map[string]any{"title": "Access review", "status": "unmet",
			"owner": "kit", "score": 6.0, "secret": "internal only"}},
	}
	tree, _, err := collection.PutMany(s, "", "controls", recs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	idx, err := collection.Build(s, tree, "controls", nil)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

// A listing filters, and returns what it declared.
func TestAListingFiltersAndProjects(t *testing.T) {
	l := &Listing{
		Name: "unmet", Collection: "controls",
		Where:  []Condition{{Field: "status", Match: Is, Value: "unmet"}},
		Fields: []string{"title", "owner"},
		Sort:   "title",
	}
	got, err := Resolve(l, index(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 2 {
		t.Fatalf("matched %d, expected 2", got.Total)
	}
	if got.Rows[0]["title"] != "Access review" {
		t.Errorf("not sorted by title: %v", got.Rows[0])
	}
}

// The allowlist is the point: a field the listing did not name never leaves.
//
// Views hands a template the whole entity and relies on the template not to
// print the wrong field, which works until somebody adds a field to a type and
// it appears on a public page nobody re-reviewed.
func TestAFieldTheListingDidNotNameIsNotReturned(t *testing.T) {
	l := &Listing{Name: "public", Collection: "controls",
		Fields: []string{"title", "status"}}
	got, err := Resolve(l, index(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range got.Rows {
		if _, leaked := row["secret"]; leaked {
			t.Fatal("a field outside the allowlist reached the template; " +
				"adding a field to a content type must not change what a " +
				"public page shows")
		}
		if _, ok := row["title"]; !ok {
			t.Error("a declared field is missing")
		}
		// The identifier always travels: a row nobody can address is a row
		// nobody can link to.
		if _, ok := row["id"]; !ok {
			t.Error("the identifier was projected away")
		}
	}
}

// A declared field with no value is present and empty, not absent.
func TestADeclaredFieldIsAlwaysPresent(t *testing.T) {
	l := &Listing{Name: "x", Collection: "controls",
		Fields: []string{"title", "nonexistent"}}
	got, err := Resolve(l, index(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := got.Rows[0]["nonexistent"]; !present {
		t.Error("a declared field with no value was omitted, so a template " +
			"cannot tell 'no value' from 'the listing did not include it'")
	}
}

// A parameter's value is checked against its kind before it reaches a filter.
func TestAParameterIsCheckedAgainstItsKind(t *testing.T) {
	l := &Listing{
		Name: "by_owner", Collection: "controls",
		Params: []Param{{Name: "who", Kind: Slug}},
		Where:  []Condition{{Field: "owner", Match: Is, Param: "who"}},
	}
	idx := index(t)

	got, err := Resolve(l, idx, map[string]string{"who": "kit"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 2 {
		t.Errorf("matched %d for kit, expected 2", got.Total)
	}

	for _, bad := range []string{
		"kit OR 1=1", "../../etc/passwd", "kit\x00", "Kit", "kit;drop",
		strings.Repeat("x", 300),
	} {
		if _, err := Resolve(l, idx, map[string]string{"who": bad}); err == nil {
			t.Errorf("accepted %q as a slug parameter", bad)
		}
	}
}

// A number parameter refuses anything that is not one.
func TestANumberParameterRefusesText(t *testing.T) {
	l := &Listing{
		Name: "by_score", Collection: "controls",
		Params: []Param{{Name: "score", Kind: Number}},
		Where:  []Condition{{Field: "score", Match: Is, Param: "score"}},
	}
	idx := index(t)
	got, err := Resolve(l, idx, map[string]string{"score": "9"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 1 {
		t.Errorf("matched %d for score 9, expected 1 — a number typed as a "+
			"string must still compare equal to a stored number", got.Total)
	}
	if _, err := Resolve(l, idx, map[string]string{"score": "nine"}); err == nil {
		t.Error("accepted text for a number parameter")
	}
}

// A missing argument returns nothing, not everything.
//
// The Drupal default is to widen to the whole collection when a contextual
// filter has no argument, which turns a filtered page into an unfiltered one —
// the way a listing meant to show one person's records shows everybody's.
func TestAMissingArgumentReturnsNothingRatherThanEverything(t *testing.T) {
	l := &Listing{
		Name: "mine", Collection: "controls",
		Params: []Param{{Name: "who", Kind: Slug}},
		Where:  []Condition{{Field: "owner", Match: Is, Param: "who"}},
	}
	got, err := Resolve(l, index(t), nil)
	if err != nil {
		t.Fatalf("a missing argument should be empty, not an error: %v", err)
	}
	if got.Total != 0 || len(got.Rows) != 0 {
		t.Errorf("a filter with no argument returned %d rows; it must not "+
			"widen to the whole collection", got.Total)
	}
}

// A default is used when nothing is supplied.
func TestADefaultFillsInAMissingArgument(t *testing.T) {
	l := &Listing{
		Name: "mine", Collection: "controls",
		Params: []Param{{Name: "who", Kind: Slug, Default: "kit"}},
		Where:  []Condition{{Field: "owner", Match: Is, Param: "who"}},
	}
	got, err := Resolve(l, index(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 2 {
		t.Errorf("the default was not applied: %d rows", got.Total)
	}
}

// Unrelated arguments are ignored rather than refused.
func TestAnUnrelatedArgumentIsIgnored(t *testing.T) {
	l := &Listing{Name: "all", Collection: "controls"}
	if _, err := Resolve(l, index(t),
		map[string]string{"utm_source": "newsletter"}); err != nil {
		t.Errorf("a tracking parameter broke the render: %v", err)
	}
}

// A condition cannot take its value from two places.
func TestAConditionCannotHaveBothALiteralAndAParameter(t *testing.T) {
	l := &Listing{
		Name: "x", Collection: "controls",
		Params: []Param{{Name: "who", Kind: Slug}},
		Where: []Condition{{Field: "owner", Match: Is,
			Value: "sam", Param: "who"}},
	}
	if err := l.Validate(); err == nil {
		t.Error("accepted a condition with a literal and a parameter; which " +
			"one wins becomes a question nobody can answer from the config")
	}
}

// A condition cannot use a parameter the listing did not declare.
func TestAConditionCannotUseAnUndeclaredParameter(t *testing.T) {
	l := &Listing{Name: "x", Collection: "controls",
		Where: []Condition{{Field: "owner", Match: Is, Param: "ghost"}}}
	if err := l.Validate(); err == nil {
		t.Error("accepted a filter on a parameter that does not exist")
	}
}

// The row ceiling is a refusal, not a truncation.
func TestTheRowCeilingIsEnforced(t *testing.T) {
	l := &Listing{Name: "x", Collection: "controls", Rows: MaxRows + 1}
	if err := l.Validate(); err == nil {
		t.Error("accepted a listing asking for more rows than the ceiling")
	}
}

// A page cannot embed an unbounded number of listings.
func TestAPageCannotEmbedTooManyListings(t *testing.T) {
	set := &Set{}
	var names []string
	for i := 0; i < MaxPerPage+1; i++ {
		n := "l" + string(rune('a'+i))
		if err := set.Add(Listing{Name: n, Collection: "controls"}); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if _, err := Check(names, set); err == nil {
		t.Error("accepted a page embedding more listings than the budget " +
			"allows; a page assembled from a dozen queries is how this " +
			"feature becomes the reason a site is slow")
	}
	if _, err := Check(names[:MaxPerPage], set); err != nil {
		t.Errorf("refused a page inside the budget: %v", err)
	}
}

// A page naming a listing that does not exist fails to build.
func TestAPageNamingAMissingListingIsRefused(t *testing.T) {
	if _, err := Check([]string{"nope"}, &Set{}); err == nil {
		t.Error("accepted a page embedding a listing that does not exist")
	}
}

// A listing given the wrong collection's index is refused.
func TestAnIndexOfTheWrongCollectionIsRefused(t *testing.T) {
	l := &Listing{Name: "x", Collection: "somewhere_else"}
	if _, err := Resolve(l, index(t), nil); err == nil {
		t.Error("read an index of a different collection")
	}
}

// Which listings a page embeds, read from its fields.
func TestOnReadsListingsFromAPage(t *testing.T) {
	if got := On(map[string]any{Field: "recent"}); len(got) != 1 ||
		got[0] != "recent" {
		t.Errorf("a single name was not read: %v", got)
	}
	if got := On(map[string]any{Field: []any{"a", "b", ""}}); len(got) != 2 {
		t.Errorf("a list was not read, or the empty entry survived: %v", got)
	}
	if got := On(map[string]any{"title": "x"}); got != nil {
		t.Errorf("a page with no listings returned %v", got)
	}
}
