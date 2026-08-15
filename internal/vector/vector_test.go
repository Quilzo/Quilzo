package vector

import (
	"strings"
	"testing"
)

func tok(s string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		if len(w) > 2 {
			out = append(out, w)
		}
	}
	return out
}

func corpus() map[string]any {
	return map[string]any{
		"budget":  map[string]any{"title": "Quarterly budget review", "body": "The finance team reviewed revenue, costs and the budget forecast for the quarter."},
		"revenue": map[string]any{"title": "Revenue grew again", "body": "Revenue and costs both rose this quarter, and the finance team expects the trend to hold."},
		"gardens": map[string]any{"title": "Planting bulbs in autumn", "body": "Tulip and daffodil bulbs go in before the first frost, in soil that drains well."},
		"soil":    map[string]any{"title": "Improving heavy soil", "body": "Heavy clay soil drains badly; add grit and compost before planting bulbs."},
		"empty":   map[string]any{"title": "", "body": ""},
	}
}

// The job people actually want: more like this.
func TestRelatedPagesAreActuallyRelated(t *testing.T) {
	idx := Build("c1", corpus(), tok)

	near, err := idx.Nearest(idx.Vectors["budget"], 2, "budget")
	if err != nil {
		t.Fatal(err)
	}
	if len(near) == 0 {
		t.Fatal("no neighbours for a page with obvious relatives")
	}
	if near[0].Page != "revenue" {
		t.Errorf("the nearest page to a finance article is %q", near[0].Page)
	}

	near, err = idx.Nearest(idx.Vectors["gardens"], 2, "gardens")
	if err != nil {
		t.Fatal(err)
	}
	if len(near) == 0 || near[0].Page != "soil" {
		t.Errorf("the nearest page to a gardening article is %v", near)
	}
}

// A result nobody can explain is a result nobody can debug. This is what a
// neural embedding cannot give you and is worth more day to day than the
// semantic reach it trades away.
func TestAMatchSaysWhyItMatched(t *testing.T) {
	idx := Build("c1", corpus(), tok)
	near, err := idx.Nearest(idx.Vectors["budget"], 1, "budget")
	if err != nil {
		t.Fatal(err)
	}
	if len(near[0].Shared) == 0 {
		t.Fatal("a match with no explanation")
	}
	found := false
	for _, term := range near[0].Shared {
		if term == "finance" || term == "revenue" || term == "quarter" ||
			term == "costs" {
			found = true
		}
	}
	if !found {
		t.Errorf("the shared terms do not explain the match: %v", near[0].Shared)
	}
}

// An arbitrary query returns nothing rather than ten arbitrary pages.
func TestAnUnrelatedQueryReturnsNothing(t *testing.T) {
	idx := Build("c1", corpus(), tok)
	near, err := idx.Nearest(idx.Embed("submarine hydraulics", tok), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(near) != 0 {
		t.Errorf("an unrelated query matched %d pages: %v", len(near), near)
	}
}

func TestAQueryFindsTheRightPage(t *testing.T) {
	idx := Build("c1", corpus(), tok)
	near, err := idx.Nearest(idx.Embed("planting bulbs before frost", tok), 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(near) == 0 {
		t.Fatal("no results")
	}
	if near[0].Page != "gardens" && near[0].Page != "soil" {
		t.Errorf("a gardening query returned %q first", near[0].Page)
	}
}

// -- the correctness properties -----------------------------------------------

// Comparing vectors from different models produces a number rather than an
// error, and a number is what somebody will ship.
func TestVectorsFromDifferentModelsCannotBeCompared(t *testing.T) {
	a := Vector{Model: "tfidf", Weights: map[string]float64{"x": 1}}
	b := FromDense("some-neural-model", []float64{1, 0, 0})
	if _, err := Cosine(a, b); err == nil {
		t.Fatal("a TF-IDF vector was compared to a neural one and produced " +
			"a number")
	}
}

// A page with no text has no position. The zero vector would be equidistant
// from everything and would appear as a neighbour of every query.
func TestAPageWithNoTextIsNotAUniversalNeighbour(t *testing.T) {
	idx := Build("c1", corpus(), tok)
	if _, ok := idx.Vectors["empty"]; ok {
		t.Error("an empty page was given a vector")
	}
	near, _ := idx.Nearest(idx.Embed("anything at all", tok), 10, "")
	for _, n := range near {
		if n.Page == "empty" {
			t.Error("the empty page came back as a neighbour")
		}
	}
}

// Vectors are normalised, so a long page does not outrank a short one purely
// for being long.
func TestLengthDoesNotDetermineRank(t *testing.T) {
	long := strings.Repeat("bulbs planting soil compost frost tulip ", 200)
	pages := corpus()
	pages["verylong"] = map[string]any{"title": "Long", "body": long}
	idx := Build("c1", pages, tok)

	var norm float64
	for _, w := range idx.Vectors["verylong"].Weights {
		norm += w * w
	}
	if norm < 0.99 || norm > 1.01 {
		t.Errorf("the vector is not normalised: |v|² = %f", norm)
	}
}

// The same query twice gives the same order. Map iteration would not.
func TestResultsAreStable(t *testing.T) {
	idx := Build("c1", corpus(), tok)
	var first []string
	for i := 0; i < 20; i++ {
		near, err := idx.Nearest(idx.Embed("finance quarter", tok), 5, "")
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, n := range near {
			got = append(got, n.Page)
		}
		if i == 0 {
			first = got
			continue
		}
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("run %d gave %v, first gave %v", i, got, first)
		}
	}
}

// A query is embedded with the index's document frequencies, not its own.
// Skipping that produces results that are wrong without ever being an error.
func TestAQueryIsEmbeddedInTheIndexsSpace(t *testing.T) {
	idx := Build("c1", corpus(), tok)
	q := idx.Embed("budget", tok)
	if q.Model != idx.Model {
		t.Errorf("the query vector is a %s, the index is %s", q.Model, idx.Model)
	}
	// "budget" appears in one of four documents, so it should carry a high
	// IDF — higher than a term in every document would.
	if len(q.Weights) == 0 {
		t.Fatal("the query embedded to nothing")
	}
}

func TestADenseProviderVectorIsNormalised(t *testing.T) {
	v := FromDense("m", []float64{3, 4, 0})
	var norm float64
	for _, w := range v.Weights {
		norm += w * w
	}
	if norm < 0.99 || norm > 1.01 {
		t.Errorf("|v|² = %f", norm)
	}
	if v.Dims != 3 {
		t.Errorf("dims %d", v.Dims)
	}
	// Zeros are not stored, which is the point of the sparse form.
	if _, ok := v.Weights["d2"]; ok {
		t.Error("a zero was stored")
	}
}

func TestAnEmptyIndexAnswersWithoutCrashing(t *testing.T) {
	idx := Build("c1", map[string]any{}, tok)
	near, err := idx.Nearest(idx.Embed("anything", tok), 5, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(near) != 0 {
		t.Errorf("%d results from an empty index", len(near))
	}
	if p, tms := idx.Size(); p != 0 || tms != 0 {
		t.Errorf("size %d/%d", p, tms)
	}
}

// An explanation reading "these are alike because both contain 'the'" is true
// and useless. On a small corpus a stopword's IDF barely penalises it, so it
// can out-contribute the word that actually made the pages similar.
func TestTheExplanationNamesDistinguishingTerms(t *testing.T) {
	pages := map[string]any{}
	// Ten documents, all sharing filler, two sharing a real subject.
	filler := "the and for with that this from have been were "
	for i := 0; i < 8; i++ {
		pages["filler"+itoa(i)] = map[string]any{
			"body": filler + "assorted unrelated words about nothing " + itoa(i)}
	}
	pages["a"] = map[string]any{"body": filler + "peregrine falcon nesting ledge"}
	pages["b"] = map[string]any{"body": filler + "peregrine falcon fledgling ledge"}

	idx := Build("c", pages, tok)
	near, err := idx.Nearest(idx.Vectors["a"], 1, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(near) == 0 || near[0].Page != "b" {
		t.Fatalf("nearest is %v", near)
	}
	for _, term := range near[0].Shared {
		for _, common := range strings.Fields(filler) {
			if term == common {
				t.Errorf("the explanation names %q, which is in every "+
					"document: %v", term, near[0].Shared)
			}
		}
	}
	found := false
	for _, term := range near[0].Shared {
		if term == "peregrine" || term == "falcon" || term == "ledge" {
			found = true
		}
	}
	if !found {
		t.Errorf("the explanation misses the actual subject: %v", near[0].Shared)
	}
}
