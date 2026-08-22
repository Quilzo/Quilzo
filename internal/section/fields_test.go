package section

import "testing"

func featuresPage() map[string]any {
	body, err := Insert(map[string]any{"title": "A page"}, "features", 0)
	if err != nil {
		panic(err)
	}
	return body
}

func fieldValue(fields []Editable, path string) (string, bool) {
	for _, f := range fields {
		if f.Path == path {
			return f.Value, true
		}
	}
	return "", false
}

// Every value inside a section has to be reachable as its own labelled input,
// or the screen is a JSON textarea with extra steps.
func TestEveryValueInASectionBecomesAField(t *testing.T) {
	fields, err := Fields(featuresPage(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"title", "columns", "items.0.title", "items.2.body"} {
		if _, ok := fieldValue(fields, want); !ok {
			t.Errorf("no field for %q; got %d fields", want, len(fields))
		}
	}
	for _, f := range fields {
		if f.Label == "" {
			t.Errorf("%s has no label, so no screen can announce it", f.Path)
		}
		if f.Path == "items.0.title" && f.Label != "items · 1 · title" {
			t.Errorf("items.0.title is labelled %q; a person counts from one", f.Label)
		}
	}
}

// A path the section does not have is ignored rather than created. The form's
// field names arrive from whoever posted them, and a shape somebody can extend
// by posting to it is a shape nobody can reason about.
func TestOnlyExistingLeavesAreWritten(t *testing.T) {
	next, err := Apply(featuresPage(), 0, map[string]string{
		"title":             "Changed",
		"items.0.title":     "First card",
		"invented":          "should not appear",
		"items.0.invented":  "nor this",
		"items.99.title":    "nor this either",
		"items":             "and a container is not a leaf",
		"../../etc/passwd":  "certainly not",
		"items.0.title.sub": "nor a leaf inside a leaf",
	})
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := Fields(next, 0)

	if v, _ := fieldValue(fields, "title"); v != "Changed" {
		t.Errorf("the title was not written: %q", v)
	}
	if v, _ := fieldValue(fields, "items.0.title"); v != "First card" {
		t.Errorf("the card title was not written: %q", v)
	}
	for _, forbidden := range []string{"invented", "items.0.invented"} {
		if _, present := fieldValue(fields, forbidden); present {
			t.Errorf("%q was created by a post", forbidden)
		}
	}
	if len(Lists(next, 0)) == 0 {
		t.Error("posting to a container name destroyed the list")
	}
}

// A number stays a number. A percentage that becomes the string "72" still
// renders and then stops satisfying the filter that makes a chart's custom
// property provably numeric — which is the guarantee the CSS injection rule
// depends on.
func TestANumberIsWrittenBackAsANumber(t *testing.T) {
	body, err := Insert(map[string]any{}, "metrics", 0)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Apply(body, 0, map[string]string{"items.0.pct": "41"})
	if err != nil {
		t.Fatal(err)
	}
	inner := next[Field].([]any)[0].(map[string]any)["metrics"].(map[string]any)
	pct := inner["items"].([]any)[0].(map[string]any)["pct"]
	if _, isNumber := pct.(float64); !isNumber {
		t.Errorf("pct came back as %T (%v), not a number", pct, pct)
	}
}

// Adding an entry copies the shape of the one before it and clears the words,
// because a list with the same card twice is a list somebody has to edit twice.
func TestAddingAnItemCopiesTheShapeAndClearsTheText(t *testing.T) {
	body, err := AddItem(featuresPage(), 0, "items")
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := Fields(body, 0)
	value, present := fieldValue(fields, "items.3.title")
	if !present {
		t.Fatalf("no fourth item was added; %d fields", len(fields))
	}
	if value != "" {
		t.Errorf("the new item arrived with text in it: %q", value)
	}
	if _, present := fieldValue(fields, "items.3.body"); !present {
		t.Error("the new item did not copy the shape of the others")
	}
}

// Removing takes the right one out and leaves the rest in order.
func TestRemovingAnItemLeavesTheOthersInOrder(t *testing.T) {
	body, err := Apply(featuresPage(), 0, map[string]string{
		"items.0.title": "one", "items.1.title": "two", "items.2.title": "three",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err = RemoveItem(body, 0, "items", 1)
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := Fields(body, 0)
	first, _ := fieldValue(fields, "items.0.title")
	second, _ := fieldValue(fields, "items.1.title")
	if first != "one" || second != "three" {
		t.Errorf("after removing the middle one: %q, %q", first, second)
	}
	if _, present := fieldValue(fields, "items.2.title"); present {
		t.Error("a third item is still there")
	}
}

// Editing one section leaves the page around it, the sections beside it, and
// the body it was given alone — the last because these run against content
// other requests are reading from.
func TestEditingOneSectionLeavesTheRestAlone(t *testing.T) {
	body, err := Insert(featuresPage(), "quote", 1)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Apply(body, 0, map[string]string{"title": "Changed"})
	if err != nil {
		t.Fatal(err)
	}
	if next["title"] != "A page" {
		t.Errorf("the page's own title became %v", next["title"])
	}
	placed := On(next)
	if len(placed) != 2 || placed[1].Kind != "quote" {
		t.Errorf("the other section changed: %+v", placed)
	}
	before, _ := Fields(body, 0)
	if v, _ := fieldValue(before, "title"); v != "What you get" {
		t.Errorf("Apply mutated the body it was given: title is now %q", v)
	}
}

// Every kind's stub has to survive a round trip through the form. A kind whose
// values cannot be read out and written back is one the screen shows and cannot
// save.
func TestEveryKindRoundTripsThroughTheForm(t *testing.T) {
	for _, k := range Kinds() {
		t.Run(k.Name, func(t *testing.T) {
			body, err := Insert(map[string]any{}, k.Name, 0)
			if err != nil {
				t.Fatal(err)
			}
			fields, err := Fields(body, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(fields) == 0 {
				t.Fatalf("%s has nothing editable, so its screen is empty", k.Name)
			}
			values := map[string]string{}
			for _, f := range fields {
				if f.Number {
					values[f.Path] = "7"
					continue
				}
				values[f.Path] = "edited"
			}
			next, err := Apply(body, 0, values)
			if err != nil {
				t.Fatal(err)
			}
			after, err := Fields(next, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != len(fields) {
				t.Errorf("%s had %d fields and has %d after a round trip",
					k.Name, len(fields), len(after))
			}
			for _, f := range after {
				want := "edited"
				if f.Number {
					want = "7"
				}
				if f.Value != want {
					t.Errorf("%s: %s came back as %q, wanted %q",
						k.Name, f.Path, f.Value, want)
				}
			}
		})
	}
}
