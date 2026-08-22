package section

import (
	"reflect"
	"testing"
)

func page(kinds ...string) map[string]any {
	list := make([]any, 0, len(kinds))
	for _, k := range kinds {
		list = append(list, map[string]any{k: map[string]any{"title": k}})
	}
	return map[string]any{"title": "A page", Field: list}
}

func order(t *testing.T, body any) []string {
	t.Helper()
	var out []string
	for _, p := range On(body) {
		out = append(out, p.Kind)
	}
	return out
}

// The four moves, and the arithmetic that is easy to get subtly wrong.
func TestTheMovesDoWhatTheySay(t *testing.T) {
	start := page("features", "metrics", "faq")

	moved, err := Move(start, 2, -1)
	if err != nil {
		t.Fatal(err)
	}
	if got := order(t, moved); !reflect.DeepEqual(got, []string{"features", "faq", "metrics"}) {
		t.Errorf("moving the last one up gave %v", got)
	}

	inserted, err := Insert(start, "quote", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := order(t, inserted); !reflect.DeepEqual(got,
		[]string{"features", "quote", "metrics", "faq"}) {
		t.Errorf("inserting at 1 gave %v", got)
	}

	appended, err := Insert(start, "quote", 99)
	if err != nil {
		t.Fatal(err)
	}
	if got := order(t, appended); !reflect.DeepEqual(got,
		[]string{"features", "metrics", "faq", "quote"}) {
		t.Errorf("inserting past the end gave %v", got)
	}

	removed, err := Remove(start, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := order(t, removed); !reflect.DeepEqual(got, []string{"metrics", "faq"}) {
		t.Errorf("removing the first gave %v", got)
	}
}

// Every move returns a copy. The body it is given comes out of the decoded
// content tree that other requests are reading from, so a mutation would change
// what a concurrent render sees — and only after the first write, which is the
// class of bug that cannot be reproduced on a fresh process.
func TestNoMoveMutatesThePageItWasGiven(t *testing.T) {
	start := page("features", "metrics")
	before := order(t, start)

	if _, err := Move(start, 0, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := Insert(start, "faq", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(start, 1); err != nil {
		t.Fatal(err)
	}

	if after := order(t, start); !reflect.DeepEqual(before, after) {
		t.Errorf("the original changed: %v became %v", before, after)
	}
}

// Two sections added from one kind must not share the slices inside the stub.
// If they did, editing one would edit the other, and the second would appear to
// change on its own.
func TestTwoSectionsOfAKindDoNotShareTheirContent(t *testing.T) {
	body, err := Insert(map[string]any{}, "features", 0)
	if err != nil {
		t.Fatal(err)
	}
	body, err = Insert(body, "features", 1)
	if err != nil {
		t.Fatal(err)
	}
	list := body[Field].([]any)
	first := list[0].(map[string]any)["features"].(map[string]any)
	second := list[1].(map[string]any)["features"].(map[string]any)

	first["title"] = "changed"
	if second["title"] == "changed" {
		t.Error("the two sections share their content")
	}
	firstItems := first["items"].([]any)
	secondItems := second["items"].([]any)
	firstItems[0].(map[string]any)["title"] = "changed too"
	if secondItems[0].(map[string]any)["title"] == "changed too" {
		t.Error("the two sections share the items inside them")
	}
}

// A move off either end is refused with a message rather than clamped, because
// a button that silently does nothing is worse than one that is not offered.
func TestMovingOffTheEndIsRefused(t *testing.T) {
	body := page("features", "metrics")
	if _, err := Move(body, 0, -1); err == nil {
		t.Error("moving the first section up was allowed")
	}
	if _, err := Move(body, 1, 1); err == nil {
		t.Error("moving the last section down was allowed")
	}
	if _, err := Remove(body, 7); err == nil {
		t.Error("removing a section that is not there was allowed")
	}
	if _, err := Insert(body, "nonexistent", 0); err == nil {
		t.Error("adding a kind that does not exist was allowed")
	}
}

// Removing the last section leaves no key rather than an empty list. They render
// the same and the absent form is the one that reads correctly in a diff.
func TestRemovingTheLastSectionLeavesNoKey(t *testing.T) {
	body, err := Remove(page("features"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := body[Field]; present {
		t.Errorf("an empty %s key was left behind: %v", Field, body)
	}
	if body["title"] != "A page" {
		t.Error("removing a section lost the rest of the page")
	}
}

// A page naming a kind this build does not have is reported, not hidden. It is
// either a kind somebody removed from a layout or a typo, and both are things
// somebody needs to see rather than a row that quietly renders nothing.
func TestAnUnknownKindIsReported(t *testing.T) {
	body := map[string]any{Field: []any{
		map[string]any{"invented": map[string]any{"title": "x"}},
	}}
	placed := On(body)
	if len(placed) != 1 || !placed[0].Unknown {
		t.Fatalf("expected one unknown section, got %+v", placed)
	}
	if placed[0].Kind != "invented" {
		t.Errorf("the unknown kind was not named: %q", placed[0].Kind)
	}
}

// Every kind in the catalogue has to describe itself and arrive with content
// that renders. A stub that is empty is a section somebody adds and cannot see.
func TestEveryKindHasASummaryAndAStubThatSaysSomething(t *testing.T) {
	if len(Kinds()) < 15 {
		t.Fatalf("only %d kinds", len(Kinds()))
	}
	for _, k := range Kinds() {
		if len(k.Summary) < 25 {
			t.Errorf("%s does not say what it is for", k.Name)
		}
		if k.Group == "" {
			t.Errorf("%s is in no group, so no screen can order it", k.Name)
		}
		if len(k.Stub) == 0 {
			t.Errorf("%s has no stub, so adding it renders nothing", k.Name)
		}
		if label(k.Stub) == "" && k.Name != "notice" {
			t.Errorf("%s has a stub with no line that names it, so a list of "+
				"sections cannot label it", k.Name)
		}
	}
}
