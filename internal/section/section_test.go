package section

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
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

// A page's arrangement is checked against the catalogue.
//
// A section whose kind this build does not know renders as nothing at all, so a
// page carrying "gallry" is a page with a gallery missing, no message anywhere,
// and a publish that reported success. The kinds are a closed list, which makes
// this a check the tool can make and an author cannot.
func TestAnUnknownKindIsRefusedAndAGoodPageIsNot(t *testing.T) {
	good := map[string]any{"sections": []any{
		map[string]any{"features": map[string]any{"title": "Three things"}},
		map[string]any{"gallery": map[string]any{"title": "Pictures",
			"shape": "square"}},
	}}
	if bad, _ := Validate(good); len(bad) != 0 {
		t.Errorf("a page of real sections was refused: %v", bad)
	}

	typo := map[string]any{"sections": []any{
		map[string]any{"gallry": map[string]any{"title": "Pictures"}},
	}}
	bad, _ := Validate(typo)
	if len(bad) != 1 {
		t.Fatalf("wanted one problem for a misspelled kind, got %v", bad)
	}
	if !strings.Contains(bad[0].Detail, "gallry") ||
		!strings.Contains(bad[0].Detail, "gallery") {
		t.Errorf("the refusal does not quote the typo and offer the real "+
			"kinds: %s", bad[0].Detail)
	}

	// Two kinds in one entry: the first renders and the rest vanish.
	both := map[string]any{"sections": []any{
		map[string]any{
			"quote":  map[string]any{"text": "One"},
			"notice": map[string]any{"title": "Two"},
		},
	}}
	if bad, _ := Validate(both); len(bad) == 0 {
		t.Error("an entry naming two kinds was accepted, so one of them would " +
			"silently not render")
	}

	// A page with no sections at all is not a page with a broken arrangement.
	if bad, _ := Validate(map[string]any{"title": "Plain"}); len(bad) != 0 {
		t.Errorf("a page with no sections was reported: %v", bad)
	}
}

// Every kind that renders a picture has somewhere to put one.
//
// The layouts read a split's image, a carousel card's, a person's portrait and a
// video's source, and the stubs for three of those named no such field — so a
// section added through the editor had no input for it and no picker beside it.
// "An image beside prose" was a kind you could not put an image in.
//
// And no stub may name a file: the video's said /media/replace-me.mp4, which no
// store holds, so adding one and publishing produced a player that could not
// play anything.
func TestEveryPictureBearingKindHasItsField(t *testing.T) {
	want := map[string][]string{
		"split":    {"image", "alt"},
		"gallery":  {"image", "alt"},
		"carousel": {"image", "alt"},
		"people":   {"image", "alt"},
		"video":    {"src", "poster"},
	}
	for name, fields := range want {
		kind, ok := Lookup(name)
		if !ok {
			t.Errorf("there is no %s kind", name)
			continue
		}
		encoded, err := json.Marshal(kind.Stub)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fields {
			if !strings.Contains(string(encoded), `"`+f+`"`) {
				t.Errorf("the %s stub has no %q, so a section added through "+
					"the editor has nowhere to choose one", name, f)
			}
		}
		for _, path := range regexp.MustCompile(`/media/[^"]+`).
			FindAllString(string(encoded), -1) {
			t.Errorf("the %s stub names %s, which no store holds: adding one "+
				"and publishing produces a broken picture", name, path)
		}
	}
}
