package menu

import (
	"strings"
	"testing"
)

func pages(names ...string) map[string]any {
	out := map[string]any{}
	for _, n := range names {
		out[n] = map[string]any{"title": n}
	}
	return out
}

// A menu entry cannot be saved pointing at a page that does not exist.
//
// Drupal's issue queue has this as an open problem with five contributed
// modules patching around it; WordPress is quieter and no better. Refusing at
// the point of the edit costs nothing and removes the class.
func TestAnEntryPointingAtNothingIsRefused(t *testing.T) {
	m := &Menu{Name: "main", Items: []Item{
		{ID: "1", Label: "About", Kind: Page, Target: "about"},
	}}
	if err := m.Validate(pages("about")); err != nil {
		t.Fatalf("refused a valid entry: %v", err)
	}
	err := m.Validate(pages("index"))
	if err == nil {
		t.Fatal("accepted an entry pointing at a page that does not exist")
	}
	if !strings.Contains(err.Error(), "about") {
		t.Errorf("the refusal does not name the missing target: %v", err)
	}
}

// The version nobody checks for: resolves in the draft, broken for readers.
func TestAnEntryPointingAtAnUnpublishedPageBreaksThePublication(t *testing.T) {
	s := &Set{}
	if err := s.Add(Menu{Name: "main", Items: []Item{
		{ID: "1", Label: "About", Kind: Page, Target: "about"},
		{ID: "2", Label: "Home", Kind: Page, Target: "index"},
	}}); err != nil {
		t.Fatal(err)
	}

	// Both exist in the draft; only index is going live.
	broken := s.Broken(pages("index"))
	if len(broken) != 1 {
		t.Fatalf("expected one problem, got %d: %v", len(broken), broken)
	}
	if broken[0].Target != "about" {
		t.Errorf("named the wrong entry: %v", broken[0])
	}
	if !strings.Contains(broken[0].String(), "not published") {
		t.Errorf("the message does not say why: %s", broken[0])
	}

	if n := len(s.Broken(pages("index", "about"))); n != 0 {
		t.Errorf("reported %d problems when everything is published", n)
	}
}

// A menu is rendered into pages readers click, so the scheme is restricted.
func TestOnlyHTTPSchemesAreAcceptedForExternalLinks(t *testing.T) {
	for _, target := range []string{
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"vbscript:msgbox",
	} {
		err := ValidateItem(Item{Label: "x", Kind: External, Target: target}, nil)
		if err == nil {
			t.Errorf("accepted %q as a menu target; that is script execution "+
				"with a label on it", target)
		}
	}
	for _, target := range []string{"https://example.org", "http://example.org/x"} {
		if err := ValidateItem(Item{Label: "x", Kind: External, Target: target},
			nil); err != nil {
			t.Errorf("refused %q: %v", target, err)
		}
	}
}

// Rendering reports what resolves rather than silently dropping it.
func TestRenderCarriesWhetherEachEntryResolves(t *testing.T) {
	m := &Menu{Name: "main", Items: []Item{
		{ID: "1", Label: "Home", Kind: Page, Target: "index", Order: 1},
		{ID: "2", Label: "Gone", Kind: Page, Target: "removed", Order: 2},
		{ID: "3", Label: "Out", Kind: External, Target: "https://example.org", Order: 3},
	}}
	got := m.Render(pages("index"), pages("index"))
	if len(got) != 3 {
		t.Fatalf("rendered %d of 3 entries; a broken one should be reported, "+
			"not hidden", len(got))
	}
	if !got[0].Resolves || got[1].Resolves {
		t.Errorf("resolution is wrong: %v", got)
	}
	if !got[2].Resolves {
		t.Error("an external link was marked unresolved; it is never fetched " +
			"and cannot be checked, so it is not reported as broken")
	}
}

// Order is stable even when two entries share an order number.
func TestRenderIsStableWhenOrdersCollide(t *testing.T) {
	m := &Menu{Name: "main", Items: []Item{
		{ID: "b", Label: "Beta", Kind: Heading, Order: 1},
		{ID: "a", Label: "Alpha", Kind: Heading, Order: 1},
	}}
	first := m.Render(nil, nil)
	for i := 0; i < 10; i++ {
		again := m.Render(nil, nil)
		for j := range first {
			if first[j].ID != again[j].ID {
				t.Fatal("two entries with the same order rendered in a " +
					"different sequence on a second call")
			}
		}
	}
	if first[0].Label != "Alpha" {
		t.Errorf("the tie broke on something other than the label: %v", first[0])
	}
}

// Nesting is a tree, and a loop would not terminate.
func TestALoopInTheNestingIsRefused(t *testing.T) {
	m := &Menu{Name: "main", Items: []Item{
		{ID: "a", Label: "A", Kind: Heading, Parent: "b"},
		{ID: "b", Label: "B", Kind: Heading, Parent: "a"},
	}}
	if err := m.Validate(nil); err == nil {
		t.Error("accepted a loop; rendering it would not terminate")
	}
}

// Renaming a page has to be able to fix the menus that named it.
func TestRetargetRewritesEveryMentionOfAPage(t *testing.T) {
	s := &Set{}
	_ = s.Add(Menu{Name: "main", Items: []Item{
		{ID: "1", Label: "Old", Kind: Page, Target: "old"},
	}})
	_ = s.Add(Menu{Name: "footer", Items: []Item{
		{ID: "1", Label: "Also old", Kind: Page, Target: "old"},
		{ID: "2", Label: "Other", Kind: Page, Target: "other"},
	}})

	if n := s.Retarget("old", "new"); n != 2 {
		t.Errorf("rewrote %d entries, expected 2", n)
	}
	if n := len(s.Mentioning("old")); n != 0 {
		t.Errorf("%d entries still point at the old name", n)
	}
	if n := len(s.Mentioning("new")); n != 2 {
		t.Errorf("%d entries point at the new name, expected 2", n)
	}
}

// Deleting a page can name what would break.
func TestMentioningNamesWhatWouldBreak(t *testing.T) {
	s := &Set{}
	_ = s.Add(Menu{Name: "main", Items: []Item{
		{ID: "1", Label: "About us", Kind: Page, Target: "about"},
	}})
	got := s.Mentioning("about")
	if len(got) != 1 || got[0].Item != "About us" {
		t.Fatalf("did not name the entry: %v", got)
	}
}

// A heading has no target, and an entry with a target is not a heading.
func TestAHeadingCannotAlsoBeALink(t *testing.T) {
	if err := ValidateItem(Item{Label: "Group", Kind: Heading,
		Target: "index"}, nil); err == nil {
		t.Error("accepted a heading with a target")
	}
	if err := ValidateItem(Item{Label: "Group", Kind: Heading}, nil); err != nil {
		t.Errorf("refused a plain heading: %v", err)
	}
}

// Bounds are refused rather than accumulated.
func TestBoundsAreEnforced(t *testing.T) {
	m := &Menu{Name: "main"}
	for i := 0; i <= MaxItems; i++ {
		m.Items = append(m.Items, Item{
			ID:    string(rune('a'+i%26)) + string(rune('a'+i/26)),
			Label: "x", Kind: Heading,
		})
	}
	if err := m.Validate(nil); err == nil {
		t.Error("accepted a menu longer than anybody navigates")
	}
}

// Nothing published means nothing resolves.
//
// Render's nil map means "do not check this side", which is right for the admin
// and wrong here: the gate is asked whether readers can follow these links, and
// when the live side cannot be read the answer is no. This used to pass — the
// pipeline check reported every entry fine on a site where every link was a
// 404, which is the exact case it exists for.
func TestAMenuIsBrokenWhenNothingIsPublished(t *testing.T) {
	set := &Set{Menus: []Menu{{
		Name: "main",
		Items: []Item{
			{ID: "shop", Label: "Shop", Kind: Page, Target: "shop"},
			{ID: "about", Label: "About", Kind: Page, Target: "about"},
			{ID: "away", Label: "Elsewhere", Kind: External,
				Target: "https://example.com"},
			{ID: "group", Label: "More", Kind: Heading},
		},
	}}}

	broken := set.Broken(nil)
	if len(broken) != 2 {
		t.Fatalf("wanted both page entries reported with nothing published, "+
			"got %d: %v", len(broken), broken)
	}
	for _, p := range broken {
		if p.Target != "shop" && p.Target != "about" {
			t.Errorf("reported %q, which is not a page entry", p.Target)
		}
	}

	// And once those pages are live, they stop being reported.
	live := map[string]any{"shop": map[string]any{}, "about": map[string]any{}}
	if rest := set.Broken(live); len(rest) != 0 {
		t.Errorf("published pages still reported as broken: %v", rest)
	}
}
