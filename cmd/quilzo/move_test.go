// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

func movable(t *testing.T) (string, *schema.Store) {
	t.Helper()
	// The package writer, which main() sets and a test does not have.
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index":       map[string]any{"title": "Home"},
		"returns":     map[string]any{"title": "Returns"},
		"blog/first":  map[string]any{"title": "First"},
		"blog/second": map[string]any{"title": "Second", "about": "returns"},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}

	reg := schema.NewRegistry()
	if err := reg.Add(schema.Type{
		Name: "article",
		Fields: []schema.Field{
			{Name: "title", Kind: schema.Text, Required: true},
			{Name: "about", Kind: schema.Reference},
		},
	}); err != nil {
		t.Fatal(err)
	}
	st := &schema.Store{Registry: reg,
		Bound: map[string]string{"blog/second": "article"}}
	if err := saveJSON(filepath.Join(root, "types.json"), st); err != nil {
		t.Fatal(err)
	}

	// A menu entry pointing at the page about to move.
	set := &menu.Set{}
	if err := set.Add(menu.Menu{Name: "main", Label: "Main", Items: []menu.Item{
		{ID: "returns", Label: "Returns", Kind: menu.Page, Target: "returns"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(menuPath(root), set); err != nil {
		t.Fatal(err)
	}
	return root, st
}

// Moving a page carries what names it.
//
// A page's name is where it is — the slash has been structure to the store, to
// the public server and to auth.covers since each of them existed — so moving
// one is renaming it. Renaming was `add` the new, `add --remove` the old, and
// then find out at the publish gate which other pages named it. Nobody does
// that twice; what people do instead is leave the page where it is and put a
// link to it somewhere, which is how a site's structure stops being its names.
func TestMovingAPageCarriesTheReferencesAndTheMenu(t *testing.T) {
	root, _ := movable(t)

	if err := cmdMove(root, []string{"returns", "legal/returns"}); err != nil {
		t.Fatal(err)
	}

	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	if _, old := pages["returns"]; old {
		t.Error("the page is still at its old name")
	}
	if _, now := pages["legal/returns"]; !now {
		t.Fatal("the page is not at its new name")
	}

	// The reference followed it, rather than waiting to be a refused publish.
	st, err := schema.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	in := st.LinksTo(pages, "legal/returns")
	if len(in) != 1 || in[0].From != "blog/second" {
		t.Errorf("the reference did not follow the page: %+v", in)
	}
	if bad := st.Unresolved(pages); len(bad) != 0 {
		t.Errorf("the move left a reference pointing at nothing: %+v", bad)
	}

	// And so did the menu, which menu.Retarget was written for.
	set := &menu.Set{}
	if err := loadJSON(menuPath(root), set); err != nil {
		t.Fatal(err)
	}
	for _, m := range set.Mentioning("returns") {
		t.Errorf("a menu entry still points at the old name: %+v", m)
	}
	if len(set.Mentioning("legal/returns")) != 1 {
		t.Error("the menu entry does not point at the new name")
	}
}

// A branch moves with everything under it.
func TestMovingABranchTakesItsChildren(t *testing.T) {
	root, _ := movable(t)

	if err := cmdMove(root, []string{"blog", "writing"}); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"writing/first", "writing/second"} {
		if _, there := pages[want]; !there {
			t.Errorf("%s is not there; the branch moved and a child did not",
				want)
		}
	}
	for _, gone := range []string{"blog/first", "blog/second"} {
		if _, there := pages[gone]; there {
			t.Errorf("%s is still at its old name", gone)
		}
	}
}

// A move into a name that is taken is refused, rather than replacing it.
func TestMovingOntoAnExistingPageIsRefused(t *testing.T) {
	root, _ := movable(t)

	err := cmdMove(root, []string{"returns", "index"})
	if err == nil {
		t.Fatal("moving a page onto another one was allowed, and the page " +
			"that was there is gone")
	}
	s, _ := open(root)
	pages, _ := site.PagesAt(s, site.RefDraft)
	if body, there := pages["index"]; !there ||
		body.(map[string]any)["title"] != "Home" {
		t.Error("the page that was in the way was replaced anyway")
	}
}

// A move into itself is refused, because it would have to happen to itself.
func TestMovingABranchInsideItselfIsRefused(t *testing.T) {
	root, _ := movable(t)
	if err := cmdMove(root, []string{"blog", "blog/older"}); err == nil {
		t.Error("moving a branch inside itself was allowed")
	}
}

// And a dry run changes nothing.
func TestADryRunMoveChangesNothing(t *testing.T) {
	root, _ := movable(t)
	s, _ := open(root)
	before := s.GetRef(site.RefDraft)

	if err := cmdMove(root, []string{"returns", "legal/returns",
		"--dry-run"}); err != nil {
		t.Fatal(err)
	}
	after, _ := open(root)
	if after.GetRef(site.RefDraft) != before {
		t.Error("a dry run wrote a commit")
	}
	menus, err := os.ReadFile(menuPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(menus), `"returns"`) {
		t.Error("a dry run retargeted the menu")
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
