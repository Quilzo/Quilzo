package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rsh1k/scrivet/internal/menu"
	"github.com/rsh1k/scrivet/internal/out"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/taxonomy"
)

func vocabPath(root string) string { return filepath.Join(root, "vocabularies.json") }
func menuPath(root string) string  { return filepath.Join(root, "menus.json") }

func loadVocabularies(root string) (*taxonomy.Set, error) {
	s := &taxonomy.Set{}
	return s, loadJSON(vocabPath(root), s)
}

func loadMenus(root string) (*menu.Set, error) {
	s := &menu.Set{}
	return s, loadJSON(menuPath(root), s)
}

// cmdTerms reads and checks the vocabularies.
//
// Reading and checking only, from here. Editing a controlled vocabulary is a
// governance act — it decides what everybody else is allowed to say about the
// content — and doing it through a screen where the existing terms and their
// usage counts are visible is better than doing it blind from a shell. The
// command that matters on this surface is the one a pipeline runs: check.
func cmdTerms(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return termsList(root)
	case "check":
		return termsCheck(root)
	default:
		return fmt.Errorf("unknown terms command %q; try list or check", args[0])
	}
}

func termsList(root string) error {
	set, err := loadVocabularies(root)
	if err != nil {
		return err
	}
	pages, err := draftPages(root)
	if err != nil {
		pages = map[string]any{}
	}
	if w.Mode == out.JSON {
		w.JSON(set)
		return nil
	}
	if len(set.Vocabularies) == 0 {
		w.Human("no vocabularies\n")
		w.Human("  %sa vocabulary is a closed list of terms; content can only "+
			"carry%s\n", dim, reset)
		w.Human("  %sterms that are in one, which is what stops two thousand "+
			"tags%s\n", dim, reset)
		return nil
	}
	for _, name := range set.Names() {
		v, _ := set.Get(name)
		state := green + "closed" + reset
		if v.Open {
			state = yellow + "open" + reset
		}
		w.Human("%s%s%s  %s\n", bold, v.Name, reset, state)
		usage := taxonomy.Count(pages, v.Name)
		for _, t := range v.Sorted() {
			w.Human("  %s%s%s", strings.Repeat("  ", t.Depth), t.ID, "")
			if n := usage.Count[t.ID]; n > 0 {
				w.Human("  %s%d item(s)%s", dim, n, reset)
			}
			if len(t.Synonyms) > 0 {
				w.Human("  %salso: %s%s", dim, strings.Join(t.Synonyms, ", "), reset)
			}
			w.Human("\n")
		}
	}
	return nil
}

// termsCheck reports content carrying terms that no longer exist.
//
// The dangling-reference check, from the direction nothing else looks: a
// vocabulary edited outside this program, or content imported from somewhere
// with its own idea of what a tag is, can both leave a page classified under
// something that is not a term.
func termsCheck(root string) error {
	set, err := loadVocabularies(root)
	if err != nil {
		return err
	}
	pages, err := draftPages(root)
	if err != nil {
		return err
	}

	type orphan struct{ Page, Vocabulary, Term string }
	var found []orphan
	for _, name := range set.Names() {
		v, _ := set.Get(name)
		for page, body := range pages {
			for _, id := range taxonomy.Of(body, name) {
				if _, ok := v.Term(id); !ok {
					found = append(found, orphan{page, name, id})
				}
			}
		}
	}

	if w.Mode == out.JSON {
		w.JSON(map[string]any{"orphans": found, "clean": len(found) == 0})
		if len(found) > 0 {
			return errBlocked{fmt.Errorf("%d classification(s) point at terms "+
				"that do not exist", len(found))}
		}
		return nil
	}
	if len(found) == 0 {
		w.Human("%severy term on every page exists%s\n", green, reset)
		return nil
	}
	for _, o := range found {
		w.Human("  %s%s%s carries %s/%s, which is not a term\n",
			red, o.Page, reset, o.Vocabulary, o.Term)
	}
	return errBlocked{fmt.Errorf("%d classification(s) point at terms that do "+
		"not exist", len(found))}
}

// cmdMenus reads and checks the navigation.
func cmdMenus(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return menusList(root)
	case "check":
		return menusCheck(root)
	default:
		return fmt.Errorf("unknown menu command %q; try list or check", args[0])
	}
}

func menusList(root string) error {
	set, err := loadMenus(root)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	draft := site.PagesOf(s, s.GetRef(site.RefDraft))
	live := site.PagesOf(s, s.GetRef(site.RefLive))

	if w.Mode == out.JSON {
		w.JSON(set)
		return nil
	}
	if len(set.Menus) == 0 {
		w.Human("no menus\n")
		return nil
	}
	for _, name := range set.Names() {
		m, _ := set.Get(name)
		w.Human("%s%s%s\n", bold, m.Name, reset)
		for _, it := range m.Render(draft, live) {
			mark := green + "ok     " + reset
			switch {
			case !it.Resolves:
				mark = red + "missing" + reset
			case !it.Live:
				mark = yellow + "draft  " + reset
			}
			w.Human("  %s %s%s  %s%s%s\n", mark,
				strings.Repeat("  ", it.Depth), it.Label, dim, it.Target, reset)
		}
	}
	return nil
}

// menusCheck is the gate, on the surface a pipeline runs it from.
//
// Exits non-zero when an entry points at a page that is not published, which
// is the failure that reaches readers. Run it before a deployment and the
// broken link is a build failure rather than a support ticket.
func menusCheck(root string) error {
	set, err := loadMenus(root)
	if err != nil {
		return err
	}
	s, err := open(root)
	if err != nil {
		return err
	}
	broken := set.Broken(site.PagesOf(s, s.GetRef(site.RefLive)))

	if w.Mode == out.JSON {
		w.JSON(map[string]any{"broken": broken, "clean": len(broken) == 0})
		if len(broken) > 0 {
			return errBlocked{fmt.Errorf("%d navigation entr(y/ies) point at "+
				"pages that are not published", len(broken))}
		}
		return nil
	}
	if len(broken) == 0 {
		w.Human("%severy navigation entry resolves for a reader%s\n", green, reset)
		return nil
	}
	for _, b := range broken {
		w.Human("  %s%s%s\n", red, b, reset)
	}
	w.Human("\n  %sthese work for you and 404 for everybody else%s\n", dim, reset)
	return errBlocked{fmt.Errorf("%d navigation entr(y/ies) point at pages "+
		"that are not published", len(broken))}
}
