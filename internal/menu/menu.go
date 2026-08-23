// Package menu is navigation that cannot point at nothing.
//
// # The bug this is built to make impossible
//
// Every CMS lets you build a menu, and every CMS lets that menu outlive what it
// points at. Drupal's own issue queue carries this: menu links keep the
// reference to a deleted target, deleting one through the interface has crashed
// sites, and there is a documented fatal error for a menu link whose entity is
// gone. WordPress is quieter about it and no better — delete a page and the
// menu item stays, silently linking to a 404.
//
// The reason it happens everywhere is that a menu is stored as a list of
// targets and the targets are stored somewhere else, so nothing owns the
// question "is this still true". It is checked, if at all, by a cron job or a
// contributed module or a person clicking every link before a launch.
//
// # So it is checked where it cannot be skipped
//
// Three points, and the third is the one that matters:
//
//	When a menu is edited, an internal target that does not exist is refused.
//
//	When a menu is read, every item carries whether its target resolves, so
//	the interface can show a broken one rather than render it.
//
//	When a site is published, a menu pointing at a page that is not being
//	published refuses the publication. Not a warning — the same gate that
//	stops an inaccessible page going out.
//
// That last one also catches the subtler version nobody checks for: a menu
// entry pointing at a page that exists in the draft and is not live yet. The
// link is not broken in the editor and is broken for every reader, which is the
// worst place to find out.
//
// # External links are a different kind of thing
//
// An external URL cannot be checked without making a request, and making
// requests from a publish gate is how a CMS becomes a scanner of somebody
// else's infrastructure. So external targets are stored, marked as external,
// scheme-restricted to http and https, and never fetched. The honest position
// is that we verify what we can see and say so about the rest.
package menu

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Limits. A navigation menu past these is not navigation.
const (
	MaxItems = 200
	MaxDepth = 4
	MaxLabel = 80
)

var reName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)

// Kind is what an item points at.
type Kind string

const (
	// Page is an internal page name, checked against the content.
	Page Kind = "page"
	// External is a URL somewhere else, stored and never fetched.
	External Kind = "external"
	// Heading is a label with no target: a group title in a nested menu.
	Heading Kind = "heading"
)

// Item is one entry.
type Item struct {
	// ID is stable across relabelling, so a saved arrangement survives an edit.
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  Kind   `json:"kind"`
	// Target is the page name, or the URL, or empty for a heading.
	Target string `json:"target,omitempty"`
	// Parent nests this under another item. Empty is top level.
	Parent string `json:"parent,omitempty"`
	// Order places it among its siblings. Lower first; ties break by label,
	// so two items with the same order still render in a stable sequence
	// rather than in whatever order the file happened to hold them.
	Order int `json:"order"`
	// Note is why this entry exists, for whoever finds it in two years.
	Note string `json:"note,omitempty"`
}

// Menu is one named navigation structure.
type Menu struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	Items []Item `json:"items"`
}

// Set is every menu a site has.
type Set struct {
	Menus []Menu `json:"menus"`
}

// ValidName reports whether a menu may be called this.
func ValidName(s string) error {
	if !reName.MatchString(s) {
		return fmt.Errorf(
			"%q is not a usable menu name: lowercase letters, digits, "+
				"hyphens and underscores, starting with a letter", s)
	}
	return nil
}

// Get finds a menu.
func (s *Set) Get(name string) (*Menu, bool) {
	for i := range s.Menus {
		if s.Menus[i].Name == name {
			return &s.Menus[i], true
		}
	}
	return nil, false
}

// Names lists the menus.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.Menus))
	for _, m := range s.Menus {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

// Add declares a menu.
func (s *Set) Add(m Menu) error {
	if err := ValidName(m.Name); err != nil {
		return err
	}
	if _, exists := s.Get(m.Name); exists {
		return fmt.Errorf("there is already a menu called %q", m.Name)
	}
	s.Menus = append(s.Menus, m)
	return nil
}

// Remove deletes a menu.
func (s *Set) Remove(name string) error {
	kept := s.Menus[:0]
	found := false
	for _, m := range s.Menus {
		if m.Name == name {
			found = true
			continue
		}
		kept = append(kept, m)
	}
	if !found {
		return fmt.Errorf("there is no menu %q", name)
	}
	s.Menus = kept
	return nil
}

// ValidateItem checks one entry, against the pages that exist.
//
// pages may be nil, which means "do not check internal targets" — used when
// validating a menu's shape without a content set to hand. That is a weaker
// check and the caller has to want it: everywhere a menu is actually saved, the
// pages are passed.
func ValidateItem(it Item, pages map[string]any) error {
	if strings.TrimSpace(it.Label) == "" {
		return fmt.Errorf("a menu entry needs a label")
	}
	if len(it.Label) > MaxLabel {
		return fmt.Errorf("that label is %d characters; the limit is %d",
			len(it.Label), MaxLabel)
	}

	switch it.Kind {
	case Heading:
		if it.Target != "" {
			return fmt.Errorf(
				"%q is a heading and has a target; a heading is a label for "+
					"the entries under it", it.Label)
		}
	case Page:
		if it.Target == "" {
			return fmt.Errorf("%q points at no page", it.Label)
		}
		if pages != nil {
			if _, exists := pages[it.Target]; !exists {
				return fmt.Errorf(
					"%q points at the page %q, which does not exist. A menu "+
						"entry pointing at nothing is a 404 every reader finds "+
						"before anybody here does", it.Label, it.Target)
			}
		}
	case External:
		u, err := url.Parse(it.Target)
		if err != nil {
			return fmt.Errorf("%q: %q is not a URL", it.Label, it.Target)
		}
		// http and https only. A menu is rendered into pages readers click, so
		// javascript: and data: targets are script execution with a friendly
		// label on it — which is the exact thing this product exists to not have.
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf(
				"%q uses the %q scheme. A menu entry becomes a link in a page "+
					"somebody clicks, so only http and https are accepted — "+
					"javascript: and data: targets are script execution with a "+
					"label on them", it.Label, u.Scheme)
		}
		if u.Host == "" {
			return fmt.Errorf("%q has no host", it.Label)
		}
	default:
		return fmt.Errorf(
			"%q has kind %q; a menu entry is a page, an external link or a "+
				"heading", it.Label, it.Kind)
	}
	return nil
}

// Validate checks a whole menu.
func (m *Menu) Validate(pages map[string]any) error {
	if err := ValidName(m.Name); err != nil {
		return err
	}
	if len(m.Items) > MaxItems {
		return fmt.Errorf(
			"%d entries in %q, and the limit is %d. A navigation menu that "+
				"long is not navigation", len(m.Items), m.Name, MaxItems)
	}

	seen := map[string]bool{}
	for _, it := range m.Items {
		if it.ID == "" {
			return fmt.Errorf("a menu entry has no identifier")
		}
		if seen[it.ID] {
			return fmt.Errorf("%q appears twice in %q", it.ID, m.Name)
		}
		seen[it.ID] = true
		if err := ValidateItem(it, pages); err != nil {
			return fmt.Errorf("in %q: %w", m.Name, err)
		}
	}
	for _, it := range m.Items {
		if it.Parent == "" {
			continue
		}
		if !seen[it.Parent] {
			return fmt.Errorf("%q sits under %q, which is not in this menu",
				it.Label, it.Parent)
		}
		if d, err := m.depth(it.ID, map[string]bool{}); err != nil {
			return err
		} else if d > MaxDepth {
			return fmt.Errorf(
				"%q nests %d deep in %q, and the limit is %d",
				it.Label, d, m.Name, MaxDepth)
		}
	}
	return nil
}

func (m *Menu) depth(id string, seen map[string]bool) (int, error) {
	if seen[id] {
		return 0, fmt.Errorf(
			"%q is its own ancestor in %q; rendering the menu would not "+
				"terminate", id, m.Name)
	}
	seen[id] = true
	it, ok := m.Item(id)
	if !ok || it.Parent == "" {
		return 1, nil
	}
	up, err := m.depth(it.Parent, seen)
	return up + 1, err
}

// Item finds one.
func (m *Menu) Item(id string) (Item, bool) {
	for _, it := range m.Items {
		if it.ID == id {
			return it, true
		}
	}
	return Item{}, false
}

// Rendered is one entry as a template or a screen sees it.
type Rendered struct {
	Item
	Depth int
	// Resolves is whether an internal target exists in the content this was
	// rendered against. Carried rather than filtered, so a screen can show a
	// broken entry and a template can skip it — the two want different things
	// and hiding it here would decide for both.
	Resolves bool
	// Live is whether the target is in the published set. An entry can resolve
	// against the draft and still be broken for every reader, which is the
	// version of this bug nobody checks for.
	Live bool
}

// Render arranges a menu as a depth-first list, checked against content.
//
// draft is what exists at all; live is what readers can see. Passing the same
// map for both is correct when only one of those questions applies.
func (m *Menu) Render(draft, live map[string]any) []Rendered {
	byParent := map[string][]Item{}
	for _, it := range m.Items {
		byParent[it.Parent] = append(byParent[it.Parent], it)
	}
	for k := range byParent {
		items := byParent[k]
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Order != items[j].Order {
				return items[i].Order < items[j].Order
			}
			return items[i].Label < items[j].Label
		})
	}

	var out []Rendered
	var walk func(parent string, depth int)
	walk = func(parent string, depth int) {
		if depth > MaxDepth {
			return
		}
		for _, it := range byParent[parent] {
			r := Rendered{Item: it, Depth: depth, Resolves: true, Live: true}
			if it.Kind == Page {
				if draft != nil {
					_, r.Resolves = draft[it.Target]
				}
				if live != nil {
					_, r.Live = live[it.Target]
				}
			}
			out = append(out, r)
			walk(it.ID, depth+1)
		}
	}
	walk("", 0)
	return out
}

// Broken is every entry in every menu that points at something absent.
//
// The publish gate calls this with the page set about to go live. An entry
// pointing at a page that exists in the draft and is not being published is
// reported here, because the link works for the person who made it and is a
// 404 for everybody else.
//
// # Why nil means nothing rather than everything
//
// Render treats a nil map as "do not check this side", which is what the admin
// wants when it is only interested in the other one. Here nil means the live
// side could not be read — nothing published yet, or a rollback that took the
// site back past its first publish — and the honest reading of that is that no
// page resolves. It used to inherit Render's answer, so `quilzo menu check` on
// a site with nothing published printed "every navigation entry resolves for a
// reader": a green light in a pipeline for a navigation where every link 404s,
// and the one situation where the check was certain to be needed.
func (s *Set) Broken(live map[string]any) []Problem {
	if live == nil {
		live = map[string]any{}
	}
	var out []Problem
	for _, m := range s.Menus {
		for _, r := range m.Render(nil, live) {
			if r.Kind != Page || r.Live {
				continue
			}
			out = append(out, Problem{
				Menu: m.Name, Item: r.Label, Target: r.Target,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Menu != out[j].Menu {
			return out[i].Menu < out[j].Menu
		}
		return out[i].Item < out[j].Item
	})
	return out
}

// Problem is one entry that will not resolve for a reader.
type Problem struct {
	Menu, Item, Target string
}

func (p Problem) String() string {
	return fmt.Sprintf("%s: %q points at %q, which is not published",
		p.Menu, p.Item, p.Target)
}

// Retarget rewrites every entry pointing at one page to point at another.
//
// What a rename needs. Without it, renaming a page means finding every menu
// that mentioned it by hand — which is the manual step that does not happen,
// and is how the dangling entry gets there in the first place.
func (s *Set) Retarget(from, to string) int {
	n := 0
	for i := range s.Menus {
		for j := range s.Menus[i].Items {
			it := &s.Menus[i].Items[j]
			if it.Kind == Page && it.Target == from {
				it.Target = to
				n++
			}
		}
	}
	return n
}

// Mentioning lists the menus and entries pointing at a page.
//
// Called before a page is deleted, so the refusal can name what would break
// rather than saying that something would.
func (s *Set) Mentioning(page string) []Problem {
	var out []Problem
	for _, m := range s.Menus {
		for _, it := range m.Items {
			if it.Kind == Page && it.Target == page {
				out = append(out, Problem{Menu: m.Name, Item: it.Label,
					Target: page})
			}
		}
	}
	return out
}
