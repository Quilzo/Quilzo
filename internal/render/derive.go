package render

import (
	"sort"
	"strings"
)

// The derived companions a template gets for free, and why they exist.
//
// # The problem
//
// The template language has no else. That is a deliberate property — an if with
// no else has one exit, so a template's structure can be read off its source —
// and it collides with the single most common shape in any real template:
//
//	a heading that is a link when there is somewhere to go, and text when there
//	is not.
//
// Written in the language directly, that needs the content to carry the
// negation: an author has to write "plain": true beside every item that has no
// href, and forget it once to get an empty heading. An empty <a> is also a
// blocking accessibility failure, so forgetting it fails the publish — the gate
// works, and the author is being asked to hand-maintain a boolean that is a
// function of the data next to it.
//
// # The answer this project already uses
//
// Compute it in Go. The demo does exactly this for prices: the language has no
// arithmetic, so price_display is written into the record before rendering. The
// same argument applies to negation, and to anything else a layout needs that
// is a pure function of the content.
//
// So a page body is decorated on its way into the render context, in one place,
// and every derived name is documented below. Because it happens inside
// Sources.For, the public server, the detail route, the accessibility gate, the
// preview and the static export all see identical data — which is the property
// this package exists to hold.
//
// # The names
//
// For every object anywhere in a page body:
//
//	unlinked   true when the object has no usable href
//	no_image   true when it has no image
//	no_slug    true when it has no slug
//	no_src     true when it has no media source
//
// For the hero, additionally:
//
//	title      the page's own title, when the hero did not set one
//
// For each item of a list, additionally:
//
//	first, last  position, so a template can treat the ends differently
//	n            one-based position, for "step 3 of 5" without arithmetic
//
// Nothing is overwritten. A page that already carries "unlinked" keeps its own
// value, because content an author wrote wins over content this inferred.

// maxDeriveDepth bounds the walk. Content is nested by authors and by importers,
// and a decorator that recursed without a limit would be a way to spend the
// server's stack on a page somebody wrote.
const maxDeriveDepth = 10

// decorate returns a copy of a page body carrying its derived companions.
//
// A copy, never a mutation. The body comes out of the decoded content tree,
// which is shared between every request that renders the same page; writing
// into it would leak one page's derived fields into another's and, worse, do it
// only after the first request — the class of bug that cannot be reproduced on
// a fresh process.
func decorate(v any, depth int) any {
	if depth > maxDeriveDepth {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t)+3)
		for k, vv := range t {
			out[k] = decorate(vv, depth+1)
		}
		derive(out)
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = decorate(item, depth+1)
		}
		// Position is a property of the list, so it is written after the items
		// are copied rather than inside each one's own walk.
		for i, item := range out {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			setIfAbsent(m, "first", i == 0)
			setIfAbsent(m, "last", i == len(out)-1)
			setIfAbsent(m, "n", float64(i+1))
		}
		return out
	default:
		return v
	}
}

// derive writes the negations onto one object.
func derive(m map[string]any) {
	setIfAbsent(m, "unlinked", !hasText(m, "href"))
	setIfAbsent(m, "no_image", !hasText(m, "image"))
	setIfAbsent(m, "no_slug", !hasText(m, "slug"))
	setIfAbsent(m, "no_src", !hasText(m, "src"))
}

func setIfAbsent(m map[string]any, key string, value any) {
	if _, exists := m[key]; exists {
		return
	}
	m[key] = value
}

func hasText(m map[string]any, key string) bool {
	s, ok := m[key].(string)
	return ok && strings.TrimSpace(s) != ""
}

// decoratePage decorates a page body and fills in the hero's inherited title.
//
// The hero inherits the page title because writing the same string twice is how
// the two drift apart: somebody renames the page, the hero still says the old
// name, and nothing catches it because both fields are populated.
func decoratePage(body any) any {
	out := decorate(body, 0)
	m, ok := out.(map[string]any)
	if !ok {
		return out
	}
	title, _ := m["title"].(string)
	if hero, isMap := m["hero"].(map[string]any); isMap && title != "" {
		setIfAbsent(hero, "title", title)
	}
	return out
}

// feeds arranges a page's listings as an ordered list.
//
// # Why this exists beside listings
//
// A template reads one listing as listings.recent.rows, which needs the name
// "recent" written into the template. That is exactly right for a layout built
// for one site and exactly wrong for a layout meant to be reusable: a shared
// template cannot know what anybody called their listings, and the language has
// no dynamic key lookup — deliberately, because a path that could be computed
// is a path an attacker could aim.
//
// So the same data is offered a second way, as a list. A generic layout walks
// feeds and renders whatever the page embedded, under whatever it was called:
//
//	{% for feed in feeds %}{% for row in feed.rows %}…{% end %}{% end %}
//
// Both views are the same rows. Neither is a copy of the other's data — they
// are two arrangements of one resolved result, so they cannot disagree.
//
// # Row links
//
// A row's href is the other thing a reusable layout cannot work out. A record's
// page exists only if some page declared itself the detail route for that
// listing, and which page that is lives in the content, not the template. It is
// resolved here, once, from the same page set the navigation is checked against
// — so a feed links to a record page when there is one and renders plain text
// when there is not, instead of linking every row at a URL that 404s.
func (s Sources) feeds(data map[string]any) []any {
	if len(data) == 0 {
		return nil
	}
	names := make([]string, 0, len(data))
	for name := range data {
		names = append(names, name)
	}
	sort.Strings(names)

	detailFor := s.detailRoutes()

	out := make([]any, 0, len(names))
	for _, name := range names {
		resolved, ok := data[name].(map[string]any)
		if !ok {
			continue
		}
		rows, _ := resolved["rows"].([]any)
		base, key := "", ""
		if route, found := detailFor[name]; found {
			base, key = route.base, route.key
		}
		decorated := make([]any, 0, len(rows))
		for _, row := range rows {
			m, isMap := row.(map[string]any)
			if !isMap {
				decorated = append(decorated, row)
				continue
			}
			copied := make(map[string]any, len(m)+4)
			for k, v := range m {
				copied[k] = v
			}
			if base != "" && key != "" {
				if slug, isText := copied[key].(string); isText && slug != "" {
					setIfAbsent(copied, "href", base+slug)
				}
			}
			derive(copied)
			decorated = append(decorated, copied)
		}
		for i, item := range decorated {
			if m, isMap := item.(map[string]any); isMap {
				setIfAbsent(m, "first", i == 0)
				setIfAbsent(m, "last", i == len(decorated)-1)
				setIfAbsent(m, "n", float64(i+1))
			}
		}
		feed := map[string]any{
			"name":  name,
			"title": title(resolved, name),
			"rows":  decorated,
			"count": float64(len(decorated)),
			"empty": len(decorated) == 0,
		}
		out = append(out, feed)
	}
	return out
}

// title is the heading a feed renders under.
//
// A listing's human name is its label — that is the field the declaration has
// and the field the resolver puts in the map. This looked for "title", found
// nothing, and fell back to the listing's machine name, so a generic layout
// printed "new_in" as a heading on a published page. Found by reading one.
//
// "title" is still accepted, because a page may set one on the resolved data
// and the more specific answer should win. When there is neither, the answer is
// empty rather than the machine name: every layout guards with
// {% if feed.title %}, so no heading is the better failure than a heading that
// reads like a variable.
func title(resolved map[string]any, name string) string {
	for _, key := range []string{"title", "label"} {
		if t, ok := resolved[key].(string); ok && strings.TrimSpace(t) != "" {
			return t
		}
	}
	return ""
}

type detailRoute struct {
	base string
	key  string
}

// detailRoutes maps a listing name to the page that serves its records.
//
// Built from the same Pages the navigation is filtered against, so a feed links
// to a detail page exactly when a reader could reach it. Two pages claiming the
// same listing is not an error here: the first by name wins, deterministically,
// rather than whichever the map iterated to first.
func (s Sources) detailRoutes() map[string]detailRoute {
	if len(s.Pages) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.Pages))
	for name := range s.Pages {
		names = append(names, name)
	}
	sort.Strings(names)

	out := map[string]detailRoute{}
	for _, name := range names {
		d, declared := DetailOf(s.Pages[name])
		if !declared || !d.Declared() {
			continue
		}
		if _, taken := out[d.Listing]; taken {
			continue
		}
		base := "/" + name + "/"
		if name == "index" {
			base = "/"
		}
		out[d.Listing] = detailRoute{base: base, key: d.Key}
	}
	return out
}

// Feeds is the context key the ordered arrangement lands under.
const Feeds = "feeds"
