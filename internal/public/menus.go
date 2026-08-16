package public

import (
	"github.com/rsh1k/scrivet/internal/menu"
)

// Navigation, as a template sees it.
//
// The menu system was built, validated and gated and then went nowhere: a
// dangling entry blocked a publish, depth was bounded, targets were checked
// against the published set — and the render context held only the page, the
// site name and the listings, so no reader ever saw a menu. menu.Render existed
// with no caller outside its own package.
//
// # What a template gets
//
// A map keyed by menu name, each holding a flat list of entries:
//
//	{% for item in menus.main %}
//	  <a href="{{ item.href }}"{% if item.current %} aria-current="page"{% end %}>
//	    {{ item.label }}</a>
//	{% end %}
//
// Flat rather than nested, because the template language has no recursion —
// that is deliberate and is what makes rendering terminate. Depth is carried on
// each entry so a template can indent, and the renderer already caps it.
//
// # Why broken entries are dropped here
//
// A menu entry pointing at a page that is not published is a link that 404s.
// The publish gate refuses that, so it should not arise — but a page can also
// be pulled out of the live set by its own expiry date, which happens on a
// schedule nobody triggers and after the gate has run. At that moment the menu
// still names it.
//
// The screens keep broken entries and show them, because somebody has to fix
// them. The public site drops them, because a reader cannot. Same data, two
// audiences, and menu.Rendered carries the flag rather than deciding.

// menuItem is one entry, in the shape the template language can walk: plain
// values only, no Go types, no methods.
type menuItem = map[string]any

// menus builds the navigation for one request.
//
// pages is the published set the entries are checked against, which is the set
// already filtered by expiry — so an entry naming a page whose window has
// closed disappears from the navigation at the same moment the page itself
// stops being served, rather than at the next publish.
func (st *Site) menus(pages map[string]any, current string) map[string]any {
	out := map[string]any{}
	if st.Menus == nil {
		return out
	}
	set, err := st.Menus()
	if err != nil || set == nil {
		// A navigation that cannot be read is a site with no navigation, not a
		// page that fails to render. The alternative is one unreadable file
		// taking the whole site down, and the page itself is fine.
		return out
	}
	for _, name := range set.Names() {
		m, ok := set.Get(name)
		if !ok {
			continue
		}
		items := make([]any, 0, len(m.Items))
		for _, r := range m.Render(pages, pages) {
			if !r.Live {
				continue
			}
			items = append(items, menuItem{
				"label":    r.Label,
				"href":     href(r),
				"depth":    r.Depth,
				"current":  r.Kind == menu.Page && r.Target == current,
				"external": r.Kind == menu.External,
			})
		}
		out[name] = items
	}
	return out
}

// href is where an entry points, as a URL.
//
// An external target is used as written — it was already restricted to http and
// https when it was saved, which is the check that matters and is not repeated
// here on the theory that two copies of a rule drift apart.
func href(r menu.Rendered) string {
	if r.Kind == menu.External {
		return r.Target
	}
	if r.Target == "index" {
		return "/"
	}
	return "/" + r.Target
}
