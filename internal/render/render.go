// Package render builds the one context a template is rendered with.
//
// # Why this exists
//
// There were seven places in this program that called tmpl.Render, and they
// built six different contexts. The public server passed the page, the site
// name, the menus and the listings. The accessibility gate — the thing that
// refuses a publish — passed the page and nothing else. So did the preview, the
// IPFS export and the decentralised bundle.
//
// Each of those is a document nobody serves, and the consequences run in both
// directions. A site whose navigation is perfectly accessible failed the gate,
// because in the gate's version of the page the navigation was not there: a
// link wrapping the site name became an empty link, thirteen times over, and
// the only way to publish was to override the gate. The reverse is worse and
// quieter — a genuine failure inside a menu or a listing is invisible to a
// check that renders neither.
//
// The export paths had a plainer version of the same bug: a static bundle
// pinned to IPFS, or handed to somebody as the durable copy of their site, came
// out with no navigation on any page.
//
// So there is one builder, and everything that renders a page uses it. It is
// the same argument as the single pages() accessor in internal/public: two
// callers that must agree cannot be trusted to agree unless they are one
// caller.
package render

import (
	"github.com/lithoform/lithoform/internal/listing"
	"github.com/lithoform/lithoform/internal/menu"
)

// Sources is everything a template can be shown.
//
// Every field is optional, and a zero Sources produces the context the callers
// used to build by hand — so a caller that genuinely has nothing to add is not
// forced to invent it.
type Sources struct {
	// Name is the site's name.
	Name string
	// Menus is the navigation. Nil means the template sees an empty map rather
	// than a missing key, so {% for item in menus.main %} renders nothing
	// instead of failing.
	Menus *menu.Set
	// Pages is the set menu targets are checked against: what a reader can
	// actually reach. Entries pointing outside it are dropped, because a
	// reader cannot fix a broken link.
	//
	// For the public site this is the published set already filtered by
	// expiry, so navigation loses an entry at the same moment the page behind
	// it stops being served. For a preview it is the draft, because a preview
	// that hid unpublished pages would not be a preview.
	Pages map[string]any
	// Listings resolves the queries a page embeds. Nil means a page naming one
	// gets an error rather than a silent gap.
	Listings *listing.Resolver
}

// For builds the context for one page.
//
// name is the page being rendered, used to mark the current entry in the
// navigation. args are the request's parameters, which listings declare and
// nothing else can read.
func (s Sources) For(name string, body any, args map[string]string) (map[string]any, error) {
	ctx := map[string]any{
		"page":  body,
		"site":  map[string]any{"name": s.Name},
		"menus": s.menus(name),
	}
	if s.Listings != nil {
		data, err := s.Listings.For(body, args)
		if err != nil {
			return nil, err
		}
		if data != nil {
			ctx[listing.Data] = data
		}
	}
	return ctx, nil
}

// menuItem is one navigation entry, in the shape the template language walks:
// plain values, no Go types, no methods.
type menuItem = map[string]any

// menus arranges every menu as a flat list.
//
// Flat because the template language has no recursion, which is what makes
// rendering terminate for every input. Depth is carried so a template can
// indent, and the renderer caps it.
func (s Sources) menus(current string) map[string]any {
	out := map[string]any{}
	if s.Menus == nil {
		return out
	}
	for _, name := range s.Menus.Names() {
		m, ok := s.Menus.Get(name)
		if !ok {
			continue
		}
		items := make([]any, 0, len(m.Items))
		for _, r := range m.Render(s.Pages, s.Pages) {
			// A broken entry is kept on the screens, where somebody can fix
			// it, and dropped here, where nobody can. menu.Rendered carries
			// the flag rather than deciding for both audiences.
			if s.Pages != nil && !r.Live {
				continue
			}
			items = append(items, menuItem{
				"label":    r.Label,
				"href":     Href(r),
				"depth":    r.Depth,
				"current":  r.Kind == menu.Page && r.Target == current,
				"external": r.Kind == menu.External,
			})
		}
		out[name] = items
	}
	return out
}

// Href is where a navigation entry points.
//
// An external target is used as written: it was restricted to http and https
// when it was saved, and repeating the rule here would give it two copies to
// drift apart.
func Href(r menu.Rendered) string {
	if r.Kind == menu.External {
		return r.Target
	}
	if r.Target == "index" {
		return "/"
	}
	return "/" + r.Target
}
