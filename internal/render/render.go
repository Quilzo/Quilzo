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
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/menu"
	"strconv"
	"time"
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
	// Now is the clock the stamp comes from. Nil means time.Now.
	Now func() time.Time
	// Form resolves a declared form into what a template renders. Nil means a
	// page naming one gets no form data and its layout renders nothing, which
	// is what every deployment did before the declaration was the only list.
	Form func(name string) map[string]any
	// SrcSet answers what narrower copies an asset has, as a srcset value, or
	// "" when it has none.
	//
	// A function rather than the library itself, because this package must not
	// know what a media library is: it is handed the one question a layout
	// needs answered. Nil means no srcset companions, which is what every
	// deployment had before renditions existed and is still correct for a site
	// whose pictures are all small.
	SrcSet func(id string) string
}

// For builds the context for one page.
//
// name is the page being rendered, used to mark the current entry in the
// navigation. args are the request's parameters, which listings declare and
// nothing else can read.
func (s Sources) For(name string, body any, args map[string]string) (map[string]any, error) {
	ctx := map[string]any{
		// Decorated, not raw. The derived companions — the negations a language
		// with no else cannot express — are added here so that every renderer
		// sees the same page. See derive.go for what they are and why.
		"page":  decoratePage(body, s.SrcSet),
		"site":  map[string]any{"name": s.Name, "page": name},
		"menus": s.menus(name),
		// When this page was rendered, for a form's timing check.
		//
		// internal/form refuses a submission with no timestamp and one older
		// than a day, both deliberately. The shipped layouts took the value
		// from the page — from content, published once — so a form either
		// carried no stamp and refused everything, or carried one that expired
		// twenty-four hours later and refused everything after that. The whole
		// forms feature was unusable from a published page in both directions.
		//
		// It belongs here because it is a fact about this render, not about the
		// content. Pages are rendered per request, so it is fresh every time.
		//
		// A string, because the template language renders what decoded JSON
		// holds — text, numbers as float64, booleans — and an int64 came out
		// as nothing at all: value="" in the markup and every submission
		// refused, which is the same failure by a different route. The form
		// parses this field as text anyway.
		"stamp": strconv.FormatInt(s.now().Unix(), 10),
	}
	// The form this page carries, from the declaration rather than from a copy
	// of the questions in the page. See formdata.go.
	if f := s.form(body); f != nil {
		ctx["form"] = f
	}
	if s.Listings != nil {
		data, err := s.Listings.For(body, args)
		if err != nil {
			return nil, err
		}
		if data != nil {
			ctx[listing.Data] = data
			// The same rows, arranged as a list, so a layout that does not know
			// what this site called its listings can still render them.
			if arranged := s.feeds(data); len(arranged) > 0 {
				ctx[Feeds] = arranged
			}
		}
	}
	return ctx, nil
}

func (s Sources) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
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
			href := Href(r)
			items = append(items, menuItem{
				"label":   r.Label,
				"href":    href,
				"depth":   r.Depth,
				"current": r.Kind == menu.Page && r.Target == current,
				// A heading is a label for the entries under it, so it has
				// nothing to point at. The companion is here because the
				// template language has no else and every layout has to
				// choose between an anchor and plain text — the same reason
				// gallery items and breadcrumbs carry one.
				"heading":  r.Kind == menu.Heading,
				"unlinked": href == "",
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
	if r.Kind == menu.Heading {
		// Nothing. A heading has no target, and this used to fall through to
		// "/" + "" — so every group title in a nested menu rendered as a link
		// to the home page. Seen in a footer where "By dyestuff" and "Reading"
		// were both underlined and both went home.
		return ""
	}
	if r.Kind == menu.External {
		return r.Target
	}
	if r.Target == "index" {
		return "/"
	}
	return "/" + r.Target
}
