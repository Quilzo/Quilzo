package listing

import (
	"fmt"

	"github.com/lithoform/lithoform/internal/collection"
	"github.com/lithoform/lithoform/internal/store"
)

// Resolving a page's listings before it renders.
//
// Before, not during. The template language has no calls in it — that is the
// property the whole product rests on — so a listing cannot be a function a
// template invokes. It is data, computed first and handed in, which also means
// the cost of a page is known before a byte of it is written.

// Data is what a page's listings add to its render context.
//
// Keyed by listing name under one key, so a template reads
// {% for row in listings.recent.rows %} and the shape is the same for every
// listing. A flat namespace would let a listing called "page" shadow the page.
const Data = "listings"

// Resolver turns a page into the listing data it asked for.
type Resolver struct {
	Store *store.Store
	Index *collection.Cache
	// Tree is the content the listings read. The published tree when rendering
	// the public site, the draft when previewing — a preview that showed live
	// data would be a preview of a different page.
	Tree string
	Set  *Set
}

// For resolves every listing one page embeds.
//
// args carry the request's parameters. The same page rendered with different
// arguments is a different page, which is what makes a contextual filter work
// and is also why a static export has to pick one set and say so.
func (r *Resolver) For(body any, args map[string]string) (map[string]any, error) {
	names := On(body)
	if len(names) == 0 {
		return nil, nil
	}
	if r == nil || r.Set == nil {
		return nil, fmt.Errorf(
			"this page embeds %d listing(s) and this build has no listings "+
				"configured", len(names))
	}

	// Budget first. An expensive page fails to build rather than building
	// slowly, because a page that works in a test with three records and takes
	// a second in production is the failure this feature invites.
	if _, err := Check(names, r.Set); err != nil {
		return nil, err
	}

	out := map[string]any{}
	for _, name := range names {
		l, ok := r.Set.Get(name)
		if !ok {
			return nil, fmt.Errorf("%q is not a listing", name)
		}
		idx, err := r.Index.For(r.Store, r.Tree, l.Collection)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		res, err := Resolve(l, idx, args)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		// Plain maps and slices, because that is all the template language
		// understands: lookup, truthiness and iteration over decoded JSON.
		// Handing it a Go struct would require field access, which is the
		// capability this language deliberately does not have.
		rows := make([]any, 0, len(res.Rows))
		for _, row := range res.Rows {
			rows = append(rows, map[string]any(row))
		}
		out[name] = map[string]any{
			"rows": rows, "total": res.Total, "shown": len(rows),
			"truncated": res.Truncated, "label": l.Label,
		}
	}
	return out, nil
}

// Context builds the full render context for a page.
//
// One place, so the public site, the preview and the static export cannot
// disagree about what a page can see — which is the same reason the type gate
// is one function.
func (r *Resolver) Context(body any, args map[string]string) (map[string]any, error) {
	ctx := map[string]any{"page": body}
	data, err := r.For(body, args)
	if err != nil {
		return nil, err
	}
	if data != nil {
		ctx[Data] = data
	}
	return ctx, nil
}
