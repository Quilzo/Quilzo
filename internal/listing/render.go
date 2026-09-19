// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package listing

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/store"
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
	// Tree is the content the listings read, as a fixed snapshot. The draft
	// when previewing, one commit's tree when exporting — a preview that
	// showed live data would be a preview of a different page.
	Tree string
	// Live resolves the tree per call, for a server whose content changes
	// under it. When set it wins over Tree.
	//
	// # Why both
	//
	// Because the two callers want opposite things and one field could only
	// serve one of them. A preview and a static export are asking about one
	// version and must not move; a running site is asking about now.
	//
	// The site had the snapshot. cmd/quilzo/sitebuild.go read the live
	// commit's tree once, at start-up, and nothing ever refreshed it — so
	// every listing-backed route served whatever the records were when the
	// server booted, while the pages around them updated on every publish.
	// A record added and published was in the page and not in the catalogue,
	// the feeds, the detail routes or any listing section, until somebody
	// restarted the process.
	Live func() string
	Set  *Set
}

// At is the tree to read, now.
//
// Live wins when it is set, because a caller that supplied it is saying the
// content moves. Nil on the receiver answers empty rather than panicking:
// every caller here already treats an absent resolver as "no listings", and a
// nil check at four call sites is four places to forget it.
func (r *Resolver) At() string {
	if r == nil {
		return ""
	}
	if r.Live != nil {
		return r.Live()
	}
	return r.Tree
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
		idx, err := r.Index.For(r.Store, r.At(), l.Collection)
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
		entry := map[string]any{
			"rows": rows, "total": res.Total, "shown": len(rows),
			"truncated": res.Truncated, "label": l.Label,
		}
		// Under its own key rather than spread alongside rows and total, so a
		// listing may name an aggregate "rows" or "total" without either one
		// quietly replacing the other.
		if len(res.Agg) > 0 {
			entry["agg"] = res.Agg
		}
		out[name] = entry
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
