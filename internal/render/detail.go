package render

import (
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/listing"
)

// A page that stands for many records.
//
// # Why this lives here rather than beside the route that serves it
//
// Two things need to know which records have pages, and they are in different
// packages: the public server, which answers /product/brass-pen, and the
// exporter, which has to write one file per product into a bundle somebody
// pins or hands over.
//
// They got different answers. The server expanded the page and the exporter did
// not, so an exported site linked to a product page for every product and
// contained exactly one — an index with no record in it. Every one of those
// links was a 404 on a site whose whole promise is that the address cannot lie.
//
// So the declaration is read in one place. render is where both already meet,
// because both build their context from Sources.
type Detail struct {
	// Listing is the declared listing the record is read through. The field
	// allow-list on that listing is what decides what of a record is public,
	// and reading through it is what stops the export and the server
	// disagreeing about that too.
	Listing string
	// Key is which field of the record appears in the URL.
	Key string
}

// Declared reports whether both halves are present.
//
// A page naming a listing and no key cannot answer for any record. Reported as
// undeclared here and refused with an explanation at the point of use, rather
// than 404ing quietly — a misconfigured detail route that silently does nothing
// looks exactly like a record that is not there.
func (d Detail) Declared() bool { return d.Listing != "" && d.Key != "" }

// DetailOf reads the declaration off a page body.
//
// The second return says whether the page claims to be a detail route at all,
// which is different from whether the claim is complete.
func DetailOf(body any) (Detail, bool) {
	m, ok := body.(map[string]any)
	if !ok {
		return Detail{}, false
	}
	name, _ := m["detail"].(string)
	key, _ := m["detail_key"].(string)
	d := Detail{
		Listing: strings.TrimSpace(name),
		Key:     strings.TrimSpace(key),
	}
	if d.Listing == "" && d.Key == "" {
		return Detail{}, false
	}
	return d, true
}

// Bundle renders a whole published site to files.
//
// # Why this is here and not written twice
//
// It was written twice: once in the admin screen that computes an IPFS
// identifier, once in `quilzo ipfs write`. Both walked the page set and emitted
// one file per page, and when detail pages arrived only one of them was taught
// about them — so which of your product pages existed depended on which
// interface you exported from.
//
// That is the failure this project has a test suite for, arriving in the one
// place the suite does not look: not a capability missing from a surface, but
// the same capability implemented twice and diverging. So there is one
// function, and the two callers pass their layouts in.
//
// # Paths
//
// index becomes index.html at the root; everything else becomes a directory
// with an index.html in it, so a gateway serves clean paths without rewrite
// rules. A page standing for records becomes one directory per record, under
// the key the page declared.
func Bundle(src Sources, layouts Layouts, pages map[string]any,
	render func(string, map[string]any) (string, error)) (
	map[string][]byte, error) {

	out := map[string][]byte{}
	for name, body := range pages {
		if d, declared := DetailOf(body); declared {
			if !d.Declared() {
				return nil, fmt.Errorf(
					"%s declares a detail route with half of it missing, so "+
						"no record can be written for it", name)
			}
			files, err := detailFiles(src, layouts, name, body, d, render)
			if err != nil {
				return nil, err
			}
			for path, html := range files {
				out[path] = html
			}
			continue
		}
		ctx, err := src.For(name, body, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		// The same layout the server would pick. An export that rendered every
		// page through the default would be a bundle that does not look like
		// the site it is a copy of.
		_, src2, lerr := layouts.For(body)
		if lerr != nil {
			return nil, fmt.Errorf("%s: %w", name, lerr)
		}
		html, err := render(src2, ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		path := name + "/index.html"
		if name == "index" {
			path = "index.html"
		}
		out[path] = []byte(html)
	}
	return out, nil
}

// detailFiles renders one file per record a detail page stands for.
//
// Read through the listing the page names, so what lands in a bundle is what
// the server would have served. The allow-list on that listing is the one
// decision about which fields of a record are public, and a second path around
// it would be a disclosure nobody reviewed.
// DetailRows is every record a detail page stands for, and the key each one is
// addressed by.
//
// Read through the listing the page names, so what a caller sees is what the
// server would serve: the allow-list on that listing is the one decision about
// which fields of a record are public, and a second path around it would be a
// disclosure nobody reviewed.
//
// Exported because two callers need the same enumeration — the bundle renders a
// file per record, and the static copy of a site has to know which addresses
// exist before it can ask for them. Two enumerations would be two answers to
// "which records have pages".
func DetailRows(src Sources, name string, body any, d Detail) (
	keys []string, rows []listing.Row, err error) {

	if src.Listings == nil || src.Listings.Set == nil {
		return nil, nil, fmt.Errorf(
			"%s reads records through %q and this build has no listings",
			name, d.Listing)
	}
	l, ok := src.Listings.Set.Get(d.Listing)
	if !ok {
		return nil, nil, fmt.Errorf(
			"%s reads records through the listing %q, which is not declared",
			name, d.Listing)
	}
	idx, err := src.Listings.Index.For(src.Listings.Store, src.Listings.Tree,
		l.Collection)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", name, err)
	}
	res, err := listing.Resolve(l, idx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", name, err)
	}
	for _, row := range res.Rows {
		key, _ := row[d.Key].(string)
		if key == "" {
			// A record with no key has no address, so it cannot have a page.
			// Skipped rather than addressed by a blank path, which would
			// collide every such record onto one URL.
			continue
		}
		keys = append(keys, key)
		rows = append(rows, row)
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf(
			"%s stands for records and the listing %q returned none, so a "+
				"bundle would carry links to pages that do not exist",
			name, d.Listing)
	}
	return keys, rows, nil
}

func detailFiles(src Sources, layouts Layouts, name string, body any, d Detail,
	render func(string, map[string]any) (string, error)) (
	map[string][]byte, error) {

	keys, rows, err := DetailRows(src, name, body, d)
	if err != nil {
		return nil, err
	}

	out := map[string][]byte{}
	for i, row := range rows {
		key := keys[i]
		ctx, cerr := src.For(name, body, nil)
		if cerr != nil {
			return nil, fmt.Errorf("%s/%s: %w", name, key, cerr)
		}
		ctx["record"] = map[string]any(row)
		_, layout, lerr := layouts.For(body)
		if lerr != nil {
			return nil, fmt.Errorf("%s/%s: %w", name, key, lerr)
		}
		html, rerr := render(layout, ctx)
		if rerr != nil {
			return nil, fmt.Errorf("%s/%s: %w", name, key, rerr)
		}
		out[name+"/"+key+"/index.html"] = []byte(html)
	}
	return out, nil
}
