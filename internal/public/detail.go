package public

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// A page for one record, so a product has a URL.
//
// # The gap this closes
//
// Records were reachable only through a listing embedded in a page. That is
// enough for a feed and useless for a shop: a product nobody can link to
// cannot be shared, cannot be the target of a search result, cannot be what a
// shopping agent points a buyer at, and cannot carry its own metadata. The
// catalogue feed said a thing was for sale and there was nowhere to send
// anybody.
//
// # Why the detail reads through a listing rather than the collection
//
// The obvious implementation looks up the record by id and renders it, and it
// leaks. A listing carries a field allow-list — the shop's catalogue excludes
// the SKU deliberately — and a detail route that read the collection directly
// would be a second answer to "what of this record is public", written by
// somebody who was thinking about templates rather than about disclosure.
//
// So a detail page names a listing, and the record is fetched through it. The
// allow-list, the parameters and the conditions are the ones already declared.
// The consequences fall out rather than being implemented: a record the listing
// filters out has no page, so an unpublished or out-of-scope product cannot be
// reached by guessing its URL, and the fields on the page are exactly the
// fields in the feed.
//
// # Why the key is declared and not the record id
//
// A URL built from a 32-character random id is not a URL anybody types, links
// or reads, and it makes the address of a thing an implementation detail of
// where it was stored. The page names which field is the key — "slug" for the
// shop — and the lookup matches on it.
//
// Two records sharing a key is a conflict, not a race: it is answered as
// ambiguous rather than by picking the first, because picking is a decision
// made by whatever order the index happened to return and nobody reviewed it.

// Detail and DetailOf now live in internal/render, because the exporter needs
// the same answer and got a different one — see the note there. Aliased rather
// than re-declared so this file still reads as the place the route is served.
type Detail = render.Detail

func detailOf(body any) (Detail, bool) { return render.DetailOf(body) }

// findRecord returns the one record a detail URL names.
//
// The listing does the filtering, so this is a scan of what the listing already
// decided is visible. That is the point: there is no second query with second
// rules, and a record the listing excludes is not found here either.
func (st *Site) findRecord(d Detail, key string, args map[string]string) (
	listing.Row, error) {

	if !d.Declared() {
		return nil, fmt.Errorf(
			"this page declares a detail route with %s missing, so it cannot "+
				"answer for any record", missingHalf(d))
	}
	if st.Listings == nil || st.Listings.Set == nil {
		return nil, fmt.Errorf("no listings are declared")
	}
	l, ok := st.Listings.Set.Get(d.Listing)
	if !ok {
		return nil, fmt.Errorf(
			"this page reads records through the listing %q, which is not "+
				"declared", d.Listing)
	}
	idx, err := st.Listings.Index.For(st.Listings.Store, st.Listings.Tree,
		l.Collection)
	if err != nil {
		return nil, err
	}
	res, err := listing.Resolve(l, idx, args)
	if err != nil {
		return nil, err
	}

	return matchOne(res.Rows, d.Key, key)
}

// matchOne finds the single row whose key field holds a value.
//
// Separate from the lookup so the three answers — none, one, several — can be
// tested without building a store to produce each. The several case is the one
// that matters: answering it by taking the first is a decision made by whatever
// order the index happened to return, which nobody reviewed, and the two pages
// would swap places on a reindex.
func matchOne(rows []listing.Row, field, want string) (listing.Row, error) {
	var found listing.Row
	var n int
	for _, row := range rows {
		if v, _ := row[field].(string); v == want {
			found = row
			n++
		}
	}
	switch n {
	case 0:
		return nil, errNoRecord
	case 1:
		return found, nil
	default:
		return nil, fmt.Errorf(
			"%d records share the %s %q, so this address does not name one "+
				"of them", n, field, want)
	}
}

func missingHalf(d Detail) string {
	switch {
	case d.Listing == "":
		return "the listing it reads through"
	case d.Key == "":
		return "the field that appears in the URL"
	}
	return "nothing"
}

// errNoRecord is a record that is not there, or that the listing excludes.
//
// One error for both, deliberately. Distinguishing them turns the route into
// an oracle for what is in the store: a different answer for "no such product"
// and "a product you may not see" tells anybody who asks which unpublished
// slugs exist.
var errNoRecord = fmt.Errorf("no such record")

// detailRoute answers a URL of the form /page/key when the page declares one.
//
// Returns false when this is not a detail request, so the caller falls through
// to the ordinary page lookup and a two-segment path that is simply not a page
// still 404s the way it always did.
func (st *Site) detailRoute(w http.ResponseWriter, r *http.Request,
	pages map[string]any, path string) bool {

	base, key, ok := strings.Cut(path, "/")
	if !ok || base == "" || key == "" || strings.Contains(key, "/") {
		return false
	}
	body, exists := pages[base]
	if !exists {
		return false
	}
	d, declared := detailOf(body)
	if !declared {
		return false
	}

	row, err := st.findRecord(d, key, firstOf(r.URL.Query()))
	if err != nil {
		if err == errNoRecord {
			st.notFound(w, r)
			return true
		}
		// A declaration that cannot work is the operator's problem and is
		// said out loud, because a misconfigured detail route that 404s looks
		// exactly like a record that is not there.
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	st.renderDetail(w, r, base, body, row)
	return true
}

// renderDetail draws a detail page with the record in scope.
//
// The record lands under "record", beside "page". Merging it into the page's
// own fields was the alternative and is worse: a record with a "title" would
// silently replace the page's, and which one a template got would depend on
// what somebody named a product field. Two names, no collision, and a template
// says which it means.
func (st *Site) renderDetail(w http.ResponseWriter, r *http.Request,
	name string, body any, row listing.Row) {

	ctx, err := st.sources().For(name, body, firstOf(r.URL.Query()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ctx["record"] = map[string]any(row)

	out, err := tmpl.Render(st.Template, ctx)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	// The same head injection every page gets, so a detail page carries the
	// manifest link, the catalogue pointer and the provenance marking. A
	// legal marking present on the shop page and missing from the product
	// page is a marking that is missing where the product actually is.
	out = st.injectHead(out, name, "")
	// The structured data, injected like the rest of the head so it cannot be
	// missing from the one template nobody checked.
	if ld := productLD(row, st.Name); ld != "" {
		out = insertBeforeHead(out, ld)
	}
	// No ETag. The page's own hash does not describe this response — the
	// record does — and a hash of both is a cache key nothing invalidates
	// when the record changes. Serving it uncached is slower and correct;
	// serving the page's hash would mean an edited product never updates.
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(out))
}

// productLD renders a record as schema.org structured data.
//
// # Why this is on the detail page and not the listing
//
// The catalogue feed is what a shopping agent reads once it knows this site
// exists. Structured data on the page is how it finds out — a crawler, a
// shopping surface and an agent arriving from a search result all read the
// page, and a product page with no machine-readable price is a product that
// exists only for people who were already looking at it.
//
// # Emitted from the same row the page renders
//
// Not from the record, from the row the listing returned. So the field
// allow-list applies to the structured data exactly as it applies to the
// visible page, and there is no second path by which the SKU reaches a
// crawler. Two renderers reading different sources is how a page says one
// price and its metadata says another.
//
// # Only what is actually known
//
// Fields absent from the row are absent from the output rather than emitted
// empty. A JSON-LD block asserting an empty brand is a claim that this shop
// has no brand, and structured data is read by machines that do not apply
// charity to blank strings.
func productLD(row listing.Row, siteName string) string {
	str := func(k string) string { v, _ := row[k].(string); return v }

	name := str("name")
	if name == "" {
		return ""
	}
	doc := map[string]any{
		"@context": "https://schema.org",
		"@type":    "Product",
		"name":     name,
	}
	// Only fields the row actually carries. There is no sku here and there
	// cannot be: it is not on the listing's allow-list, so it never reached
	// this row, which is the point of rendering from the row rather than from
	// the record.
	for key, field := range map[string]string{
		"description": "description",
		"material":    "material",
	} {
		if v := str(field); v != "" {
			doc[key] = v
		}
	}
	if siteName != "" {
		doc["brand"] = map[string]any{"@type": "Brand", "name": siteName}
	}

	// The offer. Price is the number, not the written-out string: a consumer
	// of structured data has to compare it, and "£24.00" is not a number in
	// any locale's arithmetic.
	if pence, ok := numberOf(row["price"]); ok {
		offer := map[string]any{
			"@type":         "Offer",
			"price":         fmt.Sprintf("%.2f", pence/100),
			"priceCurrency": str("currency"),
			"availability":  availabilityLD(str("availability")),
		}
		doc["offers"] = offer
	}

	b, err := json.Marshal(doc)
	if err != nil {
		return ""
	}
	return `<script type="application/ld+json">` + string(b) + `</script>`
}

// availabilityLD maps the closed availability set onto schema.org's.
//
// A mapping rather than passing the token through, because "made_to_order" is
// this shop's word and schema.org has its own. An unknown token maps to
// nothing at all rather than to InStock: guessing in the available direction
// is how a sold-out product stays listed as buyable.
func availabilityLD(v string) string {
	switch v {
	case "in_stock", "low_stock":
		return "https://schema.org/InStock"
	case "made_to_order":
		return "https://schema.org/PreOrder"
	case "sold_out":
		return "https://schema.org/OutOfStock"
	}
	return ""
}

// numberOf reads a JSON number however it decoded.
func numberOf(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return 0, false
}
