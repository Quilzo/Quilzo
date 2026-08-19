package public

import (
	"encoding/json"
	"net/http"

	"github.com/quilzo/quilzo/internal/listing"
)

// A catalogue an agent can read.
//
// # Why this is a listing rather than a new subsystem
//
// The 2026 shopping agents discover products and hand the purchase back to the
// merchant — OpenAI deprecated its own in-chat checkout in March and the
// protocols settled on discovery plus redirect. So what a shop needs from a CMS
// is not a cart. It is a machine-readable catalogue that says what is for sale,
// what may be done with the description, and where a person completes the
// purchase.
//
// A declared listing is already that. It names a collection, allows specific
// fields, carries typed parameters and a cost budget, and refuses anything
// outside them. Serving one as JSON adds a route and no new way to ask a
// question — which matters here more than usual, because this endpoint is
// meant to be read by software that was told what to fetch by somebody else.
//
// # What it deliberately does not do
//
// No prices are computed, no stock is reserved, no order is taken. Quilzo holds
// what was published and can prove it; a catalogue is a statement about
// content, and the moment it becomes a transaction this process needs
// credentials it currently does not have. The public server's one write
// capability is appending a form submission, and this does not change that.

// catalogue serves a declared listing as a machine-readable feed.
//
// The listing is named by configuration, never by the request. A caller that
// could choose which listing to run would have a query parameter that selects
// from everything declared — including the ones a page embeds behind a filter
// somebody assumed was private.
func (st *Site) catalogue(w http.ResponseWriter, r *http.Request) {
	if st.Catalogue == "" || st.Listings == nil || st.Listings.Set == nil {
		// Nothing declared, nothing served. A catalogue route that answers with
		// an empty document tells an agent this shop has no products, which is
		// a different and worse claim than "this site does not publish one".
		http.NotFound(w, r)
		return
	}

	l, ok := st.Listings.Set.Get(st.Catalogue)
	if !ok {
		// Configured to serve a listing that does not exist. Refused rather
		// than 404'd, because the two mean different things to whoever has to
		// fix it: this is a misconfiguration on this side, not an absent
		// resource.
		http.Error(w, "the configured catalogue listing does not exist",
			http.StatusInternalServerError)
		return
	}

	idx, err := st.Listings.Index.For(st.Listings.Store, st.Listings.Tree,
		l.Collection)
	if err != nil {
		http.Error(w, "the catalogue could not be read",
			http.StatusInternalServerError)
		return
	}

	// Parameters from the query string, resolved by the listing's own typed
	// definition. Unknown names are ignored there rather than here, so this
	// route cannot widen what the listing accepts.
	args := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			args[k] = v[0]
		}
	}

	res, err := listing.Resolve(l, idx, args)
	if err != nil {
		// The listing's own refusal, which is a caller error: a parameter
		// outside its declared type, or a filter it does not allow.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rows := make([]map[string]any, 0, len(res.Rows))
	for _, row := range res.Rows {
		rows = append(rows, map[string]any(row))
	}

	out := map[string]any{
		"catalogue": l.Name,
		"label":     l.Label,
		"items":     rows,
		"shown":     len(rows),
		"total":     res.Total,
		"truncated": res.Truncated,
	}
	// The terms travel with the data.
	//
	// An agent that reads a catalogue is about to repeat its contents to
	// somebody. Making it fetch a second document to discover whether it may is
	// how the terms get skipped — so the answer is in the response that carried
	// the products, pointing at the document that states it in full.
	if st.Licence != nil {
		terms := map[string]any{"policy": "/license.xml"}
		if len(st.Licence.Permits) > 0 {
			terms["permits"] = st.Licence.Permits
		}
		if len(st.Licence.Prohibits) > 0 {
			terms["prohibits"] = st.Licence.Prohibits
		}
		if st.Licence.Attribution != "" {
			terms["attribution"] = st.Licence.Attribution
		}
		out["terms"] = terms
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The mining reservation applies here too. A catalogue is content, and an
	// agent taking it for training is the case the reservation is about.
	st.tdmHeaders(w)
	_ = json.NewEncoder(w).Encode(out)
}
