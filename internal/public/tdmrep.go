package public

import (
	"encoding/json"
	"net/http"
	"strings"
)

// TDMRep: the reservation a machine reads before it takes the content.
//
// # Why this exists beside the RSL document
//
// /license.xml already states the terms, and RSL is the richer vocabulary. What
// it is not is the thing European law reads. The Text and Data Mining
// Reservation Protocol is the W3C standard for expressing an opt-out in a form
// a crawler is expected to check, and the DSM Directive's exception applies
// only where a reservation has been made "in an appropriate machine-readable
// manner". TDMRep is the mechanism written for that sentence.
//
// So the two are complements rather than alternatives. RSL says what is
// permitted and to whom, in detail, and depends on a crawler choosing to honour
// it. TDMRep says one narrow thing — mining is reserved — in the place a
// crawler is obliged to look.
//
// # Derived, never configured separately
//
// The reservation comes from the licence the operator already declared. A
// second place to state the same intention is a second place for the two to
// disagree, and a site whose RSL says "prohibits: train" while its TDMRep says
// nothing has published a contradiction that a crawler will resolve in the
// direction it prefers.
//
// Nothing is emitted when no licence is configured. A reservation nobody chose
// is worse than none: a crawler will honour it, and the operator never agreed
// to it — the same reasoning that makes /license.xml a 404 rather than an
// invention.

// tdmMining is the vocabulary that means "an automated system learns from this".
//
// Narrow on purpose. TDMRep reserves text and data mining, which is training
// and analysis — not search indexing, and not a person reading the page. A
// reservation that swept up search would take the site out of results, which
// is not what an operator asking to be excluded from training means.
var tdmMining = map[string]bool{
	"train": true, "text-and-data-mining": true, "tdm": true, "ai-train": true,
}

// reservesMining reports whether the declared licence refuses mining.
//
// Prohibition is read from Prohibits only. An absent permission is not a
// refusal: a licence that lists "search" under Permits and says nothing about
// training has not reserved anything, and inferring one from silence would
// publish a reservation the operator did not make.
func reservesMining(l *Licence) bool {
	if l == nil {
		return false
	}
	for _, p := range l.Prohibits {
		if tdmMining[strings.ToLower(strings.TrimSpace(p))] {
			return true
		}
	}
	return false
}

// tdmHeaders sets the reservation on a response.
//
// Headers rather than only a file, because that is where the standard puts the
// per-resource answer, and a crawler that fetched one page has already been
// told without a second request.
func (st *Site) tdmHeaders(w http.ResponseWriter) {
	if st.Licence == nil {
		return
	}
	if !reservesMining(st.Licence) {
		// A site that permits mining says so, rather than staying silent.
		// Silence is what an unconfigured site looks like, and "we never
		// objected" is a weaker position afterwards than "we said yes".
		w.Header().Set("tdm-reservation", "0")
		return
	}
	w.Header().Set("tdm-reservation", "1")
	// The policy is where the detail lives. Pointing at the RSL document keeps
	// one source of truth rather than restating the terms in a second grammar.
	w.Header().Set("tdm-policy", "/license.xml")
}

// tdmRep serves /.well-known/tdmrep.json.
//
// The site-wide answer, for a crawler that checks once rather than per
// resource. Same values as the headers, from the same licence.
func (st *Site) tdmRep(w http.ResponseWriter, r *http.Request) {
	if st.Licence == nil {
		http.NotFound(w, r)
		return
	}
	type entry struct {
		Location    string `json:"location"`
		Reservation int    `json:"tdm-reservation"`
		Policy      string `json:"tdm-policy,omitempty"`
	}
	e := entry{Location: "/"}
	if reservesMining(st.Licence) {
		e.Reservation = 1
		e.Policy = "/license.xml"
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode([]entry{e})
}
