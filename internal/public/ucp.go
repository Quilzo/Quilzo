// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import "net/http"

// ucpRoutes serves the catalogue over UCP when the operator has turned it on.
//
// The same listing /catalogue.json serves, read the same way, so a shopping
// agent on either route sees the same products at the same prices. It sits
// behind the same crawl gate as every other route: an agent that signs its
// requests is held to the licence terms a crawler is, because what it takes
// away is the same content.
//
// Reads only. The public server's one write is still a form submission;
// nothing here keeps anything a caller sends.
func (st *Site) ucpRoutes(mux *http.ServeMux) {
	if st.UCP == nil {
		return
	}
	mux.HandleFunc("/.well-known/ucp", st.UCP.Profile)
	mux.HandleFunc("/ucp/", func(w http.ResponseWriter, r *http.Request) {
		// The terms travel with the data here as on the catalogue: an
		// agent reading products is about to repeat them to somebody.
		st.tdmHeaders(w)
		st.UCP.ServeHTTP(w, r)
	})
}
