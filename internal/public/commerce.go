// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
)

// Selling to other people's agents.
//
// # Why this is a second route set, not a widening of the catalogue's
//
// /catalogue.json serves the same listing this surface reads, and it stays
// exactly as it was: a read-only statement of what is for sale, cacheable,
// unauthenticated, for any machine that arrives. The UCP endpoints are a
// different thing in kind — they create carts and take orders — and they
// get their own gate: every request identified by a Web Bot Auth signature
// from a key the operator configured, every state change under an
// Idempotency-Key, no route here that reads or writes anything else this
// server holds.
//
// # The one new write, stated plainly
//
// The public server's write capability was "append a form submission, to a
// store that is not the content store". This adds a second, equally narrow
// one: the commerce service appends orders to its own file, under its own
// lock, and cannot reach the content store, a ref, or a commit. An attacker
// who owns this process can place orders and cannot publish a page, and
// that boundary is the whole design here, as it was for forms.
//
// # What the operator owes the deployment
//
// The UCP transport requirements are HTTPS with TLS 1.3 or better, which is
// a property of whatever terminates TLS in front of this server, not of
// this code; an operator serving /ucp/ over plaintext has chosen to expose
// credentials and mandates on the wire, and should not.
func (st *Site) commerceRoutes(mux *http.ServeMux) {
	if st.Commerce == nil {
		return
	}
	// The discovery document is public: it is an advertisement of what this
	// shop can do, and asking an agent to sign a request before it knows
	// whether there is anything to buy would be a riddle, not a protocol.
	mux.HandleFunc("/.well-known/ucp", st.Commerce.Discover)
	mux.HandleFunc("/ucp", st.Commerce.ServeHTTP)
	mux.HandleFunc("/ucp/", st.Commerce.ServeHTTP)
}
