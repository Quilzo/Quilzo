// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/replica"
	"github.com/quilzo/quilzo/internal/store"
)

// Serving objects to a replica.
//
// # Two endpoints, because that is the whole protocol
//
// A peer asks what a ref points at, and asks for an object by id. Everything
// else — which objects are missing, what order to fetch them in, whether the
// answer may be adopted — is decided by the receiver. This side is deliberately
// stupid: it looks nothing up, decides nothing, and cannot be talked into
// sending something other than what was asked for, because the thing asked for
// is named by its own hash.
//
// # Read-only, and there is no push
//
// Nothing here accepts an object. A push endpoint is an authenticated write
// endpoint that somebody else chooses the timing of, and it is how every
// federation protocol acquires a spam problem. A store that wants content
// pulls it.
//
// # Why an object is served to a viewer and a ref is not gated further
//
// Reaching this at all takes a credential. Beyond that, the two endpoints leak
// the same thing the content API already serves to the same caller — with one
// real difference: a replica reads the *draft* as well as what is published, so
// it is gated on the same permission the draft is gated on everywhere else.
//
// An object id is not a capability. Knowing one means having read a tree that
// named it, which means already having been served that tree.
//
// # But it is the whole store, so it takes a credential for the whole store
//
// The pages API asks about each page, and the records API about each
// collection. This asked whether the caller may view "/", and then served
// whatever was asked for: a reader on the site denied /pricing was refused
// GET /api/v1/pages/pricing and read the draft's ref here, then its commit,
// its tree and the page's blob. A reader denied a collection read the
// collection the same way, and a token limited to some types or locales had
// its limits skipped, because nothing here knows which page an object is.
//
// So a replica's credential must be one the whole store may be sent to:
// viewing "/", with no deny on content or data that takes viewing away, and
// no type or locale limit. Anything narrower is refused with the reason,
// rather than served a partial store, which a replica cannot use: a tree
// with a page missing does not hash to the commit that named it.

// replicaRef answers what one ref points at.
//
//	GET /api/v1/replica/ref/{name}
func (s *Server) replicaRef(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, Error{
			Error:  "only GET",
			Detail: "a replica reads; it does not push"})
		return
	}
	// The draft is readable by a replica, so this is the draft's permission
	// rather than the public site's.
	if err := s.mayReplicate(r); err != nil {
		writeError(w, http.StatusForbidden, Error{
			Error: "not permitted", Detail: err.Error()})
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/replica/ref/")
	if name == "" || strings.Contains(name, "/") {
		writeError(w, http.StatusBadRequest, Error{
			Error:  "name one ref",
			Detail: "/api/v1/replica/ref/draft"})
		return
	}
	// A peer's own quarantine refs are not served on. Replication is between
	// two stores that were paired; passing a third store's head through this
	// one would make it look like content this store stands behind, and the
	// operator who paired them never agreed to that.
	if strings.HasPrefix(name, replica.PeerPrefix) {
		writeError(w, http.StatusNotFound, Error{
			Error: "no such ref",
			Detail: "refs holding another peer's head are not served on. " +
				"Pair with that peer directly"})
		return
	}
	oid := s.Store.GetRef(name)
	if oid == "" {
		writeError(w, http.StatusNotFound, Error{
			Error: "no such ref", Detail: name})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ref": name, "commit": oid})
}

// replicaObject answers with one object by id.
//
//	GET /api/v1/replica/object/{id}
//
// The payload is base64 in a JSON envelope rather than raw bytes, so the kind
// travels with it in one response that cannot be half-read. An object is at
// most a page; this is not the place to optimise.
func (s *Server) replicaObject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, Error{
			Error:  "only GET",
			Detail: "a replica reads; it does not push"})
		return
	}
	if err := s.mayReplicate(r); err != nil {
		writeError(w, http.StatusForbidden, Error{
			Error: "not permitted", Detail: err.Error()})
		return
	}
	oid := strings.TrimPrefix(r.URL.Path, "/api/v1/replica/object/")
	kind, payload, err := s.Store.GetRaw(oid)
	if err != nil {
		// The same answer for absent and for malformed. Distinguishing them
		// turns this into an oracle for what is in the store.
		writeError(w, http.StatusNotFound, Error{
			Error: "no such object", Detail: "nothing is stored under that id"})
		return
	}
	// Immutable by construction: the id is the hash, so this response can
	// never become wrong. Cached for a year, which is what content-addressing
	// is for and the reason an edge replica costs nothing to keep warm.
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	writeJSON(w, http.StatusOK, objectResponse{
		ID: oid, Kind: kind, Payload: base64.StdEncoding.EncodeToString(payload)})
}

// mayReplicate is whether the caller may be sent the whole store.
//
// Viewing "/" first, through may, so the credential's role, path and the
// policy are asked as everywhere else. Then the two ways a reader of "/" is
// still narrower than the store: a limit on the credential, and a deny in
// the policy. A deny is asked about through Evaluate, at the place it was
// written, so one that does not take viewing away (publishing /legal, say)
// leaves replication alone, and an expired one counts as it does elsewhere.
// An area other than the records is not in the store, so a deny there is
// not a part of it this would send.
func (s *Server) mayReplicate(r *http.Request) error {
	if err := s.may(r, auth.ActView, "/"); err != nil {
		return err
	}
	tok := tokenFrom(r)
	if len(tok.Scope.Types) > 0 || len(tok.Scope.Locales) > 0 {
		return fmt.Errorf("this credential is limited to %s, and a replica "+
			"is sent every page and record in the store. Pair with a "+
			"credential that has no type or locale limit", tok.Scope)
	}
	if s.Policy == nil {
		return nil
	}
	now := time.Now()
	for _, b := range s.Policy.Snapshot() {
		if b.Principal != tok.Principal || !b.Deny || !b.Live(now) {
			continue
		}
		if auth.IsArea(b.Resource) && !auth.Covers(auth.AreaData, b.Resource) {
			continue
		}
		if d := s.Policy.Evaluate(tok.Principal, auth.ActView, b.Resource); !d.Allowed {
			return fmt.Errorf("%s, and a replica is sent every page and "+
				"record in the store", d.Reason)
		}
	}
	return nil
}

// objectResponse is one object on the wire.
type objectResponse struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Payload string `json:"payload"`
}

// decodeObject reads one off the wire, which is the client's half.
//
// Living beside the writer on purpose: a serialisation with its two ends in
// different packages is one where a field gets renamed on one side.
func decodeObject(body []byte) (string, string, []byte, error) {
	var resp objectResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", "", nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(resp.Payload)
	if err != nil {
		return "", "", nil, err
	}
	return resp.ID, resp.Kind, payload, nil
}

var _ = store.KindBlob
