package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

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
	if err := s.may(r, auth.ActView, "/"); err != nil {
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
	if err := s.may(r, auth.ActView, "/"); err != nil {
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
