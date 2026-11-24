// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Records over HTTP.
//
// The same shape as the pages API and for the same reasons: ETag from the
// content hash, If-Match on writes, and a listing that counts what the caller
// can see rather than what exists. A second API with different rules would be
// a second set of mistakes.

// Records is what the host supplies so this package can read and write
// records without knowing where the draft is or how a commit is made.
type Records struct {
	// Tree returns the tree records are read from.
	Tree func() (string, error)
	// Commit makes a tree the new draft. It returns no commit id, and the
	// one it made is read from the draft ref under the same lock, for the
	// audit record (OnWrite, OnDelete), which named none.
	Commit func(tree, message, author string) error
	// Writable allows POST, PUT and DELETE. Off by default, like the pages
	// API: a read API and a write API are different products.
	Writable bool
}

// recordsWritableFix is the command line whose API writes records, for a
// refusal of a record write to name. Not the site's: it serves no records,
// with --api-writable or without, so the `quilzo site --api --api-writable`
// this named answered "this server does not serve records".
const recordsWritableFix = "quilzo serve"

func (s *Server) recordsEnabled(w http.ResponseWriter) bool {
	if s.Records == nil || s.Records.Tree == nil {
		writeError(w, http.StatusNotFound, Error{
			Error:  "this server does not serve records",
			Detail: "it was started without one",
		})
		return false
	}
	return true
}

// collections lists what exists.
func (s *Server) collections(w http.ResponseWriter, r *http.Request) {
	if !s.recordsEnabled(w) {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, Error{Error: "GET only"})
		return
	}
	if tokenFrom(r) == nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted", Detail: "not authenticated"})
		return
	}
	tree, err := s.Records.Tree()
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the store could not be read", Detail: err.Error()})
		return
	}
	names, err := collection.Names(s.Store, tree)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the store could not be read", Detail: err.Error()})
		return
	}
	tok := tokenFrom(r)
	type row struct {
		Name    string `json:"name"`
		Records int    `json:"records"`
	}
	out := []row{}
	for _, n := range names {
		// A token scoped to particular types does not see the others, for the
		// same reason it does not see their pages.
		if tok != nil && !tok.Scope.AllowsType(n) {
			continue
		}
		// Only the collections this caller may read, each asked about
		// itself (auth.DataResource).
		if s.may(r, auth.ActView, auth.DataResource(n)) != nil {
			continue
		}
		c, _ := collection.Count(s.Store, tree, n)
		out = append(out, row{n, c})
	}
	writeJSON(w, http.StatusOK, map[string]any{"collections": out})
}

// records handles a collection and the records in it.
func (s *Server) records(w http.ResponseWriter, r *http.Request) {
	if !s.recordsEnabled(w) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/records/")
	name, id, _ := strings.Cut(rest, "/")
	if name == "" {
		s.notFound(w, r)
		return
	}
	if err := collection.ValidName(name); err != nil {
		writeError(w, http.StatusBadRequest, Error{Error: err.Error()})
		return
	}
	tok := tokenFrom(r)
	if tok != nil && !tok.Scope.AllowsType(name) {
		// Not-found rather than forbidden, exactly as an out-of-scope page is:
		// 403 would confirm the collection exists to a token issued so it
		// could not learn that.
		writeError(w, http.StatusNotFound, Error{Error: "no such collection"})
		return
	}

	switch {
	case id == "" && r.Method == http.MethodGet:
		s.listRecords(w, r, name)
	case id == "" && r.Method == http.MethodPost:
		s.writeRecord(w, r, name, "")
	case id != "" && r.Method == http.MethodGet:
		s.getRecord(w, r, name, id)
	case id != "" && r.Method == http.MethodPut:
		s.writeRecord(w, r, name, id)
	case id != "" && r.Method == http.MethodDelete:
		s.deleteRecord(w, r, name, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, Error{
			Error: "GET and POST on a collection; GET, PUT and DELETE on a record"})
	}
}

func (s *Server) listRecords(w http.ResponseWriter, r *http.Request, name string) {
	if err := s.may(r, auth.ActView, auth.DataResource(name)); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}
	q := collection.Query{
		Equals:     map[string]any{},
		Contains:   map[string]string{},
		Sort:       r.URL.Query().Get("sort"),
		Descending: r.URL.Query().Get("order") == "desc",
	}
	// where=field:value, repeatable. A separate parameter per filter rather
	// than one expression, because an expression needs an evaluator and an
	// evaluator over a query string is the shape of every injection.
	for _, pair := range r.URL.Query()["where"] {
		if k, v, ok := strings.Cut(pair, ":"); ok {
			q.Equals[k] = typedValue(v)
		}
	}
	for _, pair := range r.URL.Query()["contains"] {
		if k, v, ok := strings.Cut(pair, ":"); ok {
			q.Contains[k] = v
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > collection.MaxLimit {
			writeError(w, http.StatusBadRequest, Error{
				Error: fmt.Sprintf("limit must be 1 to %d", collection.MaxLimit),
				Detail: "refused rather than clamped: a client asking for more " +
					"and receiving fewer believes it has everything"})
			return
		}
		q.Limit = n
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			q.Offset = n
		}
	}

	tree, err := s.Records.Tree()
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the store could not be read"})
		return
	}
	// Through the index when the server has one. An API is the surface most
	// likely to be polled, so paying the scan per request is the difference
	// between a listing endpoint and an outage.
	var recs []collection.Record
	var total int
	if s.Index != nil {
		var idx *collection.Index
		idx, err = s.Index.For(s.Store, tree, name)
		if err == nil {
			recs, total = idx.Query(q)
		}
	} else {
		recs, total, err = collection.List(s.Store, tree, name, q)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the collection could not be read", Detail: err.Error()})
		return
	}
	// An empty list is [], not the null a nil slice is written as: a
	// collection nothing matched answered "records": null.
	if recs == nil {
		recs = []collection.Record{}
	}
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	writeJSON(w, http.StatusOK, map[string]any{
		"collection": name, "total": total, "records": recs,
		"limit": q.Limit, "offset": q.Offset,
	})
}

func (s *Server) getRecord(w http.ResponseWriter, r *http.Request, name, id string) {
	if err := s.may(r, auth.ActView, auth.DataResource(name)); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}
	tree, err := s.Records.Tree()
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the store could not be read"})
		return
	}
	rec, err := collection.Get(s.Store, tree, name, id)
	if err != nil {
		writeError(w, http.StatusNotFound, Error{Error: "no such record"})
		return
	}
	// The ETag is the record's own content hash, so If-None-Match answers
	// exactly the question it appears to ask — the same property the pages
	// API has and for the same reason.
	etag := quote(recordETag(rec))
	if matches(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) writeRecord(w http.ResponseWriter, r *http.Request, name, id string) {
	if !s.Records.Writable {
		writeError(w, http.StatusMethodNotAllowed, Error{
			Error: "this API is read-only",
			Fix:   recordsWritableFix,
		})
		return
	}
	if err := s.may(r, auth.ActEditDraft, auth.DataResource(name)); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}
	// An id that can address no record is the caller's to fix, as a page
	// name the store cannot hold is: it was met only by the write, and
	// answered 500 "the write failed", which a client retries.
	if id != "" {
		if err := collection.ValidID(id); err != nil {
			writeError(w, http.StatusBadRequest, Error{
				Error: "that is not a record id", Detail: err.Error(),
				Fix: "POST to the collection to create a record, and use the id it is given",
			})
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.bodyMax())+1))
	if err != nil || len(body) > s.bodyMax() {
		writeError(w, http.StatusRequestEntityTooLarge, Error{
			Error: "the body is too large"})
		return
	}
	fields, err := objectBody(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Error: "the body is not a JSON object", Detail: err.Error()})
		return
	}

	tok := tokenFrom(r)
	who := "api"
	if tok != nil {
		who = tok.Principal
	}

	// Read, compare and write inside the ref lock, so If-Match is
	// compare-and-swap rather than advice — the same correction the pages API
	// needed after sixteen concurrent writes all succeeded against one base.
	var (
		out      collection.Record
		conflict *Error
		status   int
		cid      string
		created  = id == ""
	)
	lockErr := s.Store.WithRefLock(func() error {
		tree, err := s.Records.Tree()
		if err != nil {
			return err
		}
		if id != "" {
			existing, gerr := collection.Get(s.Store, tree, name, id)
			ifMatch, ifNone := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
			current := ""
			if gerr == nil {
				// If-None-Match: * is a precondition too, and refuses a
				// record that exists (precondition) rather than this.
				if strings.TrimSpace(ifMatch) == "" && strings.TrimSpace(ifNone) != "*" {
					status, conflict = http.StatusPreconditionRequired, &Error{
						Error: "If-Match is required",
						Detail: "a write without a validator overwrites " +
							"whatever is there now, including somebody " +
							"else's edit made since you read it",
						Fix: "GET the record, then PUT with If-Match set to its ETag",
					}
					return nil
				}
				current = recordETag(existing)
			}
			if e := precondition(ifMatch, ifNone, gerr == nil, current, "record",
				"GET it again, re-apply your change, and PUT with its new ETag"); e != nil {
				status, conflict = http.StatusPreconditionFailed, e
				return nil
			}
			created = gerr != nil
		}

		next, rec, err := collection.Put(s.Store, tree, name,
			collection.Record{ID: id, Fields: fields}, time.Now(),
			schema.RecordGate(s.Types))
		if err != nil {
			return err
		}
		if err := s.Records.Commit(next, "api: write "+name, who); err != nil {
			return err
		}
		cid = s.Store.GetRef(site.RefDraft)
		out = rec
		return nil
	})

	if conflict != nil {
		writeError(w, status, *conflict)
		return
	}
	if lockErr != nil {
		// Content that fails its type is the caller's problem, not this
		// server's. It came back as 500 until somebody looked: a record
		// missing a required field paged an on-call engineer, spent an error
		// budget on a typo, and told the client to retry something that could
		// never succeed. 422 says the request was well-formed and the content
		// was not, which is exactly the situation.
		if schema.IsInvalid(lockErr) {
			writeError(w, http.StatusUnprocessableEntity, Error{
				Error:  "this content does not satisfy its type",
				Detail: lockErr.Error(),
				Fix:    "GET /api/v1/types to see what the type requires",
			})
			return
		}
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the write failed", Detail: lockErr.Error()})
		return
	}
	if s.OnWrite != nil {
		s.OnWrite(who, name+"/"+out.ID, cid)
	}
	w.Header().Set("ETag", quote(recordETag(&out)))
	// 201 for a record the write made, by POST or by a PUT to an id with
	// nothing there, which RFC 9110 §9.3.4 requires of a PUT that creates.
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	if id == "" {
		w.Header().Set("Location", "/api/v1/records/"+name+"/"+out.ID)
	}
	writeJSON(w, code, out)
}

func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request, name, id string) {
	if !s.Records.Writable {
		writeError(w, http.StatusMethodNotAllowed, Error{
			Error: "this API is read-only", Fix: recordsWritableFix})
		return
	}
	if err := s.may(r, auth.ActEditDraft, auth.DataResource(name)); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}
	tok := tokenFrom(r)
	who := "api"
	if tok != nil {
		who = tok.Principal
	}
	// If-Match, compared under the lock as a write's is. The API's own
	// description says a delete needs it, and it was not asked for: with
	// none, or one that no longer matched, the record was deleted, so a
	// client deleting what it had read deleted whatever somebody had put
	// there since.
	ifMatch, ifNone := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
	var (
		missing  bool
		conflict *Error
		status   int
		cid      string
	)
	lockErr := s.Store.WithRefLock(func() error {
		tree, err := s.Records.Tree()
		if err != nil {
			return err
		}
		existing, err := collection.Get(s.Store, tree, name, id)
		if err != nil {
			missing = true
			return nil
		}
		if strings.TrimSpace(ifMatch) == "" {
			status, conflict = http.StatusPreconditionRequired, &Error{
				Error: "If-Match is required",
				Detail: "a delete without a validator deletes whatever is " +
					"there now, including somebody else's edit made since " +
					"you read it",
				Fix: "GET the record, then DELETE with If-Match set to its ETag",
			}
			return nil
		}
		if e := precondition(ifMatch, ifNone, true, recordETag(existing), "record",
			"GET it again, and DELETE with its new ETag if it is still to go"); e != nil {
			status, conflict = http.StatusPreconditionFailed, e
			return nil
		}
		next, err := collection.Delete(s.Store, tree, name, id)
		if err != nil {
			return err
		}
		if err := s.Records.Commit(next, "api: delete from "+name, who); err != nil {
			return err
		}
		cid = s.Store.GetRef(site.RefDraft)
		return nil
	})
	if missing {
		writeError(w, http.StatusNotFound, Error{Error: "no such record"})
		return
	}
	if conflict != nil {
		writeError(w, status, *conflict)
		return
	}
	if lockErr != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the delete failed", Detail: lockErr.Error()})
		return
	}
	// Recorded as a deletion, with the commit that made it. It was told to
	// the write path's hook "so the audit trail does not have a hole shaped
	// like the API" — its own words — and closed the hole with an entry
	// that said api.write, named no commit, and nothing about a deletion.
	// A host without OnDelete is still told, through OnWrite.
	switch {
	case s.OnDelete != nil:
		s.OnDelete(who, name+"/"+id, cid)
	case s.OnWrite != nil:
		s.OnWrite(who, name+"/"+id, cid)
	}
	w.WriteHeader(http.StatusNoContent)
}

// recordETag is the record's content hash: the object id the store keeps
// it under, by the store's own definition (store.ObjectID over the record's
// canonical JSON, which is what PutBlob hashes), so it is not a second
// definition of identity.
//
// It was the id and the second the record was last written in. Two writes
// inside one second kept the first one's validator, so a client holding it
// from before the second passed If-Match and overwrote that write unseen:
// the lost update If-Match exists to prevent. Hashed over the record as
// read, which for every record whose numbers survive being read as JSON —
// all but an integer past 2^53 written by something other than this API —
// is the id it is stored under; for the rest it is still a hash of what is
// served, the same on every read.
func recordETag(r *collection.Record) string {
	b, err := json.Marshal(r)
	if err != nil {
		// Unreachable for a record decoded from JSON. No validator rather
		// than a wrong one: an empty tag matches nothing.
		return ""
	}
	return store.ObjectID(store.KindBlob, b)
}

// typedValue reads a query-string value as the type it looks like, so a filter
// on a number matches a stored number rather than silently matching nothing.
func typedValue(v string) any {
	switch v {
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		return n
	}
	return v
}
