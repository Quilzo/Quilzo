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
	// Commit makes a tree the new draft and returns nothing useful — the
	// caller already knows what it wrote.
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

// typeFix is where a write refused by its content type can read what the
// type requires, for the 422 to name: the type's own definition, by name.
//
// Both write paths named GET /api/v1/types, and this API has no such route:
// it answered 404 "no such endpoint", the one fix offered for the refusal
// leading nowhere.
func typeFix(typeName string) string {
	if typeName == "" {
		return "quilzo type list names the types, and quilzo type show NAME what one requires"
	}
	return "quilzo type show " + typeName + " says what it requires; the detail says what this lacks"
}

// typeFixFor is typeFix for the type a binding names, read from this
// server's types.
func (s *Server) typeFixFor(bound func(*schema.Store) string) string {
	if s.Types != nil {
		if st, err := s.Types(); err == nil && st != nil {
			return typeFix(bound(st))
		}
	}
	return typeFix("")
}

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
	if !readMethod(r) {
		s.notAllowed(w, r, Error{Error: "GET only"})
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
	case id == "" && readMethod(r):
		s.listRecords(w, r, name)
	case id == "" && r.Method == http.MethodPost:
		s.writeRecord(w, r, name, "")
	case id != "" && readMethod(r):
		s.getRecord(w, r, name, id)
	case id != "" && r.Method == http.MethodPut:
		s.writeRecord(w, r, name, id)
	case id != "" && r.Method == http.MethodDelete:
		s.deleteRecord(w, r, name, id)
	default:
		s.notAllowed(w, r, Error{
			Error: "GET and POST on a collection; GET, PUT and DELETE on a record"})
	}
}

func (s *Server) listRecords(w http.ResponseWriter, r *http.Request, name string) {
	if err := s.may(r, auth.ActView, auth.DataResource(name)); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}
	// What the query asks is read as the pages listing reads it, and what
	// cannot be read is refused rather than answered as if it had not been
	// sent: offset=-5 and offset=abc were taken as 0, order=sideways sorted
	// ascending, and a where with no colon filtered nothing, so a client with
	// a typo in its query was answered everything and believed it had asked
	// for that.
	query := r.URL.Query()
	order := query.Get("order")
	if order != "" && order != "asc" && order != "desc" {
		writeError(w, http.StatusBadRequest, Error{
			Error: "order must be asc or desc", Detail: fmt.Sprintf("it is %q", order)})
		return
	}
	q := collection.Query{
		Equals:     map[string]any{},
		Contains:   map[string]string{},
		Sort:       query.Get("sort"),
		Descending: order == "desc",
	}
	// where=field:value, repeatable. A separate parameter per filter rather
	// than one expression, because an expression needs an evaluator and an
	// evaluator over a query string is the shape of every injection.
	for _, param := range []string{"where", "contains"} {
		for _, pair := range query[param] {
			k, v, ok := strings.Cut(pair, ":")
			if !ok || k == "" {
				writeError(w, http.StatusBadRequest, Error{
					Error:  param + " takes field:value",
					Detail: fmt.Sprintf("%s=%s names no field", param, pair),
					Fix:    "GET /api/v1/records/" + name + "?" + param + "=name:value"})
				return
			}
			if param == "where" {
				q.Equals[k] = typedValue(v)
			} else {
				q.Contains[k] = v
			}
		}
	}
	// Bounded by api.page.max, as the pages listing is, and by the most the
	// collection will answer, a limit above either refused rather than
	// clamped. Only the pages were bounded by the setting: set to 10, this
	// still answered a limit of a thousand, and fifty with none given.
	most := min(s.pageMax(), collection.MaxLimit)
	offset, limit, err := parsePaging(query, most)
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{
			Error: "bad paging", Detail: err.Error()})
		return
	}
	if query.Get("limit") == "" {
		// The collection's own page size when none is asked for, as before,
		// within the bound.
		limit = min(collection.DefaultLimit, most)
	}
	q.Limit, q.Offset = limit, offset

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
		s.notAllowed(w, r, Error{
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
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
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
	)
	lockErr := s.Store.WithRefLock(func() error {
		tree, err := s.Records.Tree()
		if err != nil {
			return err
		}
		if id != "" {
			existing, gerr := collection.Get(s.Store, tree, name, id)
			ifMatch := r.Header.Get("If-Match")
			if gerr == nil {
				if ifMatch == "" {
					status, conflict = http.StatusPreconditionRequired, &Error{
						Error: "If-Match is required",
						Detail: "a write without a validator overwrites " +
							"whatever is there now, including somebody " +
							"else's edit made since you read it",
						Fix: "GET the record, then PUT with If-Match set to its ETag",
					}
					return nil
				}
				if !matches(ifMatch, quote(recordETag(existing))) {
					status, conflict = http.StatusPreconditionFailed, &Error{
						Error: "the record has changed since you read it",
					}
					return nil
				}
			} else if ifMatch != "" && ifMatch != "*" {
				status, conflict = http.StatusPreconditionFailed, &Error{
					Error: "no such record, so nothing matches that validator",
					Fix:   "POST to the collection to create one",
				}
				return nil
			}
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
				Fix:    s.typeFixFor(func(st *schema.Store) string { return st.Collections[name] }),
			})
			return
		}
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the write failed", Detail: lockErr.Error()})
		return
	}
	if s.OnWrite != nil {
		s.OnWrite(who, name+"/"+out.ID, "")
	}
	w.Header().Set("ETag", quote(recordETag(&out)))
	code := http.StatusOK
	if id == "" {
		code = http.StatusCreated
		w.Header().Set("Location", "/api/v1/records/"+name+"/"+out.ID)
	}
	writeJSON(w, code, out)
}

func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request, name, id string) {
	if !s.Records.Writable {
		s.notAllowed(w, r, Error{
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
	var missing bool
	lockErr := s.Store.WithRefLock(func() error {
		tree, err := s.Records.Tree()
		if err != nil {
			return err
		}
		next, err := collection.Delete(s.Store, tree, name, id)
		if err != nil {
			missing = true
			return nil
		}
		return s.Records.Commit(next, "api: delete from "+name, who)
	})
	if missing {
		writeError(w, http.StatusNotFound, Error{Error: "no such record"})
		return
	}
	if lockErr != nil {
		writeError(w, http.StatusInternalServerError, Error{
			Error: "the delete failed", Detail: lockErr.Error()})
		return
	}
	// The same hook the write path calls, "so the audit trail does not have a
	// hole shaped like the API" — its own words. It had one anyway, shaped
	// like this half of it: writing a record was recorded and deleting one was
	// not, so a token-holding integration could empty a collection and the log
	// would show only the writes that created it.
	if s.OnWrite != nil {
		s.OnWrite(who, name+"/"+id, "")
	}
	w.WriteHeader(http.StatusNoContent)
}

// recordETag is a validator derived from the record's content.
//
// Its updated timestamp and id together: the store does not hand back the
// blob's object id from Put, and hashing the fields here would be a second
// definition of identity that could drift from the store's. Two writes in the
// same second to the same record produce the same validator, which is a real
// limitation and is bounded by the fact that a write in between changes the
// timestamp for any client that read first.
func recordETag(r *collection.Record) string {
	return fmt.Sprintf("%s-%d", r.ID, r.Updated)
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
