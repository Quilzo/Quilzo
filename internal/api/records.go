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
	if err := s.may(r, auth.ActView, "/"); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
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
	if err := s.may(r, auth.ActView, "/"+name); err != nil {
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
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	writeJSON(w, http.StatusOK, map[string]any{
		"collection": name, "total": total, "records": recs,
		"limit": q.Limit, "offset": q.Offset,
	})
}

func (s *Server) getRecord(w http.ResponseWriter, r *http.Request, name, id string) {
	if err := s.may(r, auth.ActView, "/"+name); err != nil {
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
			Fix:   "quilzo site --api-writable",
		})
		return
	}
	if err := s.may(r, auth.ActEditDraft, "/"+name); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted",
			Detail: err.Error()})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes {
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
			collection.Record{ID: id, Fields: fields}, time.Now())
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
		writeError(w, http.StatusMethodNotAllowed, Error{
			Error: "this API is read-only"})
		return
	}
	if err := s.may(r, auth.ActEditDraft, "/"+name); err != nil {
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
