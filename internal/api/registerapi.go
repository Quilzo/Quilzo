// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// The register's routes: its kinds and how many of each, one kind's
// records a page at a time, and one record with the hash it is stored
// under. The same three reads as `quilzo register` and the register's
// screens, asked about the register's area, and registered from this file,
// as a module's routes are (modules.go).

func init() {
	kinds := op("The kinds of record the security register holds", "registerKinds", nil, nil,
		map[string]any{"200": answer("Each kind, its schema and how many records of it there are, with the "+
			"register's head commit.", map[string]any{"type": "object"})})
	kind := op("One kind's records in the security register", "registerList", []any{
		param("kind", "path", "the kind, as registerKinds names it or as its collection is called", true, str),
		param("limit", "query", "how many to return", false, posInt),
		param("offset", "query", "how many to skip", false, nonNeg),
		param("filter", "query", "FIELD=VALUE: only the records whose field holds the value; repeat it for more", false, str)}, nil,
		map[string]any{"200": answer("A page of the kind's records, in the order of their identifiers.",
			map[string]any{"type": "object"})}, "400", "404")
	record := op("One record of the security register", "registerShow", []any{
		param("id", "path", "the record's identifier: 32 hexadecimal characters", true, str)}, nil,
		map[string]any{"200": answer("The record, its kind, the hash it is stored under, which is its ETag, and "+
			"what it names beside the register: each person's pseudonym and each digest of text or a file, with "+
			"whether it is held or erased.", map[string]any{"type": "object"})}, "404")
	history := op("The commits that changed one record of the security register", "registerHistory", []any{
		param("id", "path", "the record's identifier: 32 hexadecimal characters", true, str),
		param("limit", "query", "how many changes, newest first", false, posInt)}, nil,
		map[string]any{"200": answer("Each change: the commit, when, why, whose pseudonym and the object it left.",
			map[string]any{"type": "object"})}, "404")
	export := op("One kind of the security register as a table", "registerExport", []any{
		param("kind", "path", "the kind, as registerKinds names it", true, str),
		param("filter", "query", "FIELD=VALUE: only the records whose field holds the value; repeat it for more", false, str),
		param("top", "query", "only the N rated highest, for a kind with a rating (risks)", false, posInt),
		param("format", "query", "csv for the table as CSV; otherwise JSON", false, str)}, nil,
		map[string]any{"200": answer("A column per field of the kind's schema and a row per record, every cell safe "+
			"for a spreadsheet: one beginning with =, +, -, @, a tab or a carriage return is written after an "+
			"apostrophe. Free text is its digest.", map[string]any{"type": "object"})}, "400", "404")
	inventory := op("The data inventory of the security register", "registerInventory", nil, nil,
		map[string]any{"200": answer("For every kind, the fields that name a person, the free text and files kept "+
			"in the side store, their retention and who may read them; generated from the schemas.",
			map[string]any{"type": "object"})})
	registerRoutes(apiModule{
		module: "register",
		routes: []apiRoute{
			{path: "/api/v1/register/kinds", handle: (*Server).registerKinds,
				describe: map[string]map[string]any{"/api/v1/register/kinds": {"get": kinds}}},
			{path: "/api/v1/register/kinds/", handle: (*Server).registerList,
				describe: map[string]map[string]any{"/api/v1/register/kinds/{kind}": {"get": kind}}},
			{path: "/api/v1/register/records/", handle: (*Server).registerShow,
				describe: map[string]map[string]any{"/api/v1/register/records/{id}": {"get": record},
					"/api/v1/register/records/{id}/history": {"get": history}}},
			{path: "/api/v1/register/export/", handle: (*Server).registerExport,
				describe: map[string]map[string]any{"/api/v1/register/export/{kind}": {"get": export}}},
			{path: "/api/v1/register/inventory", handle: (*Server).registerInventory,
				describe: map[string]map[string]any{"/api/v1/register/inventory": {"get": inventory}}},
		},
	})
}

// registerReadable is the register, for a caller who may read it, or the
// refusal written.
func (s *Server) registerReadable(w http.ResponseWriter, r *http.Request) (*register.Register, bool) {
	if err := s.may(r, auth.ActView, register.Area); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted", Detail: err.Error(),
			Fix: "the register is the compliance area's: ask for a role there"})
		return nil, false
	}
	return register.Open(s.Store), true
}

func (s *Server) registerKinds(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.registerReadable(w, r)
	if !ok {
		return
	}
	census, err := reg.Census()
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kinds": census, "head": reg.Head()})
}

func (s *Server) registerList(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.registerReadable(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/register/kinds/")
	spec, found := register.SpecOf(name)
	if !found || strings.Contains(name, "/") {
		writeError(w, http.StatusNotFound, Error{Error: "the register has no such kind",
			Fix: "GET /api/v1/register/kinds names them"})
		return
	}
	offset, limit, err := parsePaging(r.URL.Query(), s.pageMax())
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{Error: err.Error()})
		return
	}
	filters, err := registerFilters(r.URL.Query()["filter"])
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{Error: err.Error()})
		return
	}
	entries, total, err := reg.Find(spec.Kind, filters, offset, limit)
	if errors.Is(err, register.ErrInvalid) {
		writeError(w, http.StatusBadRequest, Error{Error: err.Error()})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return
	}
	if entries == nil {
		entries = []register.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"kind": spec.Kind, "total": total, "offset": offset, "limit": limit,
		"filters": filters, "records": entries, "head": reg.Head()})
}

func (s *Server) registerShow(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.registerReadable(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/register/records/")
	if rest, ok := strings.CutSuffix(id, "/history"); ok {
		s.registerHistory(w, r, reg, rest)
		return
	}
	e, err := reg.Get(register.ID(id))
	if errors.Is(err, register.ErrNotFound) {
		writeError(w, http.StatusNotFound, Error{Error: "the register holds no such record",
			Fix: "GET /api/v1/register/kinds/{kind} lists a kind's records with their identifiers"})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return
	}
	w.Header().Set("ETag", `"`+e.Object+`"`)
	named := reg.Named(e.Record)
	if named == nil {
		named = []register.Named{}
	}
	writeJSON(w, http.StatusOK, struct {
		register.Entry
		Named []register.Named `json:"named"`
	}{e, named})
}
