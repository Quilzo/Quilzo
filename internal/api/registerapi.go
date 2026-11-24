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
		param("offset", "query", "how many to skip", false, nonNeg)}, nil,
		map[string]any{"200": answer("A page of the kind's records, in the order of their identifiers.",
			map[string]any{"type": "object"})}, "400", "404")
	record := op("One record of the security register", "registerShow", []any{
		param("id", "path", "the record's identifier: 32 hexadecimal characters", true, str)}, nil,
		map[string]any{"200": answer("The record, its kind, and the hash it is stored under, which is its ETag.",
			map[string]any{"type": "object"})}, "404")
	registerRoutes(apiModule{
		module: "register",
		routes: []apiRoute{
			{path: "/api/v1/register/kinds", handle: (*Server).registerKinds,
				describe: map[string]map[string]any{"/api/v1/register/kinds": {"get": kinds}}},
			{path: "/api/v1/register/kinds/", handle: (*Server).registerList,
				describe: map[string]map[string]any{"/api/v1/register/kinds/{kind}": {"get": kind}}},
			{path: "/api/v1/register/records/", handle: (*Server).registerShow,
				describe: map[string]map[string]any{"/api/v1/register/records/{id}": {"get": record}}},
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
	entries, total, err := reg.List(spec.Kind, offset, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return
	}
	if entries == nil {
		entries = []register.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"kind": spec.Kind, "total": total, "offset": offset, "limit": limit,
		"records": entries, "head": reg.Head()})
}

func (s *Server) registerShow(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.registerReadable(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/register/records/")
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
	writeJSON(w, http.StatusOK, e)
}
