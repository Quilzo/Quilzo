// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/register"
)

// The register's other reads: a record's history, a kind as a table or as
// CSV, the top risks, and the data inventory. The same as `quilzo register
// history`, `export` and `inventory` and the register's screens, asked
// about the register's area, and registered with the register's routes in
// registerapi.go. Nothing here writes: an erasure is a person's decision,
// taken on the command line and the admin, and the API's module routes
// read.

// registerFilters reads each filter=FIELD=VALUE of a query.
func registerFilters(raw []string) ([]register.Filter, error) {
	out := []register.Filter{}
	for _, s := range raw {
		f, err := register.ParseFilter(s)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// registerHistory answers /api/v1/register/records/{id}/history.
func (s *Server) registerHistory(w http.ResponseWriter, r *http.Request, reg *register.Register, id string) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, Error{Error: "limit is a whole number, 1 or more"})
			return
		}
		limit = n
	}
	changes, err := reg.History(register.ID(id), limit)
	if errors.Is(err, register.ErrNotFound) {
		writeError(w, http.StatusNotFound, Error{Error: "the register holds no such record",
			Fix: "GET /api/v1/register/kinds/{kind} lists a kind's records with their identifiers"})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "changes": changes, "head": reg.Head()})
}

// registerExport answers /api/v1/register/export/{kind}: the kind as
// columns and rows in JSON, or as CSV with format=csv.
func (s *Server) registerExport(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.registerReadable(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/register/export/")
	spec, found := register.SpecOf(name)
	if !found || strings.Contains(name, "/") {
		writeError(w, http.StatusNotFound, Error{Error: "the register has no such kind",
			Fix: "GET /api/v1/register/kinds names them"})
		return
	}
	q := r.URL.Query()
	filters, err := registerFilters(q["filter"])
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{Error: err.Error()})
		return
	}
	top := 0
	if raw := q.Get("top"); raw != "" {
		if top, err = strconv.Atoi(raw); err != nil || top < 1 {
			writeError(w, http.StatusBadRequest, Error{Error: "top is a whole number of records, 1 or more"})
			return
		}
	}
	entries, _, err := reg.Find(spec.Kind, filters, 0, 0)
	if err == nil && top > 0 {
		if _, rated := register.Rating(spec.New().(register.Record)); !rated {
			err = fmt.Errorf("%w: a %s has no rating to put the highest first by", register.ErrInvalid,
				strings.ToLower(string(spec.Kind)))
		} else {
			entries, err = register.Top(entries, top)
		}
	}
	if errors.Is(err, register.ErrInvalid) {
		writeError(w, http.StatusBadRequest, Error{Error: err.Error()})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return
	}
	if q.Get("format") == "csv" {
		var b bytes.Buffer
		if err := register.WriteCSV(&b, spec, entries); err != nil {
			writeError(w, http.StatusInternalServerError, Error{Error: "the export could not be written", Detail: err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="register-`+
			strings.TrimPrefix(spec.Collection, register.Prefix)+`.csv"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(b.Bytes())
		}
		return
	}
	cols, rows, err := register.ExportRows(spec, entries)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the export could not be written", Detail: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kind": spec.Kind, "filters": filters, "columns": cols, "rows": rows,
		"head": reg.Head()})
}

// registerInventory answers /api/v1/register/inventory.
func (s *Server) registerInventory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.registerReadable(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, register.Inventory())
}
