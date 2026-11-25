// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/register"
)

// The evidence routes: the formats a file is read in, the files brought in
// as evidence a page at a time, one of them with what was read from it and
// whether it checks, and a check of them all. The same reads as `quilzo
// evidence` and the Evidence screens, asked about the register's area, and
// registered from this file, as a module's routes are (modules.go).
//
// A file is brought in on the command line, on the Import screen or by an
// agent's evidence_ingest; a module's routes here read.

func init() {
	object := map[string]any{"type": "object"}
	registerRoutes(apiModule{
		module: "evidence",
		routes: []apiRoute{
			{path: "/api/v1/evidence/formats", handle: (*Server).evidenceFormats,
				describe: map[string]map[string]any{"/api/v1/evidence/formats": {"get": op(
					"The formats a file is read in as evidence", "evidenceFormats", nil, nil,
					map[string]any{"200": answer("Each format, and what files it reads.", object)})}}},
			{path: "/api/v1/evidence/files", handle: (*Server).evidenceFiles,
				describe: map[string]map[string]any{"/api/v1/evidence/files": {"get": op(
					"The files brought in as evidence", "evidenceFiles", []any{
						param("limit", "query", "how many to return", false, posInt),
						param("offset", "query", "how many to skip", false, nonNeg)}, nil,
					map[string]any{"200": answer("Each file's seal record, its grade and what it yielded, and whether its "+
						"raw bytes are still kept.", object)}, "400")}}},
			{path: "/api/v1/evidence/files/", handle: (*Server).evidenceFile,
				describe: map[string]map[string]any{"/api/v1/evidence/files/{id}": {"get": op(
					"One file brought in as evidence, and whether it checks", "evidenceFile",
					[]any{param("id", "path", "the file's seal record identifier, or its digest", true, str)}, nil,
					map[string]any{"200": answer("The file, the check of its seal, of the list of what was read from it "+
						"and of every record that list names, and the list itself.", object)}, "404")}}},
			{path: "/api/v1/evidence/verify", handle: (*Server).evidenceVerify,
				describe: map[string]map[string]any{"/api/v1/evidence/verify": {"get": op(
					"Check every file brought in as evidence", "evidenceVerify", nil, nil,
					map[string]any{"200": answer("A check of each file: its seal, the list of what was read from it, and "+
						"every record it names, whether or not its raw bytes are still kept.", object)})}}},
		},
	})
}

// evidenceReadable is the ingester of this server's register, for a caller
// who may read it, or the refusal written.
func (s *Server) evidenceReadable(w http.ResponseWriter, r *http.Request) (*evidence.Ingester, bool) {
	if err := s.may(r, auth.ActView, register.Area); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted", Detail: err.Error(),
			Fix: "evidence is the register's, in the compliance area: ask for a role there"})
		return nil, false
	}
	return evidence.New(register.Open(s.Store)), true
}

func (s *Server) evidenceFormats(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.evidenceReadable(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"formats": evidence.Formats()})
}

func (s *Server) evidenceFiles(w http.ResponseWriter, r *http.Request) {
	g, ok := s.evidenceReadable(w, r)
	if !ok {
		return
	}
	offset, limit, err := parsePaging(r.URL.Query(), s.pageMax())
	if err != nil {
		writeError(w, http.StatusBadRequest, Error{Error: err.Error()})
		return
	}
	files, total, err := g.Files(offset, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the evidence could not be read", Detail: err.Error()})
		return
	}
	if files == nil {
		files = []evidence.File{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files, "total": total, "offset": offset, "limit": limit})
}

func (s *Server) evidenceFile(w http.ResponseWriter, r *http.Request) {
	g, ok := s.evidenceReadable(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/evidence/files/")
	f, err := g.FileNamed(name)
	if errors.Is(err, register.ErrNotFound) || strings.Contains(name, "/") {
		writeError(w, http.StatusNotFound, Error{Error: "no file brought in as evidence has that identifier or digest",
			Fix: "GET /api/v1/evidence/files lists them"})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the evidence could not be read", Detail: err.Error()})
		return
	}
	checks, err := g.Verify(string(f.ID))
	if err != nil || len(checks) != 1 {
		writeError(w, http.StatusInternalServerError, Error{Error: "the file could not be checked"})
		return
	}
	read := []string{}
	if list, err := g.Raw.Yield(f.Record.Yield); err == nil {
		read = strings.Split(strings.TrimRight(string(list), "\n"), "\n")
	}
	writeJSON(w, http.StatusOK, map[string]any{"file": f, "check": checks[0], "ok": checks[0].OK(), "read": read})
}

func (s *Server) evidenceVerify(w http.ResponseWriter, r *http.Request) {
	g, ok := s.evidenceReadable(w, r)
	if !ok {
		return
	}
	checks, err := g.Verify()
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the evidence could not be checked", Detail: err.Error()})
		return
	}
	bad := 0
	for _, c := range checks {
		if !c.OK() {
			bad++
		}
	}
	if checks == nil {
		checks = []evidence.Check{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": checks, "files": len(checks), "problems": bad})
}
