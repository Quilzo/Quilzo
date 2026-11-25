// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/sources"
)

// The sources of the security record, read, and a file brought in as
// evidence through the API: the same reads as `quilzo source` and the
// Sources screen, and the same import as `quilzo ingest`, asked of the
// policy as the caller and written through the evidence ingester, which
// records every write in the audit log.
//
// The import is also how a pipeline pushes. A job in GitHub Actions or
// GitLab CI exchanges its platform's identity token at /token/exchange,
// with a DPoP proof, for a token of minutes bound to a key the job made;
// it presents that token here as DPoP with a fresh proof. What its platform
// signed about it is on the token, and the file is filed only under a
// pipeline's source that names that repository and that workflow, graded
// "ci". The same token presented as a bearer is refused, and so is a
// pipeline's token that is not bound to a key.

func init() {
	object := map[string]any{"type": "object"}
	name := param("name", "path", "the source's machine name", true, str)
	importGet := op("How a file is brought in as evidence", "evidenceImportHow", nil, nil,
		map[string]any{"200": answer("The formats read, and how a pipeline pushes with no stored secret.", object)})
	importPost := op("Bring a file in as evidence, or push one from a pipeline", "evidenceImport", []any{
		param("format", "query", "how the file is read: csv, xlsx, json, ocsf, cyclonedx, spdx, sarif, csaf, openvex, dsse or osquery", true, str),
		param("source", "query", "the source its facts are filed under; for a pipeline, its source, found by its repository and workflow when not named", false, str),
		param("map", "query", "the confirmed column map a table is read with", false, str),
		param("repository", "query", "for a pipeline, the repository it pushes for, which must be the one its token names", false, str),
	}, map[string]any{"required": true, "description": "The file, as it is.",
		"content": map[string]any{"application/octet-stream": map[string]any{"schema": map[string]any{"type": "string", "format": "binary"}}}},
		map[string]any{"201": answer("What was sealed and written, with the grade it was given and the receipt.", object)},
		"400", "403", "404", "413", "422")
	registerRoutes(apiModule{
		module: "sources",
		routes: []apiRoute{
			{path: "/api/v1/sources", handle: (*Server).sourceList,
				describe: map[string]map[string]any{"/api/v1/sources": {"get": op(
					"The sources of the record, and how fresh each is", "sourceList", nil, nil,
					map[string]any{"200": answer("Each source, when it last reported, whether it is stale and the line "+
						"that says so, and a connector's last run.", object)})}}},
			{path: "/api/v1/sources/recipes", handle: (*Server).sourceRecipes,
				describe: map[string]map[string]any{"/api/v1/sources/recipes": {"get": op(
					"The recipes a connector's source runs", "sourceRecipes", nil, nil,
					map[string]any{"200": answer("Each recipe, what it reads, the least privilege it needs and how it "+
						"was verified.", object)})}}},
			{path: "/api/v1/sources/", handle: (*Server).sourceShow,
				describe: map[string]map[string]any{"/api/v1/sources/{name}": {"get": op(
					"One source, and how fresh it is", "sourceShow", []any{name}, nil,
					map[string]any{"200": answer("The source, how it stands and a connector's last run.", object)}, "404")}}},
			{path: "/api/v1/evidence/import", handle: (*Server).evidenceImportHow, post: (*Server).evidenceImport,
				proved: true,
				describe: map[string]map[string]any{"/api/v1/evidence/import": {"get": importGet, "post": importPost}}},
		},
	})
}

func (s *Server) sourcesReadable(w http.ResponseWriter, r *http.Request) (*sources.Sources, bool) {
	if err := s.may(r, auth.ActView, register.Area); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted", Detail: err.Error(),
			Fix: "sources are the register's, in the compliance area: ask for a role there"})
		return nil, false
	}
	return sources.Open(register.Open(s.Store)), true
}

func (s *Server) sourceList(w http.ResponseWriter, r *http.Request) {
	src, ok := s.sourcesReadable(w, r)
	if !ok {
		return
	}
	all, err := src.Standings(s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the sources could not be read", Detail: err.Error()})
		return
	}
	if all == nil {
		all = []sources.Standing{}
	}
	stale := 0
	for _, st := range all {
		if st.Stale {
			stale++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": all, "stale": stale, "total": len(all)})
}

func (s *Server) sourceRecipes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sourcesReadable(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recipes": sources.Recipes()})
}

func (s *Server) sourceShow(w http.ResponseWriter, r *http.Request) {
	src, ok := s.sourcesReadable(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/sources/")
	all, err := src.Standings(s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the sources could not be read", Detail: err.Error()})
		return
	}
	for _, st := range all {
		if st.Source.Name == name {
			writeJSON(w, http.StatusOK, map[string]any{"source": st})
			return
		}
	}
	writeError(w, http.StatusNotFound, Error{Error: "no source has that name", Fix: "GET /api/v1/sources lists them"})
}

func (s *Server) evidenceImportHow(w http.ResponseWriter, r *http.Request) {
	if err := s.may(r, auth.ActView, register.Area); err != nil {
		writeError(w, http.StatusForbidden, Error{Error: "not permitted", Detail: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"formats": evidence.Formats(),
		"import":  "POST the file here with ?format=, and ?source= and ?map= as quilzo ingest takes them",
		"push": "from a pipeline: exchange the job's identity token at /token/exchange with a DPoP proof, " +
			"then POST the file here with Authorization: DPoP and a fresh proof; quilzo evidence push does both",
	})
}

// evidenceImport brings a file in: as a pipeline's push for a token bound
// to a key that carries its job, and otherwise as `quilzo ingest` does.
func (s *Server) evidenceImport(w http.ResponseWriter, r *http.Request) {
	tok := tokenFrom(r)
	if tok == nil {
		writeError(w, http.StatusUnauthorized, Error{Error: "not authenticated"})
		return
	}
	if evidence.Recorder == nil {
		writeError(w, http.StatusServiceUnavailable, Error{Error: "this server writes nothing to the register",
			Detail: "it was started without its audit log wired to the register", Fix: "use quilzo ingest"})
		return
	}
	q := r.URL.Query()
	format, ok := evidence.FormatNamed(q.Get("format"))
	if !ok {
		writeError(w, http.StatusBadRequest, Error{Error: "format names how the file is read",
			Detail: "the formats are those GET /api/v1/evidence/import lists"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, evidence.MaxFile))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, Error{Error: fmt.Sprintf("a file is at most %d bytes", evidence.MaxFile)})
		return
	}
	reg := register.Open(s.Store)
	evidence.Recorder(reg)
	g := evidence.New(reg)
	may := func(act auth.Action, resource string) error { return s.may(r, act, resource) }
	var res evidence.Result
	switch {
	case len(tok.Workload) > 0 && tok.Key == "":
		writeError(w, http.StatusUnauthorized, Error{Error: "a pipeline pushes with a token bound to a key it holds",
			Fix: "exchange the job's identity token at /token/exchange with a DPoP proof, as quilzo evidence push does"})
		return
	case len(tok.Workload) > 0:
		job := sources.WorkloadOf(tok.Workload)
		if want := q.Get("repository"); want != "" && !strings.EqualFold(want, job.Repository) {
			writeError(w, http.StatusForbidden, Error{Error: "the job's token is for another repository",
				Detail: fmt.Sprintf("it ran in %s, and pushes for %s", plaintext.Clip(orNone(job.Repository), 120, "…"),
					plaintext.Clip(want, 120, "…"))})
			return
		}
		src, err := pipelineSource(reg, q.Get("source"), job)
		if err != nil {
			s.importFailed(w, err)
			return
		}
		by := register.Actor{Name: tok.Principal, Kind: audit.KindService, Verified: true, May: may}
		res, err = g.Push(by, "", evidence.Input{Format: format, Body: body}, src, job)
		if err != nil {
			s.importFailed(w, err)
			return
		}
	default:
		kind := audit.KindService
		if tok.Person() {
			kind = audit.KindHuman
		}
		by := register.Actor{Name: tok.Principal, Kind: kind, Verified: true, May: may}
		if kind == audit.KindHuman {
			if by.Subject, err = reg.SubjectFor(tok.Principal, "person"); err != nil {
				writeError(w, http.StatusInternalServerError, Error{Error: "the subject map cannot name the writer"})
				return
			}
		}
		in := evidence.Input{Format: format, Body: body, Source: q.Get("source")}
		if err := g.Prepare(&in, q.Get("map")); err != nil {
			s.importFailed(w, err)
			return
		}
		if res, err = g.Ingest(by, "", in); err != nil {
			s.importFailed(w, err)
			return
		}
	}
	b := res.Batch
	writeJSON(w, http.StatusCreated, map[string]any{"grade": b.Grade, "source": b.Source.Name, "raw": b.Digest,
		"facts": len(b.Facts), "written": len(res.Receipt.Written), "commit": res.Receipt.Commit,
		"receipt": res.Receipt.Digest, "notes": b.Notes})
}

// pipelineSource is the pipeline's source a push is filed under: the one
// named, or the one source whose repository and workflow are the job's.
func pipelineSource(reg *register.Register, name string, job evidence.Workload) (register.Source, error) {
	all := sources.Open(reg)
	if name != "" {
		src, _, err := all.Source(name)
		return src, err
	}
	var found []register.Source
	for offset := 0; ; {
		entries, total, err := reg.List(register.KindSource, offset, 200)
		if err != nil {
			return register.Source{}, err
		}
		for _, e := range entries {
			if src, ok := e.Record.(register.Source); ok && evidence.PushAllowed(src, job) == nil {
				found = append(found, src)
			}
		}
		offset += len(entries)
		if offset >= total || len(entries) == 0 {
			break
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return register.Source{}, fmt.Errorf("%w: no pipeline's source takes pushes from %s, workflow %s; a person "+
			"adds one with quilzo source add-pipeline", sources.ErrNotFound, orNone(job.Repository), orNone(job.Workflow))
	}
	return register.Source{}, fmt.Errorf("%w: more than one source takes pushes from %s; name one with ?source=",
		register.ErrInvalid, job.Repository)
}

func orNone(s string) string {
	if s == "" {
		return "a repository the token does not name"
	}
	return s
}

// importFailed answers a refused import with the status its error is.
func (s *Server) importFailed(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, register.ErrRefused), errors.Is(err, register.ErrModel), errors.Is(err, evidence.ErrNotTheirs):
		code = http.StatusForbidden
	case errors.Is(err, register.ErrNotFound), errors.Is(err, sources.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, evidence.ErrUnreadable), errors.Is(err, evidence.ErrNoMap), errors.Is(err, evidence.ErrUnpinned),
		errors.Is(err, register.ErrInvalid):
		code = http.StatusUnprocessableEntity
	}
	writeError(w, code, Error{Error: plaintext.Clip(err.Error(), 2000, "…")})
}
