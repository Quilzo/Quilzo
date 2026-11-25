// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/programme"
	"github.com/quilzo/quilzo/internal/register"
)

// The security programme's routes: the starters and the requirements they
// brought, the statement of applicability for a scope, the controls with
// how each stands and the runs of their tests explained, and the
// populations with their cross-checks. The same reads as `quilzo
// requirement`, `quilzo soa`, `quilzo control` and `quilzo population`,
// asked about the register's area, each module registered from this file.
//
// Every decision is made on the command line or by approving what waits;
// these routes read, as a module's routes do (modules.go).

func init() {
	object := map[string]any{"type": "object"}
	registerRoutes(apiModule{
		module: "requirement",
		routes: []apiRoute{
			{path: "/api/v1/requirements", handle: (*Server).programmeRequirements,
				describe: map[string]map[string]any{"/api/v1/requirements": {"get": op(
					"The requirements of the installed starters, in each framework's own order", "requirementList",
					[]any{param("framework", "query", "only this framework's requirements", false, str)}, nil,
					map[string]any{"200": answer("Each requirement, by the framework's identifier with a line in Quilzo's own words.", object)})}}},
			{path: "/api/v1/requirements/starters", handle: (*Server).programmeStarters,
				describe: map[string]map[string]any{"/api/v1/requirements/starters": {"get": op(
					"The frameworks there are starters for, and which are installed", "requirementStarters", nil, nil,
					map[string]any{"200": answer("Each starter, how many requirements and mappings it brings, and whether it is installed.", object)})}}},
		},
	})
	registerRoutes(apiModule{
		module: "soa",
		routes: []apiRoute{
			{path: "/api/v1/soa", handle: (*Server).programmeScopes,
				describe: map[string]map[string]any{"/api/v1/soa": {"get": op(
					"The scopes the programme is decided for", "soaScopes", nil, nil,
					map[string]any{"200": answer("Each scope with its approval.", object)})}}},
			{path: "/api/v1/soa/", handle: (*Server).programmeStatement,
				describe: map[string]map[string]any{"/api/v1/soa/{scope}": {"get": op(
					"The statement of applicability for a scope", "soaShow",
					[]any{param("scope", "path", "the scope's machine name", true, str)}, nil,
					map[string]any{"200": answer("Every requirement within the scope, decided or not, with the controls mapped to it "+
						"as evidence towards it.", object)}, "404")}}},
		},
	})
	registerRoutes(apiModule{
		module: "control",
		routes: []apiRoute{
			{path: "/api/v1/controls", handle: (*Server).programmeControls,
				describe: map[string]map[string]any{"/api/v1/controls": {"get": op(
					"The controls, each with how it stood at its newest run", "controlList", nil, nil,
					map[string]any{"200": answer("Each control with its standing, which moves on a run of its tests and nothing else.", object)})}}},
			{path: "/api/v1/controls/tests", handle: (*Server).programmeTests,
				describe: map[string]map[string]any{"/api/v1/controls/tests": {"get": op(
					"The approved control tests", "controlTests", nil, nil,
					map[string]any{"200": answer("Each approved test with its query's digest and its approval.", object)})}}},
			{path: "/api/v1/controls/runs/", handle: (*Server).programmeRun,
				describe: map[string]map[string]any{"/api/v1/controls/runs/{id}": {"get": op(
					"One run of a control test, with its explanation and its replay", "controlRun",
					[]any{param("id", "path", "the run's identifier: 32 hexadecimal characters", true, str)}, nil,
					map[string]any{"200": answer("The run as recorded, why it came out as it did in lines code wrote, and whether "+
						"doing it again from the commit it read gives the same run.", object)}, "404")}}},
		},
	})
	registerRoutes(apiModule{
		module: "population",
		routes: []apiRoute{
			{path: "/api/v1/populations", handle: (*Server).programmePopulations,
				describe: map[string]map[string]any{"/api/v1/populations": {"get": op(
					"The populations coverage is counted against", "populationList", nil, nil,
					map[string]any{"200": answer("Each population as last counted, with its cross-check and its labels.", object)})}}},
			{path: "/api/v1/populations/", handle: (*Server).programmePopulation,
				describe: map[string]map[string]any{"/api/v1/populations/{name}": {"get": op(
					"One population counted at the register's head", "populationShow",
					[]any{param("name", "path", "the population's machine name", true, str)}, nil,
					map[string]any{"200": answer("Its members' count, its cross-check's, and the disagreement as a number of its own.", object)},
					"404")}}},
		},
	})
}

// programmeReadable is the programme, for a caller who may read the
// register, or the refusal written.
func (s *Server) programmeReadable(w http.ResponseWriter, r *http.Request) (*programme.Programme, *register.View, bool) {
	reg, ok := s.registerReadable(w, r)
	if !ok {
		return nil, nil, false
	}
	v, err := reg.At("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
		return nil, nil, false
	}
	keep := &programme.FileKeeper{Dir: filepath.Join(s.Store.Root(), "programme"), NoWords: s.Store.Encrypted()}
	return &programme.Programme{Reg: reg, Keep: keep}, v, true
}

func (s *Server) programmeUnreadable(w http.ResponseWriter, err error) {
	if errors.Is(err, register.ErrNotFound) {
		writeError(w, http.StatusNotFound, Error{Error: err.Error()})
		return
	}
	writeError(w, http.StatusInternalServerError, Error{Error: "the register could not be read", Detail: err.Error()})
}

func (s *Server) programmeStarters(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.programmeReadable(w, r)
	if !ok {
		return
	}
	installed, err := programme.Installed(v)
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	type row struct {
		Framework, Name, Version, About, Level string
		Requirements, Mappings                 int
		Installed                              bool
	}
	var out []row
	for _, st := range programme.Starters() {
		_, in := installed[st.Framework]
		out = append(out, row{st.Framework, st.Name, st.Version, st.About, st.Level, len(st.Clauses), len(st.Crosswalk), in})
	}
	writeJSON(w, http.StatusOK, map[string]any{"starters": out, "head": v.Commit()})
}

func (s *Server) programmeRequirements(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.programmeReadable(w, r)
	if !ok {
		return
	}
	installed, err := programme.Installed(v)
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	want := r.URL.Query().Get("framework")
	out := []register.Entry{}
	err = v.Each(register.KindRequirement, func(e register.Entry, _ map[string]any) error {
		q := e.Record.(register.Requirement)
		if _, in := installed[q.Framework]; in && (want == "" || want == q.Framework) {
			out = append(out, e)
		}
		return nil
	})
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requirements": out, "head": v.Commit()})
}

func (s *Server) programmeScopes(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.programmeReadable(w, r)
	if !ok {
		return
	}
	out := []register.Entry{}
	if err := v.Each(register.KindScope, func(e register.Entry, _ map[string]any) error {
		out = append(out, e)
		return nil
	}); err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scopes": out, "head": v.Commit()})
}

func (s *Server) programmeStatement(w http.ResponseWriter, r *http.Request) {
	p, v, ok := s.programmeReadable(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/soa/")
	st, err := programme.StatementAt(v, p.Keep, name)
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) programmeControls(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.programmeReadable(w, r)
	if !ok {
		return
	}
	standing, err := programme.Standings(v)
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	type row struct {
		register.Entry
		Standing programme.Standing `json:"standing"`
	}
	out := []row{}
	if err := v.Each(register.KindControl, func(e register.Entry, _ map[string]any) error {
		out = append(out, row{Entry: e, Standing: standing[e.ID]})
		return nil
	}); err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Record.(register.Control).Ref < out[j].Record.(register.Control).Ref
	})
	writeJSON(w, http.StatusOK, map[string]any{"controls": out, "head": v.Commit()})
}

func (s *Server) programmeTests(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.programmeReadable(w, r)
	if !ok {
		return
	}
	out := []register.Entry{}
	if err := v.Each(register.KindControlTest, func(e register.Entry, _ map[string]any) error {
		out = append(out, e)
		return nil
	}); err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tests": out, "head": v.Commit()})
}

func (s *Server) programmeRun(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.programmeReadable(w, r)
	if !ok {
		return
	}
	id := register.ID(strings.TrimPrefix(r.URL.Path, "/api/v1/controls/runs/"))
	e, err := p.Reg.Get(id)
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	rec, isRun := e.Record.(register.TestRun)
	if !isRun || rec.Commit == "" {
		writeError(w, http.StatusNotFound, Error{Error: "the register holds no run of a control test with that identifier"})
		return
	}
	at, err := p.Reg.At(rec.Commit)
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	run, err := programme.Evaluate(at, rec.Test, rec.Ran.At())
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	run.Record = rec
	replay, err := p.Replay(id)
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	w.Header().Set("ETag", `"`+e.Object+`"`)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "run": rec, "explanation": programme.Explain(run), "replay": replay})
}

func (s *Server) programmePopulations(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.programmeReadable(w, r)
	if !ok {
		return
	}
	type row struct {
		register.Entry
		Labels []programme.Label `json:"labels"`
	}
	out := []row{}
	now := time.Now()
	if err := v.Each(register.KindPopulation, func(e register.Entry, _ map[string]any) error {
		out = append(out, row{Entry: e, Labels: programme.Labels(e.Record.(register.Population), now)})
		return nil
	}); err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"populations": out, "head": v.Commit()})
}

func (s *Server) programmePopulation(w http.ResponseWriter, r *http.Request) {
	_, v, ok := s.programmeReadable(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/populations/")
	id, err := register.DeriveID(register.KindPopulation, register.Local, name)
	if err != nil || strings.Contains(name, "/") {
		writeError(w, http.StatusNotFound, Error{Error: "there is no such population", Fix: "GET /api/v1/populations names them"})
		return
	}
	c, err := programme.CountAt(v, id, time.Now())
	if err != nil {
		s.programmeUnreadable(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": c, "unexplained": c.Unexplained(), "said": programme.Disagreement(c)})
}
