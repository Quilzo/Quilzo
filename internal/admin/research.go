// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/research"
)

// Research projects: the question, the plan and whether it was registered
// before the data was seen, the computations, and the report with every
// number linked to the computation that produced it and every citation to
// a work an index returned. What the check finds is shown beside it, so a
// number nobody can trace is visible where it sits. Changing a project is
// the command line's and an agent's (quilzo research, research_* over
// MCP); this screen is for reading it and showing somebody.

// Research is what the screens need.
type Research struct {
	List func() ([]research.Project, error)
	// Load is a project, its computations, newest first, and what its
	// check finds.
	Load func(name string) (research.Project, []research.Run, []research.Finding, error)
}

func (s *Server) handleResearch(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	data := map[string]any{"Nav": "research", "Title": "Research", "Principal": p}
	if s.Research == nil || s.Research.List == nil || s.Research.Load == nil {
		data["Unavailable"] = "This build was started without research projects."
		s.render(w, r, "research.html", data)
		return
	}
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/research"), "/")
	if name == "" {
		all, err := s.Research.List()
		if err != nil {
			data["Unavailable"] = "The projects could not be read: " + err.Error()
		}
		data["Projects"] = all
		s.render(w, r, "research.html", data)
		return
	}
	if !research.ValidName(name) {
		http.NotFound(w, r)
		return
	}
	proj, runs, findings, err := s.Research.Load(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	blocks, cited := research.Render(proj)
	refs := make([]string, len(cited))
	for i, c := range cited {
		refs[i] = research.Reference(c)
	}
	data["Title"] = proj.Name
	data["Project"], data["Runs"], data["Findings"] = proj, runs, findings
	if len(proj.Ideas) > 0 {
		data["Standings"] = proj.Standings(runs)
	}
	data["Blocks"], data["Cited"], data["References"] = blocks, cited, refs
	data["Problems"] = research.Problems(findings)
	s.render(w, r, "research_project.html", data)
}
