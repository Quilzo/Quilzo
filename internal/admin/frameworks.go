// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/frameworks"
	"github.com/quilzo/quilzo/internal/posture"
)

// The posture, read against the frameworks somebody is asked about.
//
// Nothing here is a second set of checks. Every row comes from the same
// scan the Security screen shows, through the mappings in
// internal/frameworks, so the two cannot disagree. What this adds is the
// question a buyer, an auditor or a regulator asks: "and for FedRAMP?",
// "and for the AI Act?".

type frameworkRow struct {
	frameworks.Framework
	Failing, Passing, Unchecked int
}

func (s *Server) frameworksReady(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return p, false
	}
	if !s.can(w, r, p, auth.ActView, auth.AreaCompliance) {
		return p, false
	}
	return p, true
}

func (s *Server) handleFrameworks(w http.ResponseWriter, r *http.Request) {
	p, ok := s.frameworksReady(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "Frameworks", "Nav": "security", "Principal": p}
	if s.Posture == nil {
		data["Unavailable"] = "This build serves the admin without a posture " +
			"scanner, so nothing has been checked against any framework."
		s.render(w, r, "frameworks.html", data)
		return
	}
	rep := s.Posture()
	var rows []frameworkRow
	for _, f := range frameworks.Catalogue {
		row := frameworkRow{Framework: f}
		for _, st := range posture.ByFramework(rep, f.ID) {
			switch st.State {
			case "failing":
				row.Failing++
			case "passing":
				row.Passing++
			default:
				row.Unchecked++
			}
		}
		rows = append(rows, row)
	}
	data["Rows"] = rows
	data["NotChecked"] = rep.NotChecked
	s.render(w, r, "frameworks.html", data)
}

func (s *Server) handleFramework(w http.ResponseWriter, r *http.Request) {
	p, ok := s.frameworksReady(w, r)
	if !ok {
		return
	}
	f, found := frameworks.Get(strings.TrimPrefix(r.URL.Path, "/security/frameworks/"))
	if !found || s.Posture == nil {
		http.NotFound(w, r)
		return
	}
	view := posture.ByFramework(s.Posture(), f.ID)
	counts := map[string]int{}
	for _, st := range view {
		counts[st.State]++
	}
	s.render(w, r, "framework.html", map[string]any{"Title": f.Name,
		"Nav": "security", "Principal": p, "F": f, "View": view,
		"Failing": counts["failing"], "Passing": counts["passing"],
		"Unchecked": counts["not checked"]})
}
