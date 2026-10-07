// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"encoding/json"
	"net/http"

	"github.com/quilzo/quilzo/internal/aievidence"
)

// AIEvidence is the evidence an organisation using AI is asked for, from
// what its agents did. See internal/aievidence.
type AIEvidence struct {
	Inputs func(days int) (aievidence.Inputs, error)
}

func (s *Server) handleAIEvidence(w http.ResponseWriter, r *http.Request) {
	p, ok := s.frameworksReady(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "AI evidence", "Nav": "security", "Principal": p}
	if s.AIEvidence == nil || s.AIEvidence.Inputs == nil {
		data["Unavailable"] = "This build does not produce evidence for AI."
		s.render(w, r, "aievidence.html", data)
		return
	}
	days := 90
	switch r.URL.Query().Get("days") {
	case "30":
		days = 30
	case "365":
		days = 365
	}
	in, err := s.AIEvidence.Inputs(days)
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "aievidence.html", data)
		return
	}
	if r.URL.Path == "/security/ai-evidence/aibom.json" {
		body, err := json.MarshalIndent(aievidence.AIBOM(in), "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
		w.Header().Set("Content-Disposition", `attachment; filename="ai-bom.cdx.json"`)
		_, _ = w.Write(body)
		return
	}
	count := func(items []aievidence.Item) map[string]int {
		m := map[string]int{}
		for _, it := range items {
			m[it.Status]++
		}
		return m
	}
	duties, annex := aievidence.Deployer(in), aievidence.Annex(in)
	data["Days"], data["Duties"], data["Annex"] = days, duties, annex
	data["DutyCounts"], data["AnnexCounts"] = count(duties), count(annex)
	s.render(w, r, "aievidence.html", data)
}
