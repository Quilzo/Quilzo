// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/controls"
	"github.com/quilzo/quilzo/internal/odp"
	"github.com/quilzo/quilzo/internal/oscal"
)

// How Quilzo implements each NIST control and who does the rest
// (internal/controls), for the administrator and the auditor: every
// statement, the customer's part, the rules that check it (each a link),
// the settings that hold it and the organisation's parameters; and the
// whole as an OSCAL component definition to download.

type controlFamily struct {
	Code  string
	Items []controls.Implementation
}

func (s *Server) handleControls(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	all := controls.All()
	want := r.URL.Query().Get("who")
	var fams []controlFamily
	for _, im := range all {
		if want != "" && string(im.Responsibility) != want {
			continue
		}
		code, _, _ := strings.Cut(im.Control, "-")
		if len(fams) == 0 || fams[len(fams)-1].Code != code {
			fams = append(fams, controlFamily{Code: code})
		}
		fams[len(fams)-1].Items = append(fams[len(fams)-1].Items, im)
	}
	n := controls.Count(all)
	s.render(w, r, "controls.html", map[string]any{"Title": "Controls", "Nav": "security", "Principal": p,
		"Families": fams, "Total": len(all), "Quilzo": n[controls.Quilzo], "Shared": n[controls.Shared],
		"Customer": n[controls.Customer], "Who": want, "Pledge": controls.Pledge, "PledgeURL": controls.PledgeURL})
}

// handleControlsComponent is the component definition, to download.
func (s *Server) handleControlsComponent(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.assuranceReader(w, r); !ok {
		return
	}
	var params []oscal.SetParameter
	if s.Parameters != nil && s.Settings != nil && s.Settings.Load != nil {
		if pol, err := odp.Load(s.Parameters.Path); err == nil {
			if cfg, err := s.Settings.Load(); err == nil {
				params = odp.SetParameters(pol, cfg)
			}
		}
	}
	cd, err := controls.ComponentDefinition(s.Version, params, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="quilzo.component-definition.json"`)
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(cd)
}

// handleControlsSSP is the draft system security plan, to download.
func (s *Server) handleControlsSSP(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.assuranceReader(w, r); !ok {
		return
	}
	impact := r.URL.Query().Get("impact")
	if s.DraftSSP == nil {
		http.Error(w, "this server cannot draft a security plan", http.StatusServiceUnavailable)
		return
	}
	body, err := s.DraftSSP(impact)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="system-security-plan.`+impact+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
