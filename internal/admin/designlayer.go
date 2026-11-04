// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/theme"
)

// The style layer, in the browser.
//
// The same file `quilzo theme layer` writes, held to the same rule by the
// same check before anything is saved: every colour a token, url() only to
// this site's own files, no @import, no !important. A textarea rather than an
// upload, because a layer is short text somebody edits, and a form field is
// the one editor this admin can offer without script.
//
// Publisher rather than author, as installing a design is: a layer is served
// on every page at once, including pages this person may not edit.

// designLayerData fills in what the Design screen shows about the layer.
func (s *Server) designLayerData(data map[string]any, th *theme.Theme) {
	if s.DesignSet == nil || s.DesignSet.Layer == nil {
		return
	}
	data["CanLayer"] = s.DesignSet.SaveLayer != nil
	data["LayerMax"] = theme.MaxLayer / 1024
	layer, err := s.DesignSet.Layer()
	if err != nil {
		data["LayerError"] = err.Error()
		return
	}
	data["Layer"] = layer
	if layer == "" {
		return
	}
	findings := theme.CheckLayer(layer, th)
	var refused, advice []theme.Finding
	for _, f := range findings {
		if f.Blocking {
			refused = append(refused, f)
		} else {
			advice = append(advice, f)
		}
	}
	data["LayerRefused"], data["LayerAdvice"] = refused, advice
	data["LayerBytes"] = len(layer)
}

// handleDesignLayer saves the style layer, or takes it away.
func (s *Server) handleDesignLayer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return
	}
	if s.DesignSet == nil || s.DesignSet.SaveLayer == nil || s.DesignSet.Tokens == nil {
		s.designRedirect(w, r, "", "this build cannot write the style layer")
		return
	}
	// Three times the bound, because a form sends a brace, a colon, a
	// semicolon and a line break as three bytes each, and CSS is mostly
	// those. At the bound alone a sixty-kibibyte layer the terminal takes was
	// refused here as too large. The layer itself is held to MaxLayer by
	// CheckLayer below, so this bounds what is read, not what is allowed.
	r.Body = http.MaxBytesReader(w, r.Body, 3*theme.MaxLayer+16<<10)
	if err := r.ParseForm(); err != nil {
		s.designRedirect(w, r, "", fmt.Sprintf("the layer is too large: at most %d KiB", theme.MaxLayer/1024))
		return
	}
	if r.FormValue("remove") != "" {
		if err := s.DesignSet.SaveLayer(""); err != nil {
			s.designRedirect(w, r, "", err.Error())
			return
		}
		s.auditPub(p, "theme.layer.unset", "/", map[string]string{"layer": theme.LayerFile})
		s.designRedirect(w, r, "The style layer is gone; the generated stylesheet is served alone from the site's next start", "")
		return
	}
	// A browser sends a textarea's line breaks as CRLF. Kept as the person
	// typed it otherwise: what is checked is what is saved.
	css := strings.ReplaceAll(r.FormValue("layer"), "\r\n", "\n")
	if strings.TrimSpace(css) == "" {
		s.designRedirect(w, r, "", "the layer is empty; to take it away, use the button for that")
		return
	}
	overrides, err := s.DesignSet.Tokens()
	if err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	th, _ := theme.New(overrides, s.siteFamilies())
	for _, f := range theme.CheckLayer(css, th) {
		if f.Blocking {
			s.designRedirect(w, r, "", "not saved, because it would not be served: "+f.Detail)
			return
		}
	}
	if err := s.DesignSet.SaveLayer(css); err != nil {
		s.designRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "theme.layer.set", "/", map[string]string{"bytes": fmt.Sprint(len(css))})
	s.designRedirect(w, r, "The style layer is saved; the site serves it from its next start", "")
}
