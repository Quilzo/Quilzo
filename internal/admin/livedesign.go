// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import "github.com/quilzo/quilzo/internal/render"

// The design, replaced while the server runs.
//
// Layouts and SiteCSS were read once, when the server started, and nothing
// changed them. So a typeface added to templates/fonts/ was in the site's
// directory and not in the admin: the Design screen said the site "does not
// serve a font by that name" about the font it had just been given, the
// preview drew pages without it, and the cure was restarting the admin. A
// layout edited by hand had the same wait.
//
// The host reads the design again when the directory changes and hands it
// over here. It is swapped whole, behind an atomic pointer, so a request
// renders against the design as it was or as it is and never half of each:
// a preview whose layouts were new and whose stylesheet was old would be a
// page nobody is served.

// liveDesign is one reading of the design.
type liveDesign struct {
	layouts render.Layouts
	css     string
}

// SetDesign replaces the layouts and the stylesheet the preview, the
// accessibility check and the permanent-web bundle render with.
//
// Safe to call while requests are being served; a request already rendering
// finishes with the design it started with.
func (s *Server) SetDesign(layouts render.Layouts, css string) {
	s.live.Store(&liveDesign{layouts: layouts, css: css})
}

// layouts is the design's layouts as they are now.
func (s *Server) layouts() render.Layouts {
	if d := s.live.Load(); d != nil {
		return d.layouts
	}
	return s.Layouts
}

// siteStylesheet is the site's stylesheet as it is now, for the preview.
func (s *Server) siteStylesheet() string {
	if d := s.live.Load(); d != nil {
		return d.css
	}
	return s.SiteCSS
}
