package admin

import (
	"encoding/json"
	"io"
	"net/http"
)

// Installing the admin as a desktop application, without shipping one.
//
// # The alternative to wrapping it
//
// The obvious way to put this interface in a window of its own is a native
// shell — Tauri or Electron around a webview. That buys a window, an icon and
// a place in the launcher, and it costs a second toolchain, a platform webview
// dependency, per-platform packaging, and a release artefact that has to be
// signed and updated separately from the binary it wraps.
//
// The browser already does the same job. A web manifest turns any origin into
// something the platform can install: its own window with no address bar, its
// own icon, its own entry in the launcher, and its own place in the task
// switcher. That is what a wrapper was for, delivered by software already on
// every machine.
//
// So there is no desktop build here, and there is not going to be one. What
// there is, is the file that lets the desktop do it.
//
// # What this deliberately does not turn on
//
// A manifest is data, not capability. It does not add script, does not widen
// the policy beyond one directive for the file itself, and does not make this
// origin able to do anything it could not do in a tab. An installed admin is
// the same server-rendered HTML in a window with different chrome — which is
// the point: the security argument does not change because the frame did.
//
// The scope is the whole origin and the start URL is the root, so an installed
// window is the admin rather than one screen of it. display is "standalone"
// rather than "fullscreen": this is a tool somebody uses beside other things,
// and taking their whole screen is a decision for them and not for this file.

// installManifest serves the admin's own web manifest.
//
// Authenticated like every other admin route. A manifest is not secret, but it
// carries the operator's branding, and an unauthenticated endpoint that answers
// with a company's name is a way to ask an unfamiliar host who it belongs to.
func (s *Server) installManifest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	name := s.Brand.Label()

	doc := map[string]any{
		"name":       name,
		"short_name": name,
		"start_url":  "/",
		"scope":      "/",
		"display":    "standalone",
		// The operator's accent when they set one, and the built-in otherwise.
		// Read through the same validated field the stylesheet uses rather
		// than from configuration directly, so there is one answer to what
		// this deployment's colour is.
		"theme_color": s.themeColour(),
		"description": "The administration interface for " + name + ".",
		// One icon, and it is the mark.
		//
		// This shipped with no icons array at all, on the argument that the
		// interface had no image assets and a generated fallback was more
		// honest than a request that 404s. That argument was about the absence
		// of a logo, not about icons, and it stopped being true the moment
		// there was one.
		//
		// "any maskable" rather than two entries: the mark is a filled shape
		// with its subject well inside the safe area, so a platform that crops
		// it to a circle takes a bite out of the rounded corners and nothing
		// else. Claiming maskable for a logo that would lose its subject is
		// how installed icons end up beheaded.
		"icons": []map[string]any{{
			"src":     "/icon.svg",
			"sizes":   "any",
			"type":    "image/svg+xml",
			"purpose": "any maskable",
		}},
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		http.Error(w, "manifest", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	// Not cached. The manifest carries the branding, and an operator who
	// changes it should see the change rather than wait for an expiry they
	// cannot see.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// icon serves the mark as a standalone SVG.
//
// Authenticated, like the manifest and for the same reason: it carries the
// operator's accent colour, and it is the file a browser tab shows. Cached
// briefly rather than not at all — a favicon is requested on every navigation,
// and the branding it encodes changes about as often as the branding does.
func (s *Server) icon(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, _ = io.WriteString(w, MarkSVG(s.themeColour()))
}

// themeColour is the installed window's colour.
//
// The brand's when one is configured and valid, and the built-in primary
// otherwise. Taken from Brand rather than from configuration so that a value
// the stylesheet refused cannot reach the platform either — those two must not
// be able to disagree about what colour this deployment is.
func (s *Server) themeColour() string {
	if s.Brand.Style() != "" {
		return s.Brand.Colour
	}
	// The built-in primary at tone 30, which is what the stylesheet resolves
	// --primary to in the light scheme.
	return "#00515f"
}
