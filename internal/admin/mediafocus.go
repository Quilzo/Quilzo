// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
)

// Saying which part of a picture must survive a crop.
//
// # Nine choices, not a picker
//
// The obvious control is clicking the photograph where the face is. That is a
// coordinate from a pointer event, which is script, and the policy on this
// response is `script-src 'none'`.
//
// Nine radio buttons laid out as the picture is laid out is not a fallback for
// that. It is how somebody describes a photograph anyway — "the face is top
// left" — it is reachable from a keyboard without anybody having to think
// about it, and it is announced as a group of nine labelled choices rather
// than as an image with an invisible coordinate space over it. The command
// line takes two percentages for the case where none of the nine is the
// answer.
//
// # Why a name and not two numbers in the form
//
// The form carries "top-left" and the server turns that into a point. A form
// that posted two integers would be a form that can post any two integers, and
// this value ends up in a stylesheet — so the browser is given a closed set to
// choose from and the server never parses a number it did not write.

// spot is one of the nine, as the grid shows it.
type spot struct {
	Value string
	Label string
	// On is whether this is the file's current answer, so the radio can be
	// checked without the template comparing anything.
	On bool
}

// focusSpots are the nine, in reading order so the grid is laid out by the
// order it is written in and needs no positioning to be correct.
var focusSpots = []struct{ Value, Label string }{
	{"top-left", "Top left"}, {"top", "Top"}, {"top-right", "Top right"},
	{"left", "Left"}, {"centre", "Centre"}, {"right", "Right"},
	{"bottom-left", "Bottom left"}, {"bottom", "Bottom"},
	{"bottom-right", "Bottom right"},
}

// focusPoints is the point each name means.
//
// The same nine the command line offers. One table would be better than two
// and they are in different packages: cmd/quilzo cannot import from here and
// this cannot import from there. Held together by
// TestBothInterfacesOfferTheSameNinePlaces rather than by hoping.
var focusPoints = map[string]media.Focus{
	"top-left": {X: 0, Y: 0}, "top": {X: 50, Y: 0}, "top-right": {X: 100, Y: 0},
	"left": {X: 0, Y: 50}, "centre": {X: 50, Y: 50}, "right": {X: 100, Y: 50},
	"bottom-left": {X: 0, Y: 100}, "bottom": {X: 50, Y: 100},
	"bottom-right": {X: 100, Y: 100},
}

// spotsFor builds the grid for one file, with its current answer marked.
func spotsFor(f media.File) []spot {
	current := "centre"
	if f.Focus != nil {
		for name, p := range focusPoints {
			if p == *f.Focus && name != "center" {
				current = name
			}
		}
	}
	out := make([]spot, 0, len(focusSpots))
	for _, s := range focusSpots {
		out = append(out, spot{Value: s.Value, Label: s.Label, On: s.Value == current})
	}
	return out
}

// handleMediaFocus records where a picture is cropped from.
func (s *Server) handleMediaFocus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Media == nil || s.Media.Library == nil {
		http.Error(w, "no media library", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	lib, err := s.Media.Library()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, err := lib.Stat(strings.TrimSpace(r.FormValue("id")))
	if err != nil {
		http.Error(w, "no such file", http.StatusNotFound)
		return
	}
	if f.Kind != media.Image {
		// Refused rather than stored, the same as the command line: a focus
		// only means something where something crops, and one on a PDF is a
		// setting that will never do anything.
		s.render(w, r, "message.html", map[string]any{
			"Title": "Not recorded", "Principal": p, "Heading": "Not recorded",
			"Body": f.Name + " is not a picture, and a focal point is about " +
				"cropping one.",
		})
		return
	}

	if r.FormValue("clear") != "" {
		f.Focus = nil
	} else {
		point, known := focusPoints[r.FormValue("at")]
		if !known {
			// The form offered nine values and this is not one of them, so it
			// did not come from the form. Refused rather than defaulted: a
			// silent fallback to the centre would make a crafted post look
			// like it worked.
			http.Error(w, "not one of the nine places", http.StatusBadRequest)
			return
		}
		f.Focus = &point
	}

	_, body, err := lib.Get(f.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Rebuilt rather than edited, for the reason `media origin` gives: each
	// narrower copy is its own file at its own hash.
	f.Renditions = nil
	if err := lib.Put(f, body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit("media.focus", "/"+f.ID, map[string]string{
		"by": p.Name, "at": f.Focus.Position(),
	})
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// mediaSpots builds the grid for every file on the screen.
func mediaSpots(files []media.File) map[string][]spot {
	out := make(map[string][]spot, len(files))
	for _, f := range files {
		if f.Kind == media.Image {
			out[f.ID] = spotsFor(f)
		}
	}
	return out
}

// FocusPoints is the nine places this interface offers, for the test that
// holds it and the command line's list together.
//
// Exported for that reason alone. The two tables are in packages that cannot
// import each other, so the only thing that can compare them is a test in the
// package that can see both.
func FocusPoints() map[string]media.Focus {
	out := make(map[string]media.Focus, len(focusPoints))
	for k, v := range focusPoints {
		out[k] = v
	}
	return out
}
