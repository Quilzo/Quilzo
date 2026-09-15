// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

// Cropping a picture in an interface that has no canvas.
//
// # What the shape of this is, and why
//
// The policy on every response here is script-free, so there is no drag, no
// handles and no marching ants. What there is instead: named ratios as radio
// buttons, four numbers for the case where somebody knows exactly, and — the
// part that makes it usable — a rendered preview of the result before anything
// is stored.
//
// The preview is why this is a screen rather than a row of controls on the
// media list. Cropping blind is cropping three times, and a preview costs one
// page load in an interface where every operation already costs one.
//
// # Why the preview is stateless
//
// It would be easy to derive the bytes, hold them, and hand the next request a
// token. That is a cache with an eviction policy, a lifetime and a way to be
// filled up by somebody reloading a page, in exchange for saving a resample
// nobody is waiting on.
//
// So the recipe travels in the address instead. The form posts, the handler
// redirects to itself with the recipe in the query, and the picture on that
// page is an <img> pointing at a second handler that derives from the same
// query and serves the bytes. Reloading re-derives; sharing the URL shares the
// crop; the back button works. Bounded at medialib.PreviewWidth, because
// resampling six million pixels to answer "is the face still in frame" is work
// nobody asked for.
//
// # Why keeping is a separate post
//
// The preview is a GET and has to stay one: a request that stores a file
// because somebody reloaded a page is a request that fills a library. So the
// screen shows the result and a button, and only the button writes.

// aspectChoice is one ratio on the form.
type aspectChoice struct {
	Value string
	Label string
	On    bool
}

// aspects are the shapes offered, in the order somebody reads them.
//
// Named rather than typed, because a ratio is the one part of a crop people
// know the answer to before they open the screen — "make it a banner" is 16:9
// and nobody needs to work that out. The exact box is behind a disclosure for
// when the answer is not one of these.
var aspects = []aspectChoice{
	{Value: "16:9", Label: "16:9 — a banner"},
	{Value: "3:2", Label: "3:2 — a photograph"},
	{Value: "4:3", Label: "4:3 — a screen"},
	{Value: "1:1", Label: "1:1 — a square"},
	{Value: "2:3", Label: "2:3 — upright"},
	{Value: "9:16", Label: "9:16 — a phone"},
}

// editFromQuery reads a recipe out of a request, from the query or the form.
//
// One reader for both, because the preview arrives as a query string and the
// form arrives as a post, and two readers that disagreed would preview one
// crop and store another.
func editFromQuery(get func(string) string) (media.Edit, error) {
	e := media.Edit{
		Aspect: strings.TrimSpace(get("aspect")),
		Flip:   strings.TrimSpace(get("flip")),
		Grey:   get("grey") != "",
	}
	if t := strings.TrimSpace(get("turn")); t != "" {
		n, err := strconv.Atoi(t)
		if err != nil {
			return e, err
		}
		e.Turn = n
	}
	// The exact box, when all four are given. Partly filled is not a box, and
	// treating it as one would crop somewhere nobody chose.
	x, y := strings.TrimSpace(get("x")), strings.TrimSpace(get("y"))
	bw, bh := strings.TrimSpace(get("w")), strings.TrimSpace(get("h"))
	if x != "" || y != "" || bw != "" || bh != "" {
		if x == "" || y == "" || bw == "" || bh == "" {
			return e, errPartialBox
		}
		b := &media.Box{}
		for _, f := range []struct {
			raw string
			to  *float64
		}{{x, &b.X}, {y, &b.Y}, {bw, &b.W}, {bh, &b.H}} {
			v, err := strconv.ParseFloat(f.raw, 64)
			if err != nil {
				return e, errBadBox
			}
			*f.to = v
		}
		e.Crop = b
		// A box and a ratio are two ways to say where to cut. The box is the
		// more specific answer and the one somebody typed on purpose, so it
		// wins rather than the pair being refused — a refusal here would mean
		// remembering to clear a radio button before the numbers work.
		e.Aspect = ""
	}
	return e, nil
}

var (
	errPartialBox = errBox("a box needs all four numbers: across, down, " +
		"width and height, as percentages")
	errBadBox = errBox("those are not four numbers")
)

type errBox string

func (e errBox) Error() string { return string(e) }

// editQuery writes a recipe back into a query string.
func editQuery(id string, e media.Edit) string {
	// Escaped, every value. These come out of a form, go into an address, and
	// come back through a handler that derives from them; a ratio somebody
	// typed is not a thing to concatenate into a URL unexamined.
	v := "id=" + url.QueryEscape(id)
	if e.Aspect != "" {
		v += "&aspect=" + url.QueryEscape(e.Aspect)
	}
	if e.Crop != nil {
		v += "&x=" + trimNum(e.Crop.X) + "&y=" + trimNum(e.Crop.Y) +
			"&w=" + trimNum(e.Crop.W) + "&h=" + trimNum(e.Crop.H)
	}
	if e.Turn != 0 {
		v += "&turn=" + strconv.Itoa(e.Turn)
	}
	if e.Flip != "" {
		v += "&flip=" + url.QueryEscape(e.Flip)
	}
	if e.Grey {
		v += "&grey=1"
	}
	return v
}

func trimNum(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// handleMediaEdit shows the form, and stores when asked to.
func (s *Server) handleMediaEdit(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Media == nil || s.Media.Library == nil {
		s.unwired(w, r, p, "Media", "the asset library")
		return
	}
	lib, err := s.Media.Library()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	id := strings.TrimSpace(r.FormValue("id"))
	parent, perr := lib.Stat(id)
	if perr != nil {
		s.render(w, r, "message.html", map[string]any{
			"Title": "No such picture", "Principal": p,
			"Heading": "No such picture",
			"Body":    "There is nothing in the library with that address.",
		})
		return
	}

	e, eerr := editFromQuery(r.FormValue)
	problem := ""
	if eerr != nil {
		problem = eerr.Error()
	}

	if r.Method == http.MethodPost && r.FormValue("keep") != "" && problem == "" {
		opts := media.Options{}
		if s.Media.Options != nil {
			opts = s.Media.Options()
		}
		f, err := lib.Edit(id, e, opts, strings.TrimSpace(r.FormValue("alt")),
			p.Name)
		if err != nil {
			problem = err.Error()
		} else {
			s.audit("media.edit", "/", map[string]string{
				"from": medialib.ShortID(id), "id": medialib.ShortID(f.ID),
				"did": e.Describe(),
			})
			http.Redirect(w, r, "/media?m="+url.QueryEscape(
				f.Name+" was made from "+parent.Name+
					". The original is untouched."), http.StatusSeeOther)
			return
		}
	}

	// A post that is not "keep" is somebody asking to see it: redirect so the
	// recipe is in the address and the picture below is a plain <img>.
	if r.Method == http.MethodPost && problem == "" {
		if verr := e.Validate(); verr == nil {
			http.Redirect(w, r, "/media/edit?"+editQuery(id, e),
				http.StatusSeeOther)
			return
		} else {
			problem = verr.Error()
		}
	}

	shown := make([]aspectChoice, 0, len(aspects))
	for _, a := range aspects {
		a.On = a.Value == e.Aspect
		shown = append(shown, a)
	}

	data := map[string]any{
		"Title": "Edit a picture", "Principal": p, "Nav": "media",
		"Parent":  parent,
		"Aspects": shown,
		"Edit":    e,
		"Alt":     firstNonEmpty(strings.TrimSpace(r.FormValue("alt")), parent.Alt),
		"Error":   problem,
	}
	// Only when there is something to look at, and only when it would work:
	// an <img> pointing at a recipe the deriver will refuse is a broken
	// picture where an explanation belongs.
	if !e.Empty() && problem == "" {
		if verr := e.Validate(); verr == nil {
			data["Preview"] = "/media/edit/preview?" + editQuery(id, e)
			data["Did"] = e.Describe()
			data["Recipe"] = e
		} else {
			data["Error"] = verr.Error()
		}
	}
	s.render(w, r, "mediaedit.html", data)
}

// handleMediaEditPreview derives a picture nobody has asked to keep.
func (s *Server) handleMediaEditPreview(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Media == nil || s.Media.Library == nil {
		http.NotFound(w, r)
		return
	}
	lib, err := s.Media.Library()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	e, eerr := editFromQuery(r.URL.Query().Get)
	if eerr != nil {
		http.Error(w, eerr.Error(), http.StatusBadRequest)
		return
	}
	parent, body, err := lib.Preview(
		strings.TrimSpace(r.URL.Query().Get("id")), e, medialib.PreviewWidth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	h := w.Header()
	h.Set("Content-Type", parent.MIME())
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", "inline")
	// Never stored, so never cached: the bytes exist for the length of this
	// response and a copy in a proxy would outlive the question it answered.
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
