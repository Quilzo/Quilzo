// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Choosing a picture, instead of typing the hash of one.
//
// # The gap this closes
//
// A media id is the SHA-256 of the file's bytes, which is the right name for
// a stored object and an impossible thing to type. The Telegram editor knew
// that and offered a list; the browser did not, so attaching a photograph to
// a section meant copying sixty-four hexadecimal characters from one screen
// to another and hoping. Everything else about the page builder works without
// a mouse and reads correctly to a screen reader, and then this one field
// asked for a feat of transcription.
//
// # Why a page rather than a control
//
// The same reason internal/find is a form and a page: the policy on every
// response here is `script-src 'none'`, so there is no overlay, no modal and
// no type-ahead. A picker is therefore a screen you go to and come back from
// — which costs a page load and buys a URL somebody can keep, a back button
// that works, and a grid of real thumbnails rather than a dropdown of names.
//
// # Why it writes through the ordinary save
//
// The form posts to /sections/fields, the same endpoint the edit screen uses,
// carrying one value. section.Apply only touches the paths it is given, so
// picking a picture cannot disturb the rest of the section — and the write
// goes through the permission check, the type gate, the compare-and-swap and
// the commit message that were already there. A second write path would be a
// second place for those to be forgotten.

// pickable is one file, as the grid shows it.
type pickable struct {
	ID   string
	Name string
	Alt  string
	// Size is already written for a person. Formatted here rather than in the
	// template for the reason the paging arithmetic is: a calculation in a
	// template is a calculation nothing can test.
	Size     string
	Width    int
	Height   int
	Format   string
	Current  bool
	Viewable bool
}

// handleMediaPick shows the library, filtered to what this field can hold.
func (s *Server) handleMediaPick(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	page := strings.TrimSpace(q.Get("page"))
	path := strings.TrimSpace(q.Get("path"))
	at, _ := strconv.Atoi(q.Get("at"))

	// The field being filled belongs to a page, so this is the page the caller
	// has to be allowed to edit — not the site. Same reasoning as every other
	// per-page handler here.
	if !s.canPage(w, r, p, auth.ActEditDraft, page) {
		return
	}

	kind, isFile := section.FileKind(path)
	if !isFile {
		s.render(w, r, "message.html", map[string]any{
			"Title": "Nothing to pick", "Principal": p,
			"Heading": "Nothing to pick",
			"Body": "The " + path + " field does not hold a file, so there " +
				"is nothing to choose from.",
		})
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
	files, err := lib.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	current, onSection := currentValue(s.Store, page, at, path)
	if !onSection {
		// Refused rather than drawn. section.Apply will not create a field
		// that is not already there, so a picker for a path this section does
		// not have is a screen where choosing a photograph appears to work and
		// changes nothing — which is the worst of the three possible
		// outcomes.
		s.render(w, r, "message.html", map[string]any{
			"Title": "Nothing to fill", "Principal": p,
			"Heading": "Nothing to fill",
			"Body": "Section " + strconv.Itoa(at) + " of " + page +
				" has no " + path + " field, so there is nothing to put a " +
				"file in.",
		})
		return
	}
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))

	rows := make([]pickable, 0, len(files))
	for _, f := range files {
		if string(f.Kind) != kind {
			continue
		}
		// A rendition is a narrower copy of a picture that is already in this
		// list. Offering both would put the same photograph on the screen four
		// times and let somebody attach the 480-wide one to a full-width hero.
		if f.RenditionOf != "" {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(f.Name), search) &&
			!strings.Contains(strings.ToLower(f.Alt), search) {
			continue
		}
		rows = append(rows, pickable{
			ID: f.ID, Name: f.Name, Alt: f.Alt, Size: humanBytes(f.Size),
			Width: f.Width, Height: f.Height, Format: f.Format,
			Current:  sameAsset(current, f.ID),
			Viewable: f.Kind == media.Image,
		})
	}
	// Newest first, and explicitly: List walks a directory tree, so without
	// this the order is whatever the filesystem returned and it changes
	// between visits — a grid that rearranges itself is one nobody can point
	// at over somebody's shoulder. Name breaks the tie so two files uploaded
	// in the same second do not swap places either.
	when := make(map[string]int64, len(files))
	for _, f := range files {
		when[f.ID] = f.UploadedAt
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if when[rows[i].ID] != when[rows[j].ID] {
			return when[rows[i].ID] > when[rows[j].ID]
		}
		return rows[i].Name < rows[j].Name
	})

	pg := paginate(r, len(rows), PageSize)
	from, to := pg.slice(len(rows))

	s.render(w, r, "mediapick.html", map[string]any{
		"Title": "Choose a file", "Principal": p, "Nav": "sections",
		"Page": page, "At": at, "Path": path, "Kind": kind,
		"Noun":     nounFor(kind),
		"Shown":    rows[from:to],
		"Total":    len(rows),
		"Current":  current,
		"Query":    q.Get("q"),
		"Base":     s.Store.GetRef(site.RefDraft),
		"Back":     "/sections/fields?page=" + page + "&at=" + strconv.Itoa(at),
		"Paging":   pg,
		"PagePath": "/media/pick",
	})
}

// currentValue reads what the field holds now, and says whether the section
// has such a field at all.
//
// Read from the draft rather than passed in the query string: a value that
// travels through a link is a value somebody can change, and this one decides
// which radio is checked on a form that writes. The second return is what
// makes a mistyped path a refusal instead of a screen that does nothing.
func currentValue(st *store.Store, page string, at int, path string) (string, bool) {
	if st == nil || page == "" {
		return "", false
	}
	pages, err := site.PagesAt(st, site.RefDraft)
	if err != nil {
		return "", false
	}
	body, ok := pages[page]
	if !ok {
		return "", false
	}
	fields, err := section.Fields(body, at)
	if err != nil {
		return "", false
	}
	for _, f := range fields {
		if f.Path == path {
			return f.Value, true
		}
	}
	return "", false
}

// sameAsset reports whether a stored value names this file.
//
// A field may hold the bare id or the path the public site serves it at, and
// both are written by real interfaces — the Telegram editor accepts either.
// Comparing only one of them would leave the grid showing nothing selected on
// a section that is correctly filled in.
func sameAsset(value, id string) bool {
	if id == "" {
		return false
	}
	v := strings.TrimSpace(value)
	return v == id || v == "/media/"+id || v == "media/"+id
}

// humanBytes writes a file size the way somebody choosing a picture reads it.
//
// Not because the exact number is wrong, but because "2411954" and "2.4 MB"
// answer different questions, and the one being asked on this screen is
// whether the photograph is too heavy for the page it is going on.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	case n >= 1<<10:
		return strconv.FormatInt(n/(1<<10), 10) + " kB"
	default:
		return strconv.FormatInt(n, 10) + " bytes"
	}
}

// nounFor writes the kind the way a sentence needs it.
//
// "Choose a image" is what a template gets when a label is a bare kind name
// and the article beside it is a constant. Three kinds and an obvious answer
// for each, built here so every screen says the same thing.
func nounFor(kind string) string {
	switch kind {
	case "image":
		return "an image"
	case "video":
		return "a video"
	case "audio":
		return "an audio file"
	}
	return "a file"
}
