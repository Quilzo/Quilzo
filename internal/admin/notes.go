// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/note"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// What people have said about a page.
//
// Two screens rather than one, because there are two questions. /notes is
// "what is outstanding anywhere", which is the one somebody asks at the start
// of the day; the notes on the editor are "what did anybody say about this",
// which is the one they ask while changing it.
//
// See internal/note for why these live outside the store, and why each carries
// the hash of the page it was written against.

// Notes wires the remarks people leave on a draft.
//
// Nil means the feature is absent and the screens say so, rather than showing
// an empty list — the distinction every other optional field here draws,
// because "nobody has said anything" and "this build cannot tell you" look
// identical and mean opposite things.
type Notes struct {
	Store *note.Store
}

// noteRow is one remark as a screen shows it.
type noteRow struct {
	note.Note
	// Stale is computed against the page as it stands now, so the template
	// does not have to know what a hash is.
	Stale bool
	When  string
}

// handleNotes lists what is outstanding, everywhere.
func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	data := map[string]any{"Nav": "notes", "Title": "Notes", "Principal": p}
	if s.Notes == nil || s.Notes.Store == nil {
		data["Unavailable"] = "This build has nowhere to keep notes."
		s.render(w, r, "notes.html", data)
		return
	}

	all := r.URL.Query().Get("all") == "1"
	pages, err := s.Notes.Store.Pages()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type pageNotes struct {
		Page  string
		Notes []noteRow
	}
	var out []pageNotes
	open := 0
	for _, page := range pages {
		rows := s.noteRows(page, all)
		for _, n := range rows {
			if !n.Resolved {
				open++
			}
		}
		if len(rows) > 0 {
			out = append(out, pageNotes{page, rows})
		}
	}
	data["Pages"] = out
	data["Open"] = open
	data["All"] = all
	s.render(w, r, "notes.html", data)
}

// noteRows reads a page's notes and works out which have drifted.
func (s *Server) noteRows(page string, withResolved bool) []noteRow {
	if s.Notes == nil || s.Notes.Store == nil {
		return nil
	}
	notes, err := s.Notes.Store.List(page)
	if err != nil {
		return nil
	}
	now := s.pageHash(page)
	out := make([]noteRow, 0, len(notes))
	for _, n := range notes {
		if n.Resolved && !withResolved {
			continue
		}
		out = append(out, noteRow{
			Note:  n,
			Stale: n.Stale(now),
			When:  time.Unix(n.At, 0).UTC().Format("2006-01-02 15:04"),
		})
	}
	return out
}

// pageHash is what a note written now would be anchored to.
func (s *Server) pageHash(page string) string {
	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		return ""
	}
	return schema.ContentHash(pages[page])
}

// handleNoteAdd records a remark.
func (s *Server) handleNoteAdd(w http.ResponseWriter, r *http.Request) {
	p, ok := s.notesWriter(w, r)
	if !ok {
		return
	}
	page := strings.TrimSpace(r.FormValue("page"))
	text := strings.TrimSpace(r.FormValue("text"))

	n, err := s.Notes.Store.Add(note.Note{
		Page:    page,
		Field:   strings.TrimSpace(r.FormValue("field")),
		Author:  p.Name,
		Text:    text,
		Content: s.pageHash(page),
	}, time.Now())
	if err != nil {
		s.render(w, r, "message.html", map[string]any{
			"Title": "Not noted", "Principal": p, "Heading": "Not noted",
			"Body": err.Error(),
		})
		return
	}
	// AU-3, the same record the command line writes. A note names a colleague
	// and can be removed, so "somebody left this and somebody took it away"
	// has to be answerable from the log rather than from the directory, which
	// is the thing that changed.
	s.audit("note.add", "/"+page, map[string]string{"id": n.ID, "field": n.Field})

	// Back to whichever screen this was said from, by the same mechanism the
	// preference toggles use — and for the same reason: every response here
	// sets Referrer-Policy: no-referrer, so the form has to carry it.
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// handleNoteResolve marks one dealt with.
func (s *Server) handleNoteResolve(w http.ResponseWriter, r *http.Request) {
	p, ok := s.notesWriter(w, r)
	if !ok {
		return
	}
	err := s.Notes.Store.Resolve(r.FormValue("page"), r.FormValue("id"),
		p.Name, time.Now())
	if err != nil {
		s.render(w, r, "message.html", map[string]any{
			"Title": "Not resolved", "Principal": p, "Heading": "Not resolved",
			"Body": err.Error(),
		})
		return
	}
	s.audit("note.resolve", "/"+r.FormValue("page"),
		map[string]string{"id": r.FormValue("id")})
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// notesWriter is the shared gate on the two write endpoints.
//
// One function because two endpoints asking the same question in two places is
// how one of them ends up asking a slightly different one.
func (s *Server) notesWriter(w http.ResponseWriter, r *http.Request) (principal, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	// Editing a draft: a note is a remark about content, made by somebody
	// working on it.
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return principal{}, false
	}
	if s.Notes == nil || s.Notes.Store == nil {
		http.Error(w, "this build has nowhere to keep notes",
			http.StatusServiceUnavailable)
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}
