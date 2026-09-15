// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/checked"
	"github.com/quilzo/quilzo/internal/site"
)

// When did anybody last confirm this page is still right?
//
// A column on the pages list and a button on the editor, rather than a screen
// of its own. The question is asked while looking at pages, and the
// navigation is the thing this release has been shortening — a new entry for
// every new idea is how it got to twenty-nine.
//
// See internal/checked for why a record carries a hash and why the interval is
// an interval rather than a date.

// Checked wires the record of what has been confirmed.
//
// Nil means the feature is absent and the column does not appear, rather than
// a column of blanks that reads as "nothing has ever been checked".
type Checked struct {
	Store *checked.Store
	// Every is the site's answer for a page that does not name its own, read
	// per call so a change to the setting takes effect without a restart.
	Every func() time.Duration
}

// checkedCell is one page's standing, as the table shows it.
type checkedCell struct {
	State checked.State
	// When is the date of the last check, for the one state where a date is
	// the useful thing to show. The others are a word.
	When string
	By   string
	// Owner is whose job the page is, which is a different question from who
	// last read it and is empty far more often. See internal/checked.
	Owner string
}

// checkedFor builds the column, and counts what needs attention.
func (s *Server) checkedFor(names []string) (map[string]checkedCell, int) {
	if s.Checked == nil || s.Checked.Store == nil {
		return nil, 0
	}
	records, err := s.Checked.Store.All()
	if err != nil {
		return nil, 0
	}
	ids, err := site.PageIDsAt(s.Store, site.RefDraft)
	if err != nil {
		ids = map[string]string{}
	}

	rows := checked.Survey(names, ids, records, s.reviewEvery(), time.Now())
	out := make(map[string]checkedCell, len(rows))
	due := 0
	for _, r := range rows {
		if checked.NeedsAttention(r.State) {
			due++
		}
		cell := checkedCell{State: r.State, By: r.By, Owner: r.Owner}
		if r.At != 0 {
			cell.When = time.Unix(r.At, 0).UTC().Format("2006-01-02")
		}
		out[r.Page] = cell
	}
	return out, due
}

// reviewEvery is the site's interval, with the package default when nothing
// supplies one.
func (s *Server) reviewEvery() time.Duration {
	if s.Checked != nil && s.Checked.Every != nil {
		if d := s.Checked.Every(); d > 0 {
			return d
		}
	}
	return 365 * 24 * time.Hour
}

// handleCheckedSet records that somebody confirmed a page.
func (s *Server) handleCheckedSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if s.Checked == nil || s.Checked.Store == nil {
		http.Error(w, "this build has nowhere to record a check",
			http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	page := strings.TrimSpace(r.FormValue("page"))
	// Editing a draft: saying a page is still right is a statement about that
	// page, made by somebody who works on it — so it is that page the caller
	// has to be allowed to work on, not the site.
	if !s.canPage(w, r, p, auth.ActEditDraft, page) {
		return
	}
	ids, err := site.PageIDsAt(s.Store, site.RefDraft)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, exists := ids[page]; !exists {
		// Refused rather than recorded, the same as the command line: a check
		// on a page that is not there produces a record nothing will ever
		// clear.
		s.render(w, r, "message.html", map[string]any{
			"Title": "Not recorded", "Principal": p, "Heading": "Not recorded",
			"Body": "There is no page called " + page + " in the draft.",
		})
		return
	}

	if _, err := s.Checked.Store.Set(checked.Record{
		Page: page, Content: ids[page], By: p.Name,
		Every: strings.TrimSpace(r.FormValue("every")),
		Note:  strings.TrimSpace(r.FormValue("note")),
	}, time.Now()); err != nil {
		s.render(w, r, "message.html", map[string]any{
			"Title": "Not recorded", "Principal": p, "Heading": "Not recorded",
			"Body": err.Error(),
		})
		return
	}
	s.audit("checked.set", "/"+page, map[string]string{"by": p.Name})
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// handleCheckedOwn says whose job a page is.
//
// A form of its own next to the confirm button rather than a field inside it,
// because they are two different acts: one is "I have read this", the other is
// "this is yours", and a person doing the second has usually not done the
// first. See checked.Store.Own.
func (s *Server) handleCheckedOwn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if s.Checked == nil || s.Checked.Store == nil {
		http.Error(w, "this build has nowhere to record an owner",
			http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	page := strings.TrimSpace(r.FormValue("page"))
	// The same scope as recording a check, and for the same reason: this is a
	// statement about one page, made by somebody who works on that page.
	if !s.canPage(w, r, p, auth.ActEditDraft, page) {
		return
	}
	ids, err := site.PageIDsAt(s.Store, site.RefDraft)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, exists := ids[page]; !exists {
		s.render(w, r, "message.html", map[string]any{
			"Title": "Not recorded", "Principal": p, "Heading": "Not recorded",
			"Body": "There is no page called " + page + " in the draft.",
		})
		return
	}

	owner := strings.TrimSpace(r.FormValue("owner"))
	if _, err := s.Checked.Store.Own(page, owner); err != nil {
		s.render(w, r, "message.html", map[string]any{
			"Title": "Not recorded", "Principal": p, "Heading": "Not recorded",
			"Body": err.Error(),
		})
		return
	}
	// Both directions are logged, and the empty one is logged as an empty
	// owner rather than left out: "nobody owns this now" is the half somebody
	// looking for how a page fell through the cracks needs to find.
	s.audit("checked.own", "/"+page, map[string]string{
		"by": p.Name, "owner": owner,
	})
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}
