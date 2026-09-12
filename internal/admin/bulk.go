// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/checked"
	"github.com/quilzo/quilzo/internal/site"
)

// Doing the same thing to several pages.
//
// Retiring fifty pages was fifty round trips, and confirming that a section of
// a site is still right was one page at a time — which is the point at which
// somebody stops doing it.
//
// # Checkboxes, and no script to go with them
//
// A checkbox needs no JavaScript; what needs it is "select all", and there is
// none here. A page shows fifty rows at most, so selecting what you want is
// bounded work, and a "select all" that only selects the visible page is a
// control that means something different from what it says.
//
// # Why removing takes a second screen and marking does not
//
// They are different kinds of act. Recording that a page is still right is
// additive, reversible by recording it again, and wrong at worst by a day.
// Taking pages out of the draft is the one thing on this screen somebody can
// do to fifty things at once and regret.
//
// So removal lists exactly what is about to go, by name, and asks again. Not a
// dialogue — there is no script — but a screen: the names, a button that says
// how many, and a way back. The existing single-page Remove button sits next
// to ordinary actions and that has been fine for one page; fifty is a
// different question.
//
// Nothing is erased either way, and the screen says so: the store keeps every
// commit, so a removed page is still there and still addressable. That is true
// and it is not a reason to skip asking.

// selected reads the checked boxes, refusing anything not in the draft.
//
// Names come from a form, so they arrive from the browser rather than from the
// list this server rendered. Checking them against the draft is what stops a
// crafted post naming something else — and it also quietly drops a page
// somebody else deleted while this screen was open, which is the right answer
// to that race.
// A store with no draft yet selects nothing rather than failing. "There is no
// draft" is a state, not an error, and answering a form post with a 500 is how
// a first run looks broken.
func (s *Server) selected(r *http.Request) []string {
	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		return nil
	}
	var out []string
	for _, name := range r.Form["page"] {
		if _, exists := pages[name]; exists {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// handleBulk routes the two actions the pages list offers.
//
// One endpoint and one form, because two submit buttons in one form is how a
// browser expresses "pick an action for this selection" without script. The
// action is read from which button was pressed.
func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request) {
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
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	names := s.selected(r)
	if len(names) == 0 {
		// Back where they were, saying nothing was selected. An empty
		// selection is a mis-click rather than an error, and a screen that
		// shouts about it is a screen people learn to ignore.
		s.pagesBack(w, r, "Nothing was selected.", "")
		return
	}

	switch {
	case r.FormValue("confirm-remove") != "":
		s.bulkRemove(w, r, p, names)
	case r.FormValue("remove") != "":
		s.confirmRemove(w, r, p, names)
	case r.FormValue("checked") != "":
		s.bulkChecked(w, r, p, names)
	default:
		s.pagesBack(w, r, "", "no action was chosen")
	}
}

// bulkChecked records that several pages are still right.
func (s *Server) bulkChecked(w http.ResponseWriter, r *http.Request,
	p principal, names []string) {

	if s.Checked == nil || s.Checked.Store == nil {
		http.Error(w, "this build has nowhere to record a check",
			http.StatusServiceUnavailable)
		return
	}
	ids, err := site.PageIDsAt(s.Store, site.RefDraft)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	done := 0
	for _, name := range names {
		if _, cerr := s.Checked.Store.Set(checked.Record{
			Page: name, Content: ids[name], By: p.Name,
		}, now); cerr == nil {
			done++
		}
	}
	// One entry naming the set rather than one per page. Fifty rows in the log
	// for one act by one person at one moment is a log that is harder to read
	// than the thing it records — and the names are in it, which is what AU-3
	// asks for.
	s.audit("checked.set", "/", map[string]string{
		"by": p.Name, "pages": strings.Join(names, " "),
	})
	s.pagesBack(w, r, plural2(done,
		"One page is recorded as still right.",
		"Those pages are recorded as still right."), "")
}

// confirmRemove asks again, naming everything that would go.
func (s *Server) confirmRemove(w http.ResponseWriter, r *http.Request,
	p principal, names []string) {

	s.render(w, r, "confirmremove.html", map[string]any{
		"Nav": "pages", "Title": "Remove pages", "Principal": p,
		"Names": names, "Back": backTo(r),
	})
}

// bulkRemove takes the pages out of the draft, running every check the
// single-page removal runs.
//
// Reusing pointingAt, the type gate and SaveDraftFrom rather than a shorter
// path, because a bulk action that skips a check is the way around that check
// — and CONTRIBUTING.md refuses "anything that makes a control easier to skip"
// for exactly this shape of feature.
//
// Per-page permission too. An author scoped to their own corner may remove
// inside it and nowhere else, and a selection that reaches past that boundary
// is refused whole rather than partly applied: half a bulk action is worse
// than none, because nobody can tell which half.
//
// One commit, not one per page. The set went in one act and reads as one act
// in the history, and a partial failure cannot leave the draft half-changed.
func (s *Server) bulkRemove(w http.ResponseWriter, r *http.Request,
	p principal, names []string) {

	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		s.pagesBack(w, r, "", "there is no draft, so there is nothing to remove")
		return
	}

	for _, name := range names {
		if !s.mayUse(p, auth.ActEditDraft, "/"+name) {
			s.pagesBack(w, r, "", fmt.Sprintf(
				"you may not remove %s, so none of this selection was removed",
				name))
			return
		}
	}

	// Anything still pointing at one of them, checked before the removal for
	// the reason handlePageDelete gives: afterwards the page is gone, the
	// complaint is about the menu, and putting it back means remembering what
	// was in it.
	//
	// Against the pages that would remain, so a menu entry pointing at one
	// removed page does not block the removal of another — and so two pages
	// that point at each other can go together, which is the case a per-page
	// check gets wrong in both directions.
	going := make(map[string]bool, len(names))
	for _, name := range names {
		going[name] = true
	}
	remaining := make(map[string]any, len(pages))
	for k, v := range pages {
		if !going[k] {
			remaining[k] = v
		}
	}
	for _, name := range names {
		if blockers := s.pointingAt(name, remaining); len(blockers) > 0 {
			s.pagesBack(w, r, "", fmt.Sprintf(
				"%s is still used by %s, so none of this selection was "+
					"removed. Remove those first, or they become links to a "+
					"page that is not there.",
				name, strings.Join(blockers, ", ")))
			return
		}
	}

	// The type gate, compared against what is already failing — the same
	// reasoning as the single removal, which explains at length why this
	// cannot fire today and is here because that is a property of the current
	// model rather than a law.
	if s.CheckTypes != nil {
		was := failingPages(s.CheckTypes(pages))
		var introduced []string
		for _, f := range s.CheckTypes(remaining) {
			if !was[f.Page] {
				introduced = append(introduced, f.Page)
			}
		}
		if len(introduced) > 0 {
			s.pagesBack(w, r, "", fmt.Sprintf(
				"removing these would leave %s no longer satisfying its type, "+
					"so none of them was removed",
				strings.Join(introduced, ", ")))
			return
		}
	}

	msg := "remove " + strings.Join(names, ", ")
	if len(names) > 4 {
		msg = fmt.Sprintf("remove %d pages", len(names))
	}
	if _, err := site.SaveDraftFrom(s.Store, remaining, msg, p.Name,
		r.FormValue("base")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// A claim on a page that no longer exists would keep it locked forever.
	if s.Locks != nil && s.SaveLocks != nil {
		if locks, lerr := s.Locks(); lerr == nil {
			now := time.Now()
			for _, name := range names {
				locks.Release(name, p.Name, now)
			}
			_ = s.SaveLocks(locks)
		}
	}

	// One entry naming the set. Fifty rows in the log for one act by one
	// person at one moment is harder to read than the thing it records, and
	// the names are in it, which is what AU-3 asks for.
	s.audit("page.delete", "/", map[string]string{
		"by": p.Name, "pages": strings.Join(names, " "),
	})
	s.pagesBack(w, r, fmt.Sprintf(
		"%d page(s) are out of the draft. They are still in every commit that "+
			"had them, and publishing takes them off the live site.",
		len(names)), "")
}
