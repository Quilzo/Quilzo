package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lithoform/lithoform/internal/auth"
	"github.com/lithoform/lithoform/internal/schema"
	"github.com/lithoform/lithoform/internal/site"
)

// Removing a page, which the interface could not do.
//
// The command line has had `scrivet add --remove NAME` since early on. The
// browser had nothing — no button, no route, no way to get rid of a page that
// should not be there. It went unnoticed because every test that checks the
// interface covers the screens that exist, and a missing capability has no
// screen to fail on. It was found by building an application and needing to
// delete something.
//
// # Why this is not really a deletion
//
// The store is content-addressed and append-only, so nothing is erased. What
// changes is the draft: the next commit does not carry the page, publishing
// takes it off the live site, and every earlier commit still has it. That is
// the honest description and the screen says it, because "Delete" next to a
// button that does not delete is how people end up believing something is gone.
//
// Erasure, for the cases where bytes genuinely have to stop existing, is a
// different operation on a different store — see the submission handling in
// internal/form, which is deliberately not kept here for exactly this reason.
//
// # What is checked first
//
// A page other things point at. A menu entry naming a removed page is a 404
// that the person deleting will not see and every reader will, and the publish
// gate would catch it later — after the deletion, at the worst moment, blaming
// the menu rather than the delete. So it is refused here, where the fix is
// obvious and the page is still there.

// handlePageDelete drops a page from the draft.
func (s *Server) handlePageDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.pagesBack(w, r, "", "no page name")
		return
	}
	// Removing a page is editing the draft, scoped to that page, which is the
	// same permission that put it there. An author with their own corner of the
	// site can delete inside it and nowhere else.
	if !s.can(w, r, p, auth.ActEditDraft, "/"+name) {
		return
	}

	pages, err := site.PagesAt(s.Store, site.RefDraft)
	if err != nil {
		s.pagesBack(w, r, "", "there is no draft, so there is nothing to remove")
		return
	}
	if _, there := pages[name]; !there {
		s.pagesBack(w, r, "", fmt.Sprintf("there is no page called %q", name))
		return
	}

	// Anything still pointing at it. Checked before the removal rather than
	// caught by the publish gate afterwards, because at that point the page is
	// gone, the complaint is about the menu, and putting it back means
	// remembering what was in it.
	if blockers := s.pointingAt(name, pages); len(blockers) > 0 {
		s.pagesBack(w, r, "", fmt.Sprintf(
			"%s is still used by %s. Remove those first, or they become links "+
				"to a page that is not there.",
			name, strings.Join(blockers, ", ")))
		return
	}

	// The type gate, on a write that removes content rather than adding it.
	//
	// Taking a page away cannot make a remaining page violate its type, because
	// validation is per-page and no page's validity depends on another's. So
	// this never fires today, and it is here rather than exempted because that
	// reasoning is a property of the current model and not a law. If a type
	// ever gains a cross-page rule — a reference that must resolve, a slug that
	// must be unique — deletion becomes a way to break it, and this is the line
	// that starts failing instead of the live site.
	//
	// It compares against the failures already present rather than demanding a
	// clean draft, for the same reason saving does: a page somebody else broke
	// must not stop this deletion, and refusing to delete while any page is
	// invalid would make the broken page unremovable.
	if s.CheckTypes != nil {
		was := failingPages(s.CheckTypes(pages))
		remaining := make(map[string]any, len(pages))
		for k, v := range pages {
			if k != name {
				remaining[k] = v
			}
		}
		var introduced []string
		for _, f := range s.CheckTypes(remaining) {
			if !was[f.Page] {
				introduced = append(introduced, f.Page)
			}
		}
		if len(introduced) > 0 {
			s.pagesBack(w, r, "", fmt.Sprintf(
				"removing %s would leave %s no longer satisfying its type",
				name, strings.Join(introduced, ", ")))
			return
		}
	}

	delete(pages, name)

	msg := strings.TrimSpace(r.FormValue("message"))
	if msg == "" {
		msg = "remove " + name
	}
	if _, err := site.SaveDraftFrom(s.Store, pages, msg, p.Name,
		r.FormValue("base")); err != nil {

		var c *site.Conflict
		if errors.As(err, &c) {
			s.renderConflict(w, r, p, name, c)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// A claim on a page that no longer exists would keep it locked forever.
	if s.Locks != nil && s.SaveLocks != nil {
		if locks, err := s.Locks(); err == nil {
			locks.Release(name, p.Name, time.Now())
			_ = s.SaveLocks(locks)
		}
	}

	s.auditPub(p, "page.delete", "/"+name, nil)
	s.pagesBack(w, r, fmt.Sprintf(
		"%s is out of the draft. It is still in every commit that had it, and "+
			"publishing takes it off the live site.", name), "")
}

// pointingAt names the things that would break if a page went away.
func (s *Server) pointingAt(name string, pages map[string]any) []string {
	var out []string

	// Menus, which are the case that produces a 404 for a reader.
	//
	// menu.Set.Mentioning was written for this and had no caller: its comment
	// says "called before a page is deleted" and there was no deletion to call
	// it. The check existed before the feature it guards.
	if s.Structure != nil && s.Structure.Menus != nil {
		if set, err := s.Structure.Menus(); err == nil && set != nil {
			for _, m := range set.Mentioning(name) {
				out = append(out, fmt.Sprintf("%q in the %q menu", m.Item, m.Menu))
			}
		}
	}

	// A page whose own body names it as a listing source is not a thing this
	// model has, so the remaining pointer is a type binding — harmless on its
	// own, and worth clearing so a later page of the same name is not silently
	// bound to something nobody chose.
	if s.Types != nil && s.Types.Load != nil {
		if st, err := s.Types.Load(); err == nil {
			if bound, is := st.Bound[name]; is {
				out = append(out, fmt.Sprintf(
					"a binding to the type %q (unbind it on Types)", bound))
			}
		}
	}
	return out
}

// pagesBack returns to the page list with something to say.
func (s *Server) pagesBack(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// failingPages indexes a gate result by page name.
func failingPages(fs []schema.Failure) map[string]bool {
	out := make(map[string]bool, len(fs))
	for _, f := range fs {
		out[f.Page] = true
	}
	return out
}
