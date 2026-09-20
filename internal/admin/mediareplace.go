// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/site"
)

// Replacing a picture, in the browser.
//
// The rewrite itself is site.ReplaceAsset, which the command line calls too.
// Two surfaces each implementing "point everything at a different file" will
// disagree — one will walk pages and not records, or match the bare id and not
// the path spelling — and the site will be half replaced by whichever one
// somebody happened to use. This is the shape the image-rights gate got wrong
// before internal/media held a single answer about what a reference looks
// like.
//
// What is here is the part that is genuinely about a browser: which files may
// stand in for this one, and turning a form post into that call.

// handleMediaReplace points every draft reference at a different file.
func (s *Server) handleMediaReplace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// The same right as editing a draft, because that is what this does: it
	// writes a draft commit. Publishing it is still a separate act by somebody
	// who is allowed to publish.
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Media == nil {
		s.unwired(w, r, p, "Media", "the media library")
		return
	}
	if s.Store == nil {
		s.unwired(w, r, p, "Store", "the content store")
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
	oldID, newID := r.FormValue("id"), r.FormValue("with")
	if newID == "" {
		s.mediaRedirect(w, r, "", "choose the picture that replaces it")
		return
	}
	old, err := lib.Stat(oldID)
	if err != nil {
		s.mediaRedirect(w, r, "", "the picture being replaced: "+err.Error())
		return
	}
	next, err := lib.Stat(newID)
	if err != nil {
		s.mediaRedirect(w, r, "", "the picture replacing it: "+err.Error())
		return
	}
	if err := checkReplacement(lib, old, next); err != nil {
		s.mediaRedirect(w, r, "", err.Error())
		return
	}

	// The succession first. A rewrite that succeeded and a record that did not
	// leaves a site that is right and a library that cannot say why it
	// changed; the other order leaves a library that knows and a site that
	// does not, which is the recoverable half.
	next.Supersedes = old.ID
	_, body, gerr := lib.Get(next.ID)
	if gerr != nil {
		s.mediaRedirect(w, r, "", gerr.Error())
		return
	}
	next.Renditions = nil
	if perr := lib.Put(next, body); perr != nil {
		s.mediaRedirect(w, r, "", perr.Error())
		return
	}

	changed, _, rerr := site.ReplaceAsset(s.Store, old.ID, next.ID, p.Name)
	if rerr != nil {
		s.mediaRedirect(w, r, "", rerr.Error())
		return
	}
	s.auditPub(p, "media.replace", "/", map[string]string{
		"replaced": shortHash(old.ID), "with": shortHash(next.ID),
		"rewritten": fmt.Sprint(changed),
	})
	if changed == 0 {
		s.mediaRedirect(w, r, fmt.Sprintf(
			"%s now supersedes %s. Nothing in the draft pointed at it, so "+
				"only the library changed.", next.Name, old.Name), "")
		return
	}
	s.mediaRedirect(w, r, fmt.Sprintf(
		"%s now supersedes %s, in %d place(s) in the draft. The commit this "+
			"moved from is still stored, so History undoes it.",
		next.Name, old.Name, changed), "")
}

// checkReplacement refuses a substitution that cannot mean what it looks like.
//
// Shared with the command line in spirit and not in code, because the two
// return different things — an error a terminal prints and an error a redirect
// carries. What must not differ is the set of refusals, so both are listed
// here and the command's own test names the same three.
func checkReplacement(lib *medialib.Library, old, next media.File) error {
	if old.ID == next.ID {
		return fmt.Errorf(
			"%s is the same file as itself; two identical pictures have one "+
				"address here", old.Name)
	}
	if old.Kind != next.Kind {
		return fmt.Errorf(
			"%s is a %s and %s is a %s; a replacement has to be the same "+
				"kind of thing, because the content around it was written "+
				"for one", old.Name, old.Kind, next.Name, next.Kind)
	}
	return successionStaysAChain(lib, old.ID, next.ID)
}

// successionStaysAChain refuses a loop.
func successionStaysAChain(lib *medialib.Library, oldID, newID string) error {
	seen := map[string]bool{newID: true}
	at := oldID
	for range 64 {
		if at == "" {
			return nil
		}
		if seen[at] {
			return fmt.Errorf(
				"%s already replaces %s, directly or through a chain; "+
					"recording this would make the succession a loop, and "+
					"following it is the only reason to record it",
				shortHash(oldID), shortHash(newID))
		}
		seen[at] = true
		f, err := lib.Stat(at)
		if err != nil {
			return nil
		}
		at = f.Supersedes
	}
	return fmt.Errorf("the succession behind %s is more than 64 deep",
		shortHash(oldID))
}

// replacementsFor lists what each picture could be replaced with.
//
// Same kind only, and never itself or a narrower copy. Worked out here rather
// than in the template because a template comparing every file to every other
// file is a template doing a join, and the answer is the same for every row of
// the same kind.
func replacementsFor(files []media.File) map[string][]media.File {
	byKind := map[media.Kind][]media.File{}
	for _, f := range files {
		if f.RenditionOf != "" {
			continue
		}
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	for k := range byKind {
		sort.Slice(byKind[k], func(i, j int) bool {
			return byKind[k][i].Name < byKind[k][j].Name
		})
	}
	out := map[string][]media.File{}
	for _, f := range files {
		if f.RenditionOf != "" {
			continue
		}
		var others []media.File
		for _, c := range byKind[f.Kind] {
			if c.ID != f.ID {
				others = append(others, c)
			}
		}
		out[f.ID] = others
	}
	return out
}

// supersededBy is what replaced each file, for the listing.
//
// Supersedes points backwards, so this is the only way to answer "has this one
// been retired" while looking at the one that was. Sorted, because nothing
// stops two pictures claiming to replace the same one and a list that named
// whichever came first out of a map would read differently each time.
func supersededBy(files []media.File) map[string][]string {
	out := map[string][]string{}
	for _, f := range files {
		if f.Supersedes != "" {
			out[f.Supersedes] = append(out[f.Supersedes], f.Name)
		}
	}
	for id := range out {
		sort.Strings(out[id])
	}
	return out
}
