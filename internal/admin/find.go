// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/find"
	"github.com/quilzo/quilzo/internal/site"
)

// Looking for one thing, across everything.
//
// A hundred and thirteen routes, twenty-nine destinations, seventy settings,
// and until now the only way to reach any of it was to remember which of five
// groups it was in and scroll. The site this interface makes has had search
// since there was a site; the interface had none.
//
// # Why it is a form and a page, and not a suggestion list
//
// The policy on every response here is `script-src 'none'`, so there is no
// type-ahead and there will not be one. A GET form and a results page is the
// whole mechanism: the query is in the address, so a search is a link somebody
// can keep, send, or go back to — which a suggestion list is not.
//
// # What a person may search is what they may see
//
// The sources are assembled per request from this person's permissions rather
// than searched and filtered afterwards. Filtering afterwards leaks: the count
// of results, or their absence, still says what is in the list. So a reader is
// handed no settings at all rather than settings they cannot open.

// handleFind searches, and shows what was found.
func (s *Server) handleFind(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	data := map[string]any{
		"Title": "Find", "Nav": "find", "Principal": p, "Query": query,
	}
	if query == "" {
		// No query is not an empty result. A screen that says "nothing
		// matched" before anybody has typed reads as a broken search.
		s.render(w, r, "find.html", data)
		return
	}

	hits := find.Search(query, s.findSources(p), 40)
	data["Hits"] = groupHits(hits)
	data["Count"] = len(hits)
	s.render(w, r, "find.html", data)
}

// findSources is what this person may look through.
func (s *Server) findSources(p principal) find.Sources {
	src := find.Sources{
		Commit:  s.Store.GetRef(site.RefDraft),
		Screens: s.navigableTo(p),
	}
	if pages, err := site.PagesAt(s.Store, site.RefDraft); err == nil {
		src.Pages = pages
	}

	// The settings, for somebody who may read them. A key's summary describes
	// a control, which is why the settings screen asks for the same thing.
	if s.mayUse(p, auth.ActGrant, "/") {
		for _, o := range config.All() {
			src.Settings = append(src.Settings,
				find.Option{Key: o.Key, Summary: o.Summary})
		}
	}

	if s.Media != nil && s.Media.Library != nil {
		if lib, err := s.Media.Library(); err == nil && lib != nil {
			if files, ferr := lib.List(); ferr == nil {
				for _, f := range files {
					src.Media = append(src.Media,
						find.File{ID: f.ID, Alt: f.Alt})
				}
			}
		}
	}

	if s.Types != nil && s.Types.Load != nil {
		if st, err := s.Types.Load(); err == nil && st != nil && st.Registry != nil {
			for _, t := range st.Registry.Types {
				names := make([]string, 0, len(t.Fields))
				for _, f := range t.Fields {
					names = append(names, f.Name)
				}
				src.Types = append(src.Types,
					find.ContentType{Name: t.Name, Fields: names})
			}
		}
	}
	return src
}

// navigableTo is the screens this person may open.
//
// The navigation already hides what somebody may not use — "The refusal still
// happens at the handler; this is presentation" — and the same filter applies
// here for a stronger reason than presentation: a search that returns a screen
// and then refuses it teaches the searcher that the screen exists, which is
// the one thing hiding it was for.
func (s *Server) navigableTo(p principal) []find.Destination {
	var out []find.Destination
	for _, d := range destinations {
		if !s.mayUse(p, d.Needs, "/") {
			continue
		}
		for _, sc := range Screens() {
			if sc.Path == d.Path {
				out = append(out, sc)
				break
			}
		}
	}
	return out
}

// mayUse is the same question the navigation asks, asked the same way.
//
// Against "/" rather than the screen's own path, because that is what
// navigation() does and the two must agree: a screen the menu shows and the
// search hides, or the reverse, is a difference nobody can account for.
//
// No policy means no access control is configured, which is the single-operator
// case and permits everything — again matching navigation().
func (s *Server) mayUse(p principal, act auth.Action, resource string) bool {
	if s.Policy == nil {
		return true
	}
	return s.Policy.Evaluate(p.Name, act, resource).Allowed
}

// group is one heading of results.
type group struct {
	Heading string
	Hits    []find.Hit
}

// groupHits splits the ranked list under a heading per kind.
//
// The order within a kind is the finder's and is not touched. The kinds keep
// the order they arrived in, which is the finder's argument about their scores
// not being comparable — re-sorting them here would be this screen having a
// second opinion about it.
func groupHits(hits []find.Hit) []group {
	headings := map[find.Kind]string{
		find.Screen:  "Screens",
		find.Setting: "Settings",
		find.Type:    "Content types",
		find.Page:    "Pages",
		find.Media:   "Media",
	}
	var out []group
	for _, h := range hits {
		name := headings[h.Kind]
		if name == "" {
			name = string(h.Kind)
		}
		if len(out) > 0 && out[len(out)-1].Heading == name {
			out[len(out)-1].Hits = append(out[len(out)-1].Hits, h)
			continue
		}
		out = append(out, group{Heading: name, Hits: []find.Hit{h}})
	}
	return out
}
