// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/decide"
)

// Deciders on a screen: declare typed questions, try them on some state, and
// see each answer with its confidence and whether a person would get it.

// Deciders is the site's deciders, supplied by whatever wired this server.
type Deciders struct {
	Load  func() (*decide.Set, error)
	Save  func(set *decide.Set, by, change, name string) error
	Model func(name string) (decide.Model, string)
}

// exampleDecider is what the new-decider box starts with, so the shape of a
// declaration is on the screen rather than in a manual.
const exampleDecider = `{
  "name": "ticket",
  "title": "Support ticket triage",
  "questions": [
    {"name": "queue", "ask": "Which team should handle this?", "kind": "choice",
     "options": ["billing", "shipping", "returns", "other"]},
    {"name": "angry", "ask": "Is the customer angry?", "kind": "yesno"},
    {"name": "urgency", "ask": "How urgent is it, from 0 to 1?", "kind": "score"}
  ],
  "min_confidence": 0.8,
  "samples": 3
}`

func (s *Server) handleDeciders(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assistantsReady(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Nav": "decisions", "Title": "Decisions", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanSave": s.mayUse(p, auth.ActPublish, "/") && !p.Limits.ReadOnly,
		"Example": exampleDecider}
	if s.Deciders == nil || s.Deciders.Load == nil {
		data["Unavailable"] = "This build was started without deciders."
		s.render(w, r, "deciders.html", data)
		return
	}
	set, err := s.Deciders.Load()
	if err != nil {
		data["Unavailable"] = "The deciders could not be read: " + err.Error()
		s.render(w, r, "deciders.html", data)
		return
	}
	data["List"] = set.Deciders
	s.render(w, r, "deciders.html", data)
}

// handleDecider shows one decider and runs its test console.
func (s *Server) handleDecider(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assistantsReady(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/decisions/")
	if s.Deciders == nil || s.Deciders.Load == nil || name == "" {
		http.Redirect(w, r, "/decisions", http.StatusSeeOther)
		return
	}
	set, err := s.Deciders.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d, found := set.Get(name)
	if !found {
		http.NotFound(w, r)
		return
	}
	decl, _ := json.MarshalIndent(d, "", "  ")
	data := map[string]any{"Nav": "decisions", "Title": d.Title, "Principal": p, "D": d,
		"Declaration": string(decl),
		"Message":     r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanSave": s.mayUse(p, auth.ActPublish, "/") && !p.Limits.ReadOnly}

	// The console. A POST, because the state may be somebody's ticket and
	// does not belong in an address, a history or a server log.
	if r.Method == http.MethodPost {
		raw := r.FormValue("state")
		data["State"] = raw
		var state any
		if err := json.Unmarshal([]byte(raw), &state); err != nil {
			data["TestError"] = "The state is not JSON: " + err.Error()
		} else {
			var m decide.Model
			why := ""
			if s.Deciders.Model != nil {
				m, why = s.Deciders.Model(d.Name)
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
			defer cancel()
			res, derr := decide.Decide(ctx, d, m, state)
			if derr != nil {
				data["TestError"] = derr.Error()
			} else {
				if res.Note == "" && why != "" {
					res.Note = why
				}
				data["Res"] = res
			}
		}
	}
	s.render(w, r, "decider.html", data)
}

func (s *Server) handleDeciderSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.deciderWrite(w, r)
	if !ok {
		return
	}
	var d decide.Decider
	if err := json.Unmarshal([]byte(r.FormValue("declaration")), &d); err != nil {
		http.Redirect(w, r, "/decisions?e="+url.QueryEscape("That is not a decider: "+err.Error()),
			http.StatusSeeOther)
		return
	}
	set, err := s.Deciders.Load()
	if err == nil {
		err = set.Put(d)
	}
	if err == nil {
		err = s.Deciders.Save(set, p.Name, "declare", d.Name)
	}
	if err != nil {
		http.Redirect(w, r, "/decisions?e="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/decisions/"+url.PathEscape(d.Name)+"?m="+url.QueryEscape("Saved."),
		http.StatusSeeOther)
}

func (s *Server) handleDeciderRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.deciderWrite(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	set, err := s.Deciders.Load()
	if err == nil && !set.Remove(name) {
		err = errNoSuchDecider
	}
	if err == nil {
		err = s.Deciders.Save(set, p.Name, "remove", name)
	}
	if err != nil {
		http.Redirect(w, r, "/decisions?e="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/decisions?m="+url.QueryEscape(name+" was removed."), http.StatusSeeOther)
}

const errNoSuchDecider = assistantError("there is no decider by that name")

func (s *Server) deciderWrite(w http.ResponseWriter, r *http.Request) (principal, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "takes a POST", http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return principal{}, false
	}
	if s.Deciders == nil || s.Deciders.Load == nil || s.Deciders.Save == nil {
		http.Error(w, "this build cannot change deciders", http.StatusServiceUnavailable)
		return principal{}, false
	}
	return p, true
}
