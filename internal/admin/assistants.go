// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/auth"
)

// Building a site's chatbots, and seeing exactly why they answer as they do.
//
// The screen every chatbot builder has, and one part most of them do not: the
// test console shows the passages that were retrieved and how each ranker
// placed them, and every sentence verification removed with the reason. An
// owner whose assistant keeps saying "I could not find that" can see whether
// the page is missing, the words differ, or the model wrote something the
// page does not say — three different fixes that look identical from the
// outside.

// DocumentChoice is a media library file offered as knowledge.
type DocumentChoice struct {
	ID, Name, Format string
	On               bool
}

// Assistants is the site's chatbots, supplied by whatever wired this server.
type Assistants struct {
	Load func() (*assistant.Set, error)
	// Save writes the set, recording who changed which assistant and how.
	Save func(set *assistant.Set, by, change, name string) error
	// Index is what an assistant reads: the published site, filtered, and
	// its documents — with the reason any document could not be used.
	Index func(assistant.Assistant) (*assistant.Index, []string, error)
	// Documents lists the library files a chatbot could be given.
	Documents func() ([]DocumentChoice, error)
	// Model is the configured model, or nil with the reason there is none.
	Model func(assistant.Assistant) (assistant.Model, string)
	// Forms names the site's forms, for the action picker.
	Forms func() ([]string, error)
}

func (s *Server) assistantsReady(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return principal{}, false
	}
	return p, true
}

func (s *Server) handleAssistants(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assistantsReady(w, r)
	if !ok {
		return
	}
	data := map[string]any{
		"Nav": "assistants", "Title": "Assistants", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanSave": s.mayUse(p, auth.ActPublish, "/") && !p.Limits.ReadOnly,
	}
	if s.Assistants == nil || s.Assistants.Load == nil {
		data["Unavailable"] = "This build was started without assistant " +
			"declarations, so there is nothing to list or change here."
		s.render(w, r, "assistants.html", data)
		return
	}
	set, err := s.Assistants.Load()
	if err != nil {
		data["Unavailable"] = "The assistants could not be read: " + err.Error()
		s.render(w, r, "assistants.html", data)
		return
	}
	data["List"] = set.Assistants
	s.render(w, r, "assistants.html", data)
}

// handleAssistant shows one assistant: its settings, its actions, and the
// test console.
func (s *Server) handleAssistant(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assistantsReady(w, r)
	if !ok {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/assistants/")
	if s.Assistants == nil || s.Assistants.Load == nil || name == "" {
		http.Redirect(w, r, "/assistants", http.StatusSeeOther)
		return
	}
	set, err := s.Assistants.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a, found := set.Get(name)
	if !found {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{
		"Nav": "assistants", "Title": a.Title, "Principal": p, "A": a,
		"Pages":   strings.Join(a.Pages, ", "),
		"Exclude": strings.Join(a.Exclude, ", "),
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanSave": s.mayUse(p, auth.ActPublish, "/") && !p.Limits.ReadOnly,
	}
	if s.Assistants.Documents != nil {
		if docs, derr := s.Assistants.Documents(); derr == nil {
			on := map[string]bool{}
			for _, id := range a.Documents {
				on[id] = true
			}
			for i := range docs {
				docs[i].On = on[docs[i].ID]
			}
			data["Docs"] = docs
		}
	}
	data["EmbedList"] = strings.Join(a.Embed, "\n")
	// The launcher's settings with their defaults, so the form shows what
	// a new one would be as well as what an existing one is.
	l := assistant.Launcher{}
	if a.Launcher != nil {
		l = *a.Launcher
	}
	data["L"] = l.Normalised()
	data["LPages"] = strings.Join(l.Pages, ", ")
	data["LNudgePages"] = strings.Join(l.NudgePages, ", ")
	data["LSuggestions"] = strings.Join(l.Suggestions, "\n")
	if s.Assistants.Forms != nil {
		if names, ferr := s.Assistants.Forms(); ferr == nil {
			data["FormNames"] = names
		}
	}

	// The test console.
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" && s.Assistants.Index != nil {
		data["Q"] = q
		idx, warnings, ierr := s.Assistants.Index(a)
		data["DocWarnings"] = warnings
		if ierr != nil {
			data["TestError"] = ierr.Error()
		} else {
			var m assistant.Model
			why := "extractive by declaration"
			if a.UseModel && s.Assistants.Model != nil {
				m, why = s.Assistants.Model(a)
			}
			ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
			defer cancel()
			ans, aerr := assistant.RespondTo(ctx, a, idx, m, q,
				r.URL.Query().Get("prev"))
			if aerr != nil {
				data["TestError"] = aerr.Error()
			} else {
				data["Ans"] = ans
				if ans.Note == "" && m == nil {
					ans.Note = why
					data["Ans"] = ans
				}
				data["Passages"] = len(idx.Passages)
			}
		}
	}
	s.render(w, r, "assistant.html", data)
}

// handleAssistantSave creates or updates an assistant's settings.
func (s *Server) handleAssistantSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assistantWrite(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	back := "/assistants"
	err := s.changeAssistants(p, "declare", name, func(set *assistant.Set) error {
		a, existed := set.Get(name)
		if !existed {
			a = assistant.Assistant{Name: name}
		}
		if r.FormValue("full") == "1" {
			a.Title = strings.TrimSpace(r.FormValue("title"))
			a.Greeting = strings.TrimSpace(r.FormValue("greeting"))
			a.Instructions = strings.TrimSpace(r.FormValue("instructions"))
			a.Refusal = strings.TrimSpace(r.FormValue("refusal"))
			a.Pages = splitCSV(r.FormValue("pages"))
			a.Exclude = splitCSV(r.FormValue("exclude"))
			a.Public = r.FormValue("public") == "1"
			a.Static = r.FormValue("static") == "1"
			a.UseModel = r.FormValue("use_model") == "1"
			a.KeepInstructions = r.FormValue("keep_instructions") == "1"
			n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("passages")))
			a.Passages = n
			a.Documents = r.Form["documents"]
			var origins []string
			for _, line := range strings.Split(r.FormValue("embed"), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					o, oerr := assistant.Origin(line)
					if oerr != nil {
						return oerr
					}
					origins = append(origins, o)
				}
			}
			a.Embed = origins
			a.Handoff = r.FormValue("handoff") == "1"
			a.Voice = r.FormValue("voice") == "1"
			a.Translate = r.FormValue("translate") == "1"
			days, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("handoff_days")))
			a.HandoffDays = days
			a.Launcher = nil
			if r.FormValue("launcher") == "1" {
				var qs []string
				for _, line := range strings.Split(r.FormValue("suggestions"), "\n") {
					if line = strings.TrimSpace(line); line != "" {
						qs = append(qs, line)
					}
				}
				after, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("nudge_after")))
				a.Launcher = &assistant.Launcher{Style: r.FormValue("launcher_style"), Side: r.FormValue("launcher_side"),
					Label: strings.TrimSpace(r.FormValue("launcher_label")), Panel: r.FormValue("panel"),
					Pages: splitCSV(r.FormValue("launcher_pages")), Suggestions: qs,
					Nudge: strings.TrimSpace(r.FormValue("nudge")), NudgeAfter: after,
					NudgePages: splitCSV(r.FormValue("nudge_pages"))}
			}
		} else {
			a.Title = strings.TrimSpace(r.FormValue("title"))
		}
		return set.Put(a)
	})
	if err != nil {
		http.Redirect(w, r, back+"?e="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/assistants/"+url.PathEscape(name)+"?m="+
		url.QueryEscape("Saved."), http.StatusSeeOther)
}

// handleAssistantAction adds or removes one action.
func (s *Server) handleAssistantAction(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assistantWrite(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("assistant"))
	action := strings.TrimSpace(r.FormValue("action"))
	back := "/assistants/" + url.PathEscape(name)
	remove := r.FormValue("remove") == "1"
	change := "action"
	if remove {
		change = "action.remove"
	}
	err := s.changeAssistants(p, change, name, func(set *assistant.Set) error {
		a, found := set.Get(name)
		if !found {
			return errNoSuchAssistant
		}
		kept := a.Actions[:0:0]
		for _, ac := range a.Actions {
			if ac.Name != action {
				kept = append(kept, ac)
			}
		}
		if !remove {
			kept = append(kept, assistant.Action{
				Name: action, Kind: assistant.ActionKind(r.FormValue("kind")),
				Target:      strings.TrimSpace(r.FormValue("target")),
				Description: strings.TrimSpace(r.FormValue("description")),
				Fields:      splitCSV(r.FormValue("fields")),
			})
		}
		a.Actions = kept
		return set.Put(a)
	})
	if err != nil {
		http.Redirect(w, r, back+"?e="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	msg := "Action added."
	if remove {
		msg = "Action removed."
	}
	http.Redirect(w, r, back+"?m="+url.QueryEscape(msg), http.StatusSeeOther)
}

// handleAssistantRemove deletes an assistant.
func (s *Server) handleAssistantRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assistantWrite(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	err := s.changeAssistants(p, "remove", name, func(set *assistant.Set) error {
		if !set.Remove(name) {
			return errNoSuchAssistant
		}
		return nil
	})
	if err != nil {
		http.Redirect(w, r, "/assistants?e="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/assistants?m="+url.QueryEscape(name+" was removed."),
		http.StatusSeeOther)
}

type assistantError string

func (e assistantError) Error() string { return string(e) }

const errNoSuchAssistant = assistantError("there is no assistant by that name")

// assistantWrite gates every change: a POST, from somebody who may publish.
// A public assistant is a new way for anybody on the internet to reach what
// the site says and what it offers to do.
func (s *Server) assistantWrite(w http.ResponseWriter, r *http.Request) (principal, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this changes an assistant and takes a POST",
			http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return principal{}, false
	}
	if s.Assistants == nil || s.Assistants.Load == nil || s.Assistants.Save == nil {
		http.Error(w, "this build cannot change assistants", http.StatusServiceUnavailable)
		return principal{}, false
	}
	return p, true
}

func (s *Server) changeAssistants(p principal, change, name string,
	edit func(*assistant.Set) error) error {

	set, err := s.Assistants.Load()
	if err != nil {
		return err
	}
	if err := edit(set); err != nil {
		return err
	}
	return s.Assistants.Save(set, p.Name, change, name)
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
