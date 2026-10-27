// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentport"
)

// Agents brought in from other platforms, and taken out to them. The file
// is read into declarations and shown with what was kept, what was
// changed, what was left out and what is the reader's to decide, and
// nothing is declared until they say so. See internal/agentport.

// importedView is one agent of an import, as the screen shows it.
type importedView struct {
	M                              agent.Manifest
	Source                         string
	Kept, Changed, Left, Decide    []string
	Invalid                        string
	Exists, Declarable             bool
	Declaration                    string
	Files                          []importedFile
	Model, Instructions, Delegates string
}

type importedFile struct{ Name, Body string }

// importText is what was pasted or chosen, whichever there is.
func importText(r *http.Request) ([]byte, error) {
	if f, _, err := r.FormFile("file"); err == nil {
		defer f.Close()
		return io.ReadAll(io.LimitReader(f, MaxRequestBody))
	}
	if t := strings.TrimSpace(r.FormValue("text")); t != "" {
		return []byte(t), nil
	}
	return nil, errors.New("choose the file, or paste what it holds")
}

func (s *Server) handleAgentImport(w http.ResponseWriter, r *http.Request) {
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	var formats []agentport.Format
	for _, f := range agentport.Formats {
		if f.Import {
			formats = append(formats, f)
		}
	}
	data := map[string]any{"Title": "Import an agent", "Principal": p, "Nav": "agents",
		"Formats": formats, "Error": r.URL.Query().Get("e")}
	if s.Agents == nil || s.Agents.Load == nil || s.Agents.Save == nil {
		// Without the declarations there is nothing to check an import
		// against, and nowhere to declare it.
		data["Unavailable"] = "this server was started without access to the agent declarations, " +
			"so nothing can be imported here: use quilzo agent import FILE"
		s.render(w, r, "agent_import.html", data)
		return
	}
	if r.Method == http.MethodPost && r.FormValue("do") == "declare" {
		s.declareImported(w, r, p)
		return
	}
	if r.Method == http.MethodPost {
		from, name := r.FormValue("from"), strings.TrimSpace(r.FormValue("name"))
		data["From"], data["Name"] = from, name
		raw, err := importText(r)
		var imp *agentport.Imported
		if err == nil {
			imp, err = agentport.Read(raw, from, name)
		}
		if err != nil {
			data["ReadError"] = err.Error()
			s.render(w, r, "agent_import.html", data)
			return
		}
		declared, err := s.Agents.Load()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var known map[string]bool
		if s.Agents.Known != nil {
			known = map[string]bool{}
			for _, c := range s.Agents.Known() {
				known[c] = true
			}
		}
		f, _ := agentport.FormatNamed(imp.Format)
		var views []importedView
		var declarable []agent.Manifest
		for _, a := range imp.Agents {
			v := importedView{M: a.Manifest, Source: a.Source, Model: a.Manifest.Model,
				Instructions: a.Manifest.Instructions, Delegates: strings.Join(a.Manifest.Delegates, ", ")}
			for _, n := range a.Notes {
				switch n.Kind {
				case agentport.Kept:
					v.Kept = append(v.Kept, n.Text)
				case agentport.Changed:
					v.Changed = append(v.Changed, n.Text)
				case agentport.Left:
					v.Left = append(v.Left, n.Text)
				default:
					v.Decide = append(v.Decide, n.Text)
				}
			}
			check := a.Manifest
			if err := check.Validate(known); err != nil {
				v.Invalid = err.Error()
			}
			_, v.Exists = declared[a.Manifest.Name]
			v.Declarable = v.Invalid == "" && !v.Exists
			if v.Declarable {
				declarable = append(declarable, a.Manifest)
			}
			if b, err := json.MarshalIndent(a.Manifest, "", "  "); err == nil {
				v.Declaration = string(b)
			}
			names := make([]string, 0, len(a.Files))
			for n := range a.Files {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				v.Files = append(v.Files, importedFile{Name: n, Body: string(a.Files[n])})
			}
			views = append(views, v)
		}
		var notes []string
		for _, n := range imp.Notes {
			notes = append(notes, n.Text)
		}
		data["Read"] = map[string]any{"Format": f.Title, "FormatName": imp.Format, "Agents": views, "Notes": notes,
			"Several": len(views) > 1}
		if len(declarable) > 0 {
			if b, err := json.Marshal(declarable); err == nil {
				data["Declarable"] = string(b)
			}
		}
	}
	s.render(w, r, "agent_import.html", data)
}

// declareImported declares what a person chose of an import, each after the
// agents it hands work to. Each is checked again as it is saved, as any
// declaration is: what came back from the page is not trusted for being
// what the page was sent.
func (s *Server) declareImported(w http.ResponseWriter, r *http.Request, p principal) {
	var ms []agent.Manifest
	dec := json.NewDecoder(strings.NewReader(r.FormValue("agents")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ms); err != nil || len(ms) == 0 {
		http.Redirect(w, r, "/agents/import?"+url.Values{"e": {"read the file again: what came back was not its agents"}}.Encode(),
			http.StatusSeeOther)
		return
	}
	chosen := map[string]bool{}
	for _, n := range r.Form["pick"] {
		chosen[n] = true
	}
	var picked []agent.Manifest
	for _, m := range ms {
		if chosen[m.Name] {
			picked = append(picked, m)
		}
	}
	if len(picked) == 0 {
		http.Redirect(w, r, "/agents/import?"+url.Values{"e": {"nothing was chosen to declare"}}.Encode(), http.StatusSeeOther)
		return
	}
	var did []string
	var failed []string
	for _, i := range agentport.Order(picked) {
		m := picked[i]
		if err := s.Agents.Save(m, true, p.actor()); err != nil {
			failed = append(failed, fmt.Sprintf("%s was not declared: %v", m.Name, err))
			continue
		}
		did = append(did, m.Name)
	}
	v := url.Values{}
	switch {
	case len(did) == 0:
		v.Set("e", strings.Join(failed, "; "))
		http.Redirect(w, r, "/agents/import?"+v.Encode(), http.StatusSeeOther)
		return
	case len(failed) > 0:
		v.Set("e", "Declared "+strings.Join(did, ", ")+". "+strings.Join(failed, "; "))
	case len(did) == 1:
		v.Set("m", "Imported. Below is what it may do here; it may do more only when you give it more.")
		http.Redirect(w, r, "/agents/edit/"+url.PathEscape(did[0])+"?"+v.Encode(), http.StatusSeeOther)
		return
	default:
		v.Set("m", "Imported "+strings.Join(did, ", ")+". Each may do more only when you give it more, on its page.")
	}
	http.Redirect(w, r, "/agents?"+v.Encode(), http.StatusSeeOther)
}

// handleAgentExport is /agents/export/NAME: the declaration in another
// platform's format, with what that format cannot hold, and the file to
// download.
func (s *Server) handleAgentExport(w http.ResponseWriter, r *http.Request) {
	p, ok := s.studioAllowed(w, r)
	if !ok {
		return
	}
	if s.Agents == nil || s.Agents.Load == nil {
		http.Error(w, "this build was started without the agent declarations", http.StatusServiceUnavailable)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/agents/export/")
	declared, err := s.Agents.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m, found := declared[name]
	if !found || !agentName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	var formats []agentport.Format
	for _, f := range agentport.Formats {
		if f.Export {
			formats = append(formats, f)
		}
	}
	to := r.URL.Query().Get("to")
	if to == "" {
		to = "claude-subagent"
	}
	e, err := agentport.Write(m, to)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if file := r.URL.Query().Get("file"); file != "" {
		body, ok := e.Files[file]
		if !ok {
			http.NotFound(w, r)
			return
		}
		ct := "application/json"
		if strings.HasSuffix(file, ".yaml") {
			ct = "application/yaml"
		} else if strings.HasSuffix(file, ".md") {
			ct = "text/markdown; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(file, `"`, "")+`"`)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(body)
		return
	}
	names := make([]string, 0, len(e.Files))
	for n := range e.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	var files []importedFile
	for _, n := range names {
		files = append(files, importedFile{Name: n, Body: string(e.Files[n])})
	}
	var notes []string
	for _, n := range e.Notes {
		notes = append(notes, n.Text)
	}
	f, _ := agentport.FormatNamed(to)
	s.render(w, r, "agent_export.html", map[string]any{"Title": "Export " + name, "Principal": p, "Nav": "agents",
		"M": m, "To": to, "Format": f, "Formats": formats, "Files": files, "Notes": notes})
}
