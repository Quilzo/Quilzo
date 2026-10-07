// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/memory"
)

// MemoryAdmin is what agents remember, for the people it is about. See
// internal/memory.
type MemoryAdmin struct {
	Store *memory.Store
	// Confirm, Delete and Forget change it, recorded by the host.
	Confirm func(id, by string) error
	Delete  func(id, by string) error
	Forget  func(about, by string) (int, error)
}

// handleMemory shows what agents remember: about you, or, for an
// administrator, about everybody, with what waits for a person first.
func (s *Server) handleMemory(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Nav": "memory", "Title": "Memory", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Memory == nil {
		data["Off"] = true
		s.render(w, r, "memory.html", data)
		return
	}
	admin := s.policyAdmin(p.Name, p.Role, p.Scope, p.Limits)
	data["Admin"] = admin
	f := memory.Filter{}
	if !admin {
		f.About = p.Name
	}
	all, err := s.Memory.Store.List(f)
	if err != nil {
		data["Error"] = err.Error()
	}
	var held, kept []memory.Entry
	for _, e := range all {
		if !admin && e.About != p.Name {
			continue
		}
		if e.Held {
			held = append(held, e)
		} else {
			kept = append(kept, e)
		}
	}
	data["Held"], data["Kept"] = held, kept
	s.render(w, r, "memory.html", data)
}

// policyAdmin says somebody administers the whole site, with a credential
// that may.
func (s *Server) policyAdmin(name string, role auth.Role, scope string, limits auth.Scope) bool {
	return s.Policy != nil && s.Policy.Evaluate(name, auth.ActGrant, "/").Allowed &&
		auth.CheckCredential(role, scope, limits, auth.ActGrant, "/") == nil
}

// handleMemoryAct confirms, deletes or forgets: your own, or anybody's for
// an administrator.
func (s *Server) handleMemoryAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	back := func(k, v string) { http.Redirect(w, r, "/memory?"+k+"="+url.QueryEscape(v), http.StatusSeeOther) }
	if s.Memory == nil {
		http.NotFound(w, r)
		return
	}
	admin := s.policyAdmin(p.Name, p.Role, p.Scope, p.Limits)
	switch op := r.FormValue("op"); op {
	case "confirm", "delete":
		e, err := s.Memory.Store.Get(r.FormValue("id"))
		// Somebody else's memory and no memory at all look the same.
		if err != nil || (!admin && e.About != p.Name) {
			back("e", "no memory of yours has that id")
			return
		}
		do, said := s.Memory.Confirm, "confirmed: it is recalled from now on"
		if op == "delete" {
			do, said = s.Memory.Delete, "deleted"
		}
		if err := do(e.ID, p.Name); err != nil {
			back("e", err.Error())
			return
		}
		back("m", said)
	case "forget":
		about := p.Name
		if a := r.FormValue("about"); a != "" && a != p.Name {
			if !admin {
				http.Error(w, "forgetting somebody else is an administrator's", http.StatusForbidden)
				return
			}
			about = a
		}
		n, err := s.Memory.Forget(about, p.Name)
		if err != nil {
			back("e", err.Error())
			return
		}
		back("m", plural2(n, "1 memory", strconv.Itoa(n)+" memories")+" removed; no agent remembers "+about+" now")
	default:
		back("e", "choose what to do")
	}
}
