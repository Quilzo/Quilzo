// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/scim"
)

// The Provisioning screen: the identity provider's connection, and what
// each of its groups means here. See internal/scim.

// SCIMAdmin is provisioning, as the admin reaches it.
type SCIMAdmin struct {
	// Handler answers the identity provider at /scim/v2.
	Handler     http.Handler
	Status      func() (tokenSet bool, st *scim.State, err error)
	Map         func(group, to, by string) error
	Unmap       func(group, by string) error
	NewToken    func(by string) (string, error)
	RevokeToken func(by string) error
}

type scimGroupRow struct {
	Name, Means string
	Members     int
}

type scimUserRow struct {
	Name   string
	Active bool
	Groups string
	Holds  string
}

func (s *Server) handleProvisioning(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	s.renderProvisioning(w, r, p, "")
}

func (s *Server) renderProvisioning(w http.ResponseWriter, r *http.Request, p principal, token string) {
	data := map[string]any{"Title": "Provisioning", "Nav": "provisioning", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"), "Token": token,
		"Roles": auth.Roles, "Jobs": auth.Jobs}
	if s.SCIM == nil || s.SCIM.Status == nil {
		data["Unavailable"] = "This build was started without provisioning."
		s.render(w, r, "provisioning.html", data)
		return
	}
	set, st, err := s.SCIM.Status()
	if err != nil {
		data["Unavailable"] = "Provisioning could not be read: " + err.Error()
		s.render(w, r, "provisioning.html", data)
		return
	}
	data["TokenSet"] = set
	var groups []scimGroupRow
	for _, g := range st.Groups {
		groups = append(groups, scimGroupRow{Name: g.DisplayName, Means: st.Mapping[g.DisplayName], Members: len(g.Members)})
	}
	// A mapping for a group the provider has not sent yet is still shown:
	// it is what that group will mean when it arrives.
	for name, to := range st.Mapping {
		found := false
		for _, g := range groups {
			if g.Name == name {
				found = true
			}
		}
		if !found {
			groups = append(groups, scimGroupRow{Name: name, Means: to})
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	data["Groups"] = groups
	var users []scimUserRow
	for _, u := range st.Users {
		users = append(users, scimUserRow{Name: u.UserName, Active: u.Active,
			Groups: strings.Join(st.GroupsOf(u.ID), ", "), Holds: strings.Join(st.Grants(u.ID), ", ")})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	data["Users"] = users
	s.render(w, r, "provisioning.html", data)
}

func (s *Server) handleProvisioningAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if p.Limits.ReadOnly {
		http.Error(w, "this token is read-only", http.StatusForbidden)
		return
	}
	if s.SCIM == nil || s.SCIM.Status == nil {
		http.Error(w, "this build has no provisioning", http.StatusServiceUnavailable)
		return
	}
	back := func(key, msg string) {
		http.Redirect(w, r, "/provisioning?"+url.Values{key: {msg}}.Encode(), http.StatusSeeOther)
	}
	group := strings.TrimSpace(r.FormValue("group"))
	var err error
	switch r.FormValue("do") {
	case "map":
		if group == "" {
			back("e", "Name the group, as the identity provider spells it.")
			return
		}
		if err = s.SCIM.Map(group, r.FormValue("to"), p.Name); err == nil {
			back("m", "Members of "+group+" are now "+r.FormValue("to")+" here.")
			return
		}
	case "unmap":
		if err = s.SCIM.Unmap(group, p.Name); err == nil {
			back("m", group+" no longer grants anything here.")
			return
		}
	case "token":
		token, terr := s.SCIM.NewToken(p.Name)
		if terr == nil {
			// Shown in this response and never again, so not a redirect.
			s.renderProvisioning(w, r, p, token)
			return
		}
		err = terr
	case "revoke":
		if err = s.SCIM.RevokeToken(p.Name); err == nil {
			back("m", "The provisioning token is revoked. The identity provider can change nothing until a new one is made.")
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	back("e", err.Error())
}
