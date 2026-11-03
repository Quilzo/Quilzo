// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/dual"
	"github.com/quilzo/quilzo/internal/scim"
)

// The Provisioning screen: the identity provider's connection, and what
// each of its groups means here. See internal/scim.

// SCIMAdmin is provisioning, as the admin reaches it.
type SCIMAdmin struct {
	// Handler answers the identity provider at /scim/v2.
	Handler http.Handler
	Status  func() (tokenSet bool, st *scim.State, err error)
	Map     func(group, to, by string) error
	Unmap   func(group, by string) error
	// NewToken makes the provisioning token, keeping who made it and how
	// it was approved.
	NewToken    func(made scim.TokenMade) (string, error)
	RevokeToken func(by string) error
	// TokenEnds is when the provisioning token stops working, if one is set.
	TokenEnds func() (time.Time, bool, error)
	// LiveTokens are the provisioning tokens that work now, with who made
	// each and how, for whoever approves a mapping that makes
	// administrators.
	LiveTokens func() ([]scim.LiveToken, error)
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
		"Roles": auth.Roles, "Jobs": auth.Jobs, "AppRoles": s.appRoles()}
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
	if s.SCIM.TokenEnds != nil {
		if ends, ok, terr := s.SCIM.TokenEnds(); terr == nil && ok {
			now := time.Now()
			data["TokenEnds"] = ends.Format("2 January 2006")
			data["TokenEnded"] = !now.Before(ends)
			data["TokenEndsSoon"] = now.Before(ends) && ends.Sub(now) < 30*24*time.Hour
		}
	}
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

// provisioningMakesAdministrators reports whether a group the identity
// provider sends makes its members administrators of anything, or will
// once a mapping waiting for a second administrator is approved.
// Unreadable is taken as yes, which waits rather than hands out a way in.
func (s *Server) provisioningMakesAdministrators() bool {
	_, st, err := s.SCIM.Status()
	if err != nil || st == nil {
		return true
	}
	for _, to := range st.Mapping {
		if dual.MapsToAdministrator(to) {
			return true
		}
	}
	// Or will, once a mapping waiting for a second administrator is
	// approved. Its approver reads the live tokens with the request, and a
	// token made after that was made on one administrator's word and was
	// not among them (scimMakesAdministrators says the same).
	if s.Dual == nil || s.Dual.Store == nil {
		return false
	}
	now := time.Now()
	pend, err := s.Dual.Store.Pending(now)
	if err != nil {
		return true
	}
	for _, r := range pend {
		if r.Kind == dual.Mapping && r.Open(now) {
			return true
		}
	}
	return false
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
		to := r.FormValue("to")
		// A group mapped to an administrator's role or job makes whoever the
		// identity provider puts in it an administrator, so it waits for a
		// second administrator as making one by hand does.
		if dual.MapsToAdministrator(to) {
			apply, msg, perr := s.proposeSecond(p, dual.Mapping,
				fmt.Sprintf("map the identity provider's group %q to %s, making its members administrators", group, to),
				dual.MappingChange{Group: group, To: to}, "")
			if perr != nil {
				back("e", perr.Error())
				return
			}
			if !apply {
				back("m", msg)
				return
			}
		}
		if err = s.SCIM.Map(group, to, p.Name); err == nil {
			msg := "Members of " + group + " are now " + to + " here."
			if dual.MapsToAdministrator(to) {
				msg += " " + s.mappedTokens()
			}
			back("m", msg)
			return
		}
	case "unmap":
		if err = s.SCIM.Unmap(group, p.Name); err == nil {
			back("m", group+" no longer grants anything here.")
			return
		}
	case "token":
		// While a group makes administrators, whoever holds this token
		// makes anybody one by putting them in it, so making it waits for a
		// second administrator, as an administrator's token does, and is
		// received by whoever asked (on People). It did not, and either of
		// two administrators alone made mallory an administrator through
		// the identity provider's door.
		made := scim.TokenMade{By: p.Name, Approval: scim.Unasked}
		if s.provisioningMakesAdministrators() {
			apply, msg, perr := s.proposeSecond(p, dual.SCIMToken,
				"a new provisioning token, which makes administrators through a mapped group",
				dual.SCIMTokenChange{}, "")
			if perr != nil {
				back("e", perr.Error())
				return
			}
			if !apply {
				back("m", msg)
				return
			}
			made.Approval = scim.Alone
		}
		token, terr := s.SCIM.NewToken(made)
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
