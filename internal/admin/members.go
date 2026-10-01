// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/member"
)

// The Members screen: the site's own accounts, as `quilzo member` shows
// them. Staff see that an account exists and can stop it signing in, erase
// it, or invite somebody; nothing here can sign in as a member, because
// nothing stored would let anybody.

// MembersAdmin is the site's accounts, as the admin reaches them.
type MembersAdmin struct {
	// Mode is site.members: off, open or invite.
	Mode     func() string
	List     func() ([]member.Member, error)
	Sessions func(id string) int
	// The changes, each recorded under who made it.
	SetDisabled func(id string, disabled bool, by string) error
	Remove      func(id, by string) error
	Invite      func(by, note string) (string, member.Invite, error)
	Invites     func() []member.Invite
	Revoke      func(hash, by string) error
}

type memberRow struct {
	ID, Name, Joined, Seen string
	Passkeys, Sessions     int
	Disabled               bool
}

type inviteRow struct{ Hash, Short, By, Note, Until string }

func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	s.renderMembers(w, r, p, "")
}

func (s *Server) renderMembers(w http.ResponseWriter, r *http.Request, p principal, code string) {
	data := map[string]any{"Title": "Members", "Nav": "members", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"), "Code": code}
	if s.Members == nil || s.Members.List == nil {
		data["Unavailable"] = "This build was started without a place to keep accounts."
		s.render(w, r, "members.html", data)
		return
	}
	data["Mode"] = s.Members.Mode()
	all, err := s.Members.List()
	if err != nil {
		data["Unavailable"] = "The accounts could not be read: " + err.Error()
		s.render(w, r, "members.html", data)
		return
	}
	now := time.Now()
	var rows []memberRow
	for _, m := range all {
		rows = append(rows, memberRow{ID: m.ID, Name: m.Name,
			Joined: m.Created.Format("2 Jan 2006"), Seen: agoText(now.Sub(m.LastSeen)),
			Passkeys: len(m.Passkeys), Sessions: s.Members.Sessions(m.ID), Disabled: m.Disabled})
	}
	data["Rows"] = rows
	var invites []inviteRow
	for _, inv := range s.Members.Invites() {
		invites = append(invites, inviteRow{Hash: inv.Hash, Short: inv.Hash[:12], By: inv.By,
			Note: inv.Note, Until: inv.Expires.Format("2 Jan 2006")})
	}
	data["Invites"] = invites
	s.render(w, r, "members.html", data)
}

func (s *Server) handleMembersAct(w http.ResponseWriter, r *http.Request) {
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
	if s.Members == nil || s.Members.List == nil {
		http.Error(w, "this build keeps no accounts", http.StatusServiceUnavailable)
		return
	}
	back := func(key, msg string) {
		http.Redirect(w, r, "/members?"+url.Values{key: {msg}}.Encode(), http.StatusSeeOther)
	}
	id := r.FormValue("id")
	var err error
	switch r.FormValue("do") {
	case "disable":
		err = s.Members.SetDisabled(id, true, p.Name)
		if err == nil {
			back("m", "Disabled. Its sessions are ended and it cannot sign in.")
			return
		}
	case "enable":
		err = s.Members.SetDisabled(id, false, p.Name)
		if err == nil {
			back("m", "Enabled. It can sign in again.")
			return
		}
	case "remove":
		if r.FormValue("confirm") != "remove" {
			back("e", "Nothing was removed: type remove to confirm.")
			return
		}
		err = s.Members.Remove(id, p.Name)
		if err == nil {
			back("m", "Removed, with its passkeys, recovery codes and sessions.")
			return
		}
	case "invite":
		code, _, ierr := s.Members.Invite(p.Name, r.FormValue("note"))
		if ierr == nil {
			// Shown in this response and never again, so not a redirect.
			s.renderMembers(w, r, p, code)
			return
		}
		err = ierr
	case "revoke":
		err = s.Members.Revoke(r.FormValue("hash"), p.Name)
		if err == nil {
			back("m", "The invitation is withdrawn.")
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	back("e", err.Error())
}
