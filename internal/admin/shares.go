// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
)

// Links to a draft page for somebody with no account (cmd/quilzo
// sharecmd.go): made, listed and revoked from the editor.

// Shares are the hooks the editor uses.
type Shares struct {
	// Create shares a page of the draft as it is now, for days: its link.
	Create func(page, by string, days int) (ShareLink, error)
	// For lists a page's links, newest first.
	For func(page string) ([]ShareLink, error)
	// Revoke ends a link to page; one to another page is not found.
	Revoke func(page, id, by string) error
}

// ShareLink is one link, as the editor shows it.
type ShareLink struct {
	ID, URL, By string
	Expires     time.Time
	Live        bool
}

// sharesFor are a page's links, for the editor; nil when there is no way
// to share.
func (s *Server) sharesFor(page string) []ShareLink {
	if s.Shares == nil || s.Shares.For == nil {
		return nil
	}
	links, _ := s.Shares.For(page)
	return links
}

func (s *Server) handleShares(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	page := strings.TrimSpace(r.FormValue("page"))
	back := func(key, msg string) {
		http.Redirect(w, r, "/page/"+page+"?"+key+"="+url.QueryEscape(msg)+"#share", http.StatusSeeOther)
	}
	if page == "" || s.Shares == nil || s.Shares.Create == nil || s.Shares.Revoke == nil {
		back("e", "this build cannot share a draft")
		return
	}
	if p.Limits.ReadOnly {
		back("e", "a read-only session shares nothing")
		return
	}
	switch r.FormValue("op") {
	case "share":
		// Showing a draft to somebody outside: whoever may publish it.
		if !s.can(w, r, p, auth.ActPublish, "/"+page) {
			return
		}
		days, _ := strconv.Atoi(r.FormValue("days"))
		link, err := s.Shares.Create(page, p.Name, days)
		if err != nil {
			back("e", err.Error())
			return
		}
		s.audit("share.created", "/"+page, map[string]string{"by": p.Name, "share": link.ID, "days": strconv.Itoa(days)})
		back("m", "Shared until "+link.Expires.Local().Format("2 Jan 15:04")+": "+link.URL)
	case "revoke":
		if !s.can(w, r, p, auth.ActEditDraft, "/"+page) {
			return
		}
		id := strings.TrimSpace(r.FormValue("id"))
		if err := s.Shares.Revoke(page, id, p.Name); err != nil {
			back("e", err.Error())
			return
		}
		s.audit("share.revoked", "/"+page, map[string]string{"by": p.Name, "share": id})
		back("m", "Revoked. The link shows nothing from now on.")
	default:
		back("e", "nothing asked")
	}
}
