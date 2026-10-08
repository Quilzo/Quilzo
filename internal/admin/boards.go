// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/board"
)

// The Boards screen: where members may write, and what they wrote that is
// waiting for a person. The same operations as `quilzo board`.

// BoardsAdmin is the site's boards and posts, as the admin reaches them.
type BoardsAdmin struct {
	Set     func() (*board.Set, error)
	Save    func(b board.Board, by string) error
	Remove  func(name, by string) error
	Held    func() []board.Post
	Recent  func() []board.Post
	Approve func(id, by string) error
	Delete  func(id, by string) error
}

type postView struct {
	ID, Board, Thread, Href, Name, When, Body string
}

func postViews(ps []board.Post, now time.Time, index string) []postView {
	out := make([]postView, 0, len(ps))
	for _, p := range ps {
		href := "/preview/" + p.Thread
		if p.Thread == index {
			href = "/preview/" + index
		}
		out = append(out, postView{ID: p.ID, Board: p.Board, Thread: p.Thread, Href: href,
			Name: p.Name, When: agoText(now.Sub(p.Created)), Body: p.Body})
	}
	return out
}

func (s *Server) handleBoards(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, auth.AreaBoards) {
		return
	}
	data := map[string]any{"Title": "Boards", "Nav": "boards", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Boards == nil || s.Boards.Set == nil {
		data["Unavailable"] = "This build was started without a place to keep posts."
		s.render(w, r, "boards.html", data)
		return
	}
	set, err := s.Boards.Set()
	if err != nil {
		data["Unavailable"] = "The boards could not be read: " + err.Error()
		s.render(w, r, "boards.html", data)
		return
	}
	now := time.Now()
	data["Boards"] = set.Boards
	data["Held"] = postViews(s.Boards.Held(), now, "index")
	data["Recent"] = postViews(s.Boards.Recent(), now, "index")
	data["CanDeclare"] = auth.CheckCredential(p.Role, p.Scope, p.Limits, auth.ActPublish, "/") == nil &&
		s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed
	s.render(w, r, "boards.html", data)
}

func (s *Server) handleBoardsAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, auth.AreaBoards) {
		return
	}
	if p.Limits.ReadOnly {
		http.Error(w, "this token is read-only", http.StatusForbidden)
		return
	}
	if s.Boards == nil || s.Boards.Set == nil {
		http.Error(w, "this build keeps no posts", http.StatusServiceUnavailable)
		return
	}
	back := func(key, msg string) {
		http.Redirect(w, r, "/boards?"+url.Values{key: {msg}}.Encode(), http.StatusSeeOther)
	}
	var err error
	msg := ""
	switch r.FormValue("do") {
	case "approve":
		err, msg = s.Boards.Approve(r.FormValue("id"), p.Name), "Approved; it is on the page now."
	case "delete":
		err, msg = s.Boards.Delete(r.FormValue("id"), p.Name), "Deleted."
	case "declare", "remove":
		// Opening or closing a place for other people's words is a publish.
		if !s.can(w, r, p, auth.ActPublish, "/") {
			return
		}
		if r.FormValue("do") == "remove" {
			err, msg = s.Boards.Remove(r.FormValue("name"), p.Name), "The board is gone; its posts stay until deleted, and no page shows them."
			break
		}
		max, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("max")))
		b := board.Board{Name: strings.TrimSpace(r.FormValue("name")),
			Title: strings.TrimSpace(r.FormValue("title")), Moderation: r.FormValue("moderation"),
			MaxLength: max, Closed: r.FormValue("closed") == "1"}
		err, msg = s.Boards.Save(b, p.Name), "Saved. A page shows it with a comments section naming "+b.Name+"."
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		back("e", err.Error())
		return
	}
	back("m", msg)
}
