// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/handoff"
)

// The inbox: conversations a site's assistant handed to a person.
//
// Read and answered here, by whoever may edit the site's content. A reply is
// signed with the name of the person who sent it in the record, and shown to
// the visitor as coming from the business; the visitor is never told who.
//
// "Suggest a reply" asks the assistant the visitor's last message and puts
// what it finds into the reply box, with its sources, for the person to
// read, change and send. It is never sent on its own. That is the same
// arrangement as everywhere else in this program: a model proposes, and a
// person decides.

// Inbox is what the inbox screens need, supplied by whatever wired this
// server.
type Inbox struct {
	List  func() ([]handoff.Conversation, error)
	Get   func(assistant, id string) (handoff.Conversation, error)
	Reply func(assistant, id, by, text string) error
	Close func(assistant, id, by string) error
	// Suggest drafts a reply from the assistant's own knowledge. It returns
	// the draft and the pages it came from, or why it could not.
	Suggest func(assistant, question string) (string, []string, error)
	// Titles names each assistant, for showing which one a conversation
	// came through.
	Titles func() map[string]string
}

func (s *Server) inboxReady(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return principal{}, false
	}
	// What a visitor said is theirs. It is not kept by the browser.
	w.Header().Set("Cache-Control", "no-store")
	return p, true
}

type inboxRow struct {
	Assistant, Title, ID, Href, Preview, When, State, Tone string
	Count                                                  int
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	p, ok := s.inboxReady(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Title": "Inbox", "Nav": "inbox", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Inbox == nil || s.Inbox.List == nil {
		data["Unavailable"] = "This build was started without a place to keep " +
			"conversations, so there is nothing here."
		s.render(w, r, "inbox.html", data)
		return
	}
	all, err := s.Inbox.List()
	if err != nil {
		data["Unavailable"] = "The conversations could not be read: " + err.Error()
		s.render(w, r, "inbox.html", data)
		return
	}
	titles := map[string]string{}
	if s.Inbox.Titles != nil {
		titles = s.Inbox.Titles()
	}
	now := time.Now()
	var rows []inboxRow
	waiting := 0
	for _, c := range all {
		row := inboxRow{Assistant: c.Assistant, Title: titles[c.Assistant],
			ID: c.ID, Href: "/inbox/" + c.Assistant + "/" + c.ID,
			When: agoText(now.Sub(c.Last)), Count: len(c.Messages)}
		if row.Title == "" {
			row.Title = c.Assistant
		}
		if n := len(c.Messages); n > 0 {
			row.Preview = clipText(c.Messages[n-1].Text, 140)
		}
		switch {
		case c.Waiting():
			row.State, row.Tone = "waiting for you", "warning"
			waiting++
		case c.Closed:
			row.State, row.Tone = "ended", "unknown"
		default:
			row.State, row.Tone = "answered", "good"
		}
		rows = append(rows, row)
	}
	data["Rows"], data["Waiting"] = rows, waiting
	s.render(w, r, "inbox.html", data)
}

func (s *Server) handleConversation(w http.ResponseWriter, r *http.Request) {
	p, ok := s.inboxReady(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/inbox/")
	name, id, _ := strings.Cut(rest, "/")
	if s.Inbox == nil || s.Inbox.Get == nil || !handoff.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	c, err := s.Inbox.Get(name, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.showConversation(w, r, p, c, map[string]any{
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")})
}

// showConversation draws one conversation. A draft reply, when there is one,
// is passed here rather than through the address: what a visitor said and
// what somebody is about to say back do not belong in a URL, which is kept
// in a browser's history and in whatever logs requests.
func (s *Server) showConversation(w http.ResponseWriter, r *http.Request,
	p principal, c handoff.Conversation, extra map[string]any) {

	title := c.Assistant
	if s.Inbox.Titles != nil {
		if t := s.Inbox.Titles()[c.Assistant]; t != "" {
			title = t
		}
	}
	data := map[string]any{"Title": "Conversation", "Nav": "inbox",
		"Principal": p, "C": c, "Through": title,
		"Opened":     c.Opened.Format("Mon 2 Jan 2006 15:04 UTC"),
		"CanSuggest": s.Inbox.Suggest != nil}
	for k, v := range extra {
		data[k] = v
	}
	type line struct {
		N             int
		Who, Text, At string
		Visitor       bool
	}
	var lines []line
	for _, m := range c.Messages {
		who := "Visitor"
		if m.From == handoff.Person {
			who = m.By
		}
		lines = append(lines, line{N: m.N, Who: who, Text: m.Text,
			At: m.At.Format("2 Jan 15:04"), Visitor: m.From == handoff.Visitor})
	}
	data["Lines"] = lines
	s.render(w, r, "conversation.html", data)
}

func (s *Server) handleInboxAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.inboxReady(w, r)
	if !ok {
		return
	}
	if p.Limits.ReadOnly {
		http.Error(w, "this token is read-only", http.StatusForbidden)
		return
	}
	if s.Inbox == nil || s.Inbox.Get == nil {
		http.Error(w, "this build keeps no conversations", http.StatusServiceUnavailable)
		return
	}
	name, id := r.FormValue("assistant"), r.FormValue("id")
	if !handoff.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	c, err := s.Inbox.Get(name, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	page := "/inbox/" + c.Assistant + "/" + c.ID
	back := func(v url.Values) {
		http.Redirect(w, r, page+"?"+v.Encode(), http.StatusSeeOther)
	}
	switch r.FormValue("do") {
	case "reply":
		if s.Inbox.Reply == nil {
			http.NotFound(w, r)
			return
		}
		text := r.FormValue("text")
		if err := s.Inbox.Reply(c.Assistant, c.ID, p.Name, text); err != nil {
			// What they wrote is given back, so a refusal does not lose it.
			s.showConversation(w, r, p, c, map[string]any{"Error": err.Error(),
				"Draft": text, "Status": http.StatusUnprocessableEntity})
			return
		}
		s.audit("handoff.reply", "/ask/"+c.Assistant,
			map[string]string{"by": p.Name, "conversation": c.ID})
		back(url.Values{"m": {"Sent."}})
	case "close":
		if s.Inbox.Close == nil {
			http.NotFound(w, r)
			return
		}
		if err := s.Inbox.Close(c.Assistant, c.ID, p.Name); err != nil {
			back(url.Values{"e": {err.Error()}})
			return
		}
		s.audit("handoff.close", "/ask/"+c.Assistant,
			map[string]string{"by": p.Name, "conversation": c.ID})
		back(url.Values{"m": {"Ended. The visitor sees that it has."}})
	case "suggest":
		if s.Inbox.Suggest == nil {
			http.NotFound(w, r)
			return
		}
		var last string
		for _, m := range c.Messages {
			if m.From == handoff.Visitor {
				last = m.Text
			}
		}
		draft, sources, serr := s.Inbox.Suggest(c.Assistant, last)
		if serr != nil {
			s.showConversation(w, r, p, c, map[string]any{
				"Error": fmt.Sprintf("No suggestion: %v", serr)})
			return
		}
		s.showConversation(w, r, p, c, map[string]any{"Draft": draft,
			"DraftSources": sources, "Message": "A suggestion is in the " +
				"box. Read it, change it, and send it if it is right."})
	default:
		http.Error(w, "nothing to do", http.StatusBadRequest)
	}
}
