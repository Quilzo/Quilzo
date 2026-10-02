// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/board"
	"github.com/quilzo/quilzo/internal/throttle"
)

// What members write under a page. See internal/board.
//
// Posting is the second thing a visitor can write on this server, after a
// form submission, and it is held to more: the writer must be a signed-in
// member, the request must come from this site's own page, the page must be
// published and must carry a comments section for that board, and each
// member is rate limited. A post is text, escaped where it is shown.

// Boards gives the public server its boards. Nil means there are none.
type Boards struct {
	Set   func() (*board.Set, error)
	Store *board.Store
	// Limit bounds posts per member.
	Limit *throttle.Limiter
	// Audit records that a member posted, never what.
	Audit func(action, member, board, page string, ok bool)
}

func (st *Site) boardsOn() bool {
	return st.Boards != nil && st.Boards.Store != nil && st.Boards.Set != nil
}

// threadData is a board's thread on one page, for the renderer: the same
// for everybody who looks.
func (st *Site) threadData(name, page string) map[string]any {
	if !st.boardsOn() {
		return nil
	}
	set, err := st.Boards.Set()
	if err != nil {
		return nil
	}
	b, ok := set.Get(name)
	if !ok {
		return nil
	}
	var posts []any
	for _, post := range st.Boards.Store.Thread(name, page, "") {
		row := map[string]any{"name": post.Name, "body": post.Body,
			"created": post.Created.Format(time.RFC3339)}
		if !post.Edited.IsZero() {
			row["edited"] = true
		}
		posts = append(posts, row)
	}
	return map[string]any{"title": b.Title, "posts": posts,
		"open": !b.Closed && st.membersOn(), "held": b.Moderation == "pre",
		"live": true}
}

// commentsOn names the boards a page shows.
func commentsOn(body any) []string {
	m, ok := body.(map[string]any)
	if !ok {
		return nil
	}
	sections, _ := m["sections"].([]any)
	var out []string
	for _, s := range sections {
		sec, _ := s.(map[string]any)
		if c, ok := sec["comments"].(map[string]any); ok {
			if name, _ := c["board"].(string); name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}

// threadsTag mixes what a page's threads say into its ETag, so a new post
// is not answered with "not modified".
func (st *Site) threadsTag(tag, page string, boards []string) string {
	if !st.boardsOn() || len(boards) == 0 {
		return tag
	}
	h := sha256.New()
	h.Write([]byte(tag))
	for _, b := range boards {
		h.Write([]byte("\x00" + b + "\x00" + st.Boards.Store.Version(b, page)))
	}
	return `"` + hex.EncodeToString(h.Sum(nil))[:32] + `"`
}

// post receives one post: POST /board/NAME with the thread and the body.
func (st *Site) post(w http.ResponseWriter, r *http.Request) {
	if !st.boardsOn() || !st.membersOn() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	if !st.sameSite(r) {
		http.Error(w, "this can only be done from this site's own pages", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that could not be read", http.StatusBadRequest)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/board/")
	page := r.PostFormValue("thread")
	back := "/" + page
	if page == st.indexName() {
		back = "/"
	}

	m, signedIn := st.signedIn(r)
	if !signedIn {
		http.Redirect(w, r, "/account?next="+url.QueryEscape(back+"#comments"), http.StatusSeeOther)
		return
	}
	set, err := st.Boards.Set()
	if err != nil {
		http.Error(w, "this site's boards could not be read", http.StatusInternalServerError)
		return
	}
	b, ok := set.Get(name)
	if !ok || !st.pageShowsBoard(page, name, true) {
		// Only a published page that shows this board is a thread. A post
		// to anything else would be stored where nobody could see it, or
		// worse, somewhere the owner never offered.
		http.NotFound(w, r)
		return
	}
	if l := st.Boards.Limit; l != nil {
		subj := throttle.Subject{Source: "member:" + m.ID}
		if d := l.Check(subj); !d.Allowed {
			http.Error(w, "you have posted a lot in a short time; wait a minute", http.StatusTooManyRequests)
			return
		}
		l.Spend(subj)
	}
	p, err := st.Boards.Store.Add(b, page, m.ID, m.Name, r.PostFormValue("body"))
	if st.Boards.Audit != nil {
		st.Boards.Audit("board.post", m.ID, name, page, err == nil)
	}
	if err != nil {
		st.renderAccount(w, accountView{Member: m, SignedIn: true, Problem: err.Error() + "."},
			http.StatusUnprocessableEntity)
		return
	}
	if p.State == board.Held {
		http.Redirect(w, r, "/account?done=post-held", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"#comments", http.StatusSeeOther)
}

// pageShowsBoard reports whether a published page carries a comments
// section for a board. Members' pages count when the poster is a member.
func (st *Site) pageShowsBoard(page, name string, member bool) bool {
	pages, _, err := st.pages()
	if err != nil {
		return false
	}
	body, ok := pages[page]
	if !ok && member {
		body, _, ok = st.memberPage(page)
	}
	if !ok {
		return false
	}
	for _, b := range commentsOn(body) {
		if b == name {
			return true
		}
	}
	return false
}
