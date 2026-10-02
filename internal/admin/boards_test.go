// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/board"
)

func wireBoards(t *testing.T, srv *Server) (*board.Set, *board.Store) {
	t.Helper()
	posts, err := board.Open(filepath.Join(t.TempDir(), "boards"))
	if err != nil {
		t.Fatal(err)
	}
	set := &board.Set{}
	srv.Boards = &BoardsAdmin{
		Set:     func() (*board.Set, error) { return set, nil },
		Save:    func(b board.Board, _ string) error { return set.Put(b) },
		Remove:  func(n, _ string) error { set.Remove(n); return nil },
		Held:    posts.Held,
		Recent:  func() []board.Post { return posts.Recent(50) },
		Approve: func(id, _ string) error { return posts.Approve(id) },
		Delete:  func(id, _ string) error { return posts.Remove(id, "") },
	}
	return set, posts
}

func TestTheBoardsScreenModeratesWhatMembersWrote(t *testing.T) {
	srv, token := setup(t)
	set, posts := wireBoards(t, srv)
	postForm(t, srv, "/boards/act", token, "do=declare&name=letters&title=Letters&moderation=pre&max=0")
	b, ok := set.Get("letters")
	if !ok || b.Moderation != "pre" {
		t.Fatalf("declaring a board: %+v", set)
	}
	p, _ := posts.Add(b, "index", "m1", "Ada", "Dear <editor>")
	body := get(t, srv, "/boards", token).Body.String()
	if !strings.Contains(body, "Dear &lt;editor&gt;") {
		t.Fatal("a waiting post is not shown, escaped, to the moderator")
	}
	postForm(t, srv, "/boards/act", token, "do=approve&id="+p.ID)
	if got, _ := posts.Get(p.ID); got.State != board.Visible {
		t.Error("approving did not show the post")
	}
	postForm(t, srv, "/boards/act", token, "do=delete&id="+p.ID)
	if _, err := posts.Get(p.ID); err == nil {
		t.Error("deleting did not delete")
	}
}

// An author moderates; opening a board is a publish.
func TestAnAuthorModeratesButCannotOpenABoard(t *testing.T) {
	author, atoken := asRole(t, auth.RoleAuthor)
	set, posts := wireBoards(t, author)
	_ = set.Put(board.Board{Name: "talk", Title: "Talk", Moderation: "pre"})
	b, _ := set.Get("talk")
	p, _ := posts.Add(b, "index", "m1", "Ada", "hello")
	postForm(t, author, "/boards/act", atoken, "do=approve&id="+p.ID)
	if got, _ := posts.Get(p.ID); got.State != board.Visible {
		t.Error("an author could not approve a post")
	}
	postForm(t, author, "/boards/act", atoken, "do=declare&name=open-mic&title=Open&moderation=post")
	if _, ok := set.Get("open-mic"); ok {
		t.Error("an author opened a board")
	}
}
