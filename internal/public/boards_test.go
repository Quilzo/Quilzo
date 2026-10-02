// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/board"
	"github.com/quilzo/quilzo/internal/member"
	"github.com/quilzo/quilzo/internal/render"
)

// A layout that prints a comments section's posts, so a test can see them.
const boardLayout = `<html><head></head><body><h1>{{ page.title }}</h1>
{% for s in page.sections %}{% if s.comments %}<ol>{% for p in s.comments.posts %}<li>{{ p.name }}: {{ p.body }}</li>{% end %}</ol>{% if s.comments.open %}<form action="/board/{{ s.comments.board }}">{% end %}{% end %}{% end %}
</body></html>`

func boardSite(t *testing.T, moderation string) (*Site, *member.Store, *board.Store) {
	t.Helper()
	st, members := memberSite(t, "open")
	comments := []any{map[string]any{"comments": map[string]any{"board": "talk"}}}
	st = published(t, map[string]any{
		"index":  map[string]any{"title": "Home", "sections": comments},
		"plain":  map[string]any{"title": "No comments here"},
		"lounge": map[string]any{"title": "The lounge", "sections": comments, MembersOnlyField: true},
	})
	st.Layouts = render.OneLayout(boardLayout)
	st.Members = &Members{Store: members, Mode: "open", Party: memberSiteParty}
	posts, err := board.Open(filepath.Join(t.TempDir(), "boards"))
	if err != nil {
		t.Fatal(err)
	}
	set := &board.Set{}
	if err := set.Put(board.Board{Name: "talk", Title: "Talk", Moderation: moderation}); err != nil {
		t.Fatal(err)
	}
	st.Boards = &Boards{Set: func() (*board.Set, error) { return set, nil }, Store: posts}
	return st, members, posts
}

func say(v *visitor, page, body string) *httptest.ResponseRecorder {
	return v.form("/board/talk", url.Values{"thread": {page}, "body": {body}})
}

func TestAMemberPostsUnderAPage(t *testing.T) {
	st, _, posts := boardSite(t, "post")
	anon := &visitor{t: t, st: st, site: "same-origin"}
	before := anon.do(http.MethodGet, "/", nil, "").Header().Get("ETag")

	// Not signed in: sent to sign in, and nothing is stored.
	if w := say(anon, "index", "hello"); w.Code != http.StatusSeeOther ||
		!strings.HasPrefix(w.Header().Get("Location"), "/account?next=") {
		t.Fatalf("an anonymous post answered %d to %q", w.Code, w.Header().Get("Location"))
	}
	if len(posts.Thread("talk", "index", "")) != 0 {
		t.Fatal("an anonymous post was stored")
	}

	ada := &visitor{t: t, st: st, site: "same-origin"}
	signUp(t, ada, newDevice(t), "Ada", "")
	if w := say(ada, "index", "<b>First</b> post"); w.Code != http.StatusSeeOther {
		t.Fatalf("posting: %d %s", w.Code, w.Body.String())
	}
	page := anon.do(http.MethodGet, "/", nil, "")
	if !strings.Contains(page.Body.String(), "Ada: &lt;b&gt;First&lt;/b&gt; post") {
		t.Errorf("the post is not on the page, escaped:\n%s", page.Body.String())
	}
	if page.Header().Get("ETag") == before {
		t.Error("the page's ETag did not change when a post appeared, so a reader would be told nothing changed")
	}
}

// Posts go only where the owner offered a board.
func TestAPostGoesOnlyWhereABoardIsOffered(t *testing.T) {
	st, _, posts := boardSite(t, "post")
	ada := &visitor{t: t, st: st, site: "same-origin"}
	signUp(t, ada, newDevice(t), "Ada", "")
	for _, page := range []string{"plain", "nowhere", "../index", ""} {
		if w := say(ada, page, "hi"); w.Code != http.StatusNotFound {
			t.Errorf("a post to %q answered %d", page, w.Code)
		}
	}
	if w := ada.form("/board/other", url.Values{"thread": {"index"}, "body": {"hi"}}); w.Code != http.StatusNotFound {
		t.Errorf("a post to an undeclared board answered %d", w.Code)
	}
	// A members' page is a thread for members.
	if w := say(ada, "lounge", "inside"); w.Code != http.StatusSeeOther {
		t.Errorf("a member posting in the lounge: %d", w.Code)
	}
	if n := len(posts.ByAuthor(ada.memberID(t))); n != 1 {
		t.Errorf("stored %d posts, want 1", n)
	}
	// And from another site, nothing.
	evil := &visitor{t: t, st: st, cookie: ada.cookie, site: "cross-site"}
	if w := say(evil, "index", "forged"); w.Code != http.StatusForbidden {
		t.Errorf("a cross-site post answered %d", w.Code)
	}
}

func TestAHeldPostWaitsAndItsAuthorCanSeeAndDeleteIt(t *testing.T) {
	st, _, posts := boardSite(t, "pre")
	ada := &visitor{t: t, st: st, site: "same-origin"}
	signUp(t, ada, newDevice(t), "Ada", "")
	w := say(ada, "index", "Dear editor")
	if w.Header().Get("Location") != "/account?done=post-held" {
		t.Fatalf("a held post sent the author to %q", w.Header().Get("Location"))
	}
	if strings.Contains(ada.do(http.MethodGet, "/", nil, "").Body.String(), "Dear editor") {
		t.Error("a held post is on the page")
	}
	account := ada.do(http.MethodGet, "/account", nil, "").Body.String()
	if !strings.Contains(account, "Dear editor") || !strings.Contains(account, "waiting for a person") {
		t.Error("the author's account page does not show the waiting post")
	}
	p := posts.ByAuthor(ada.memberID(t))[0]
	if err := posts.Approve(p.ID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ada.do(http.MethodGet, "/", nil, "").Body.String(), "Dear editor") {
		t.Error("an approved post is not on the page")
	}
	ada.form("/account/post/delete", url.Values{"id": {p.ID}})
	if strings.Contains(ada.do(http.MethodGet, "/", nil, "").Body.String(), "Dear editor") {
		t.Error("the author deleted the post and it is still there")
	}
}

func TestAnotherMemberCannotDeleteYourPost(t *testing.T) {
	st, _, posts := boardSite(t, "post")
	ada := &visitor{t: t, st: st, site: "same-origin"}
	signUp(t, ada, newDevice(t), "Ada", "")
	say(ada, "index", "mine")
	p := posts.ByAuthor(ada.memberID(t))[0]
	bo := &visitor{t: t, st: st, site: "same-origin"}
	signUp(t, bo, newDevice(t), "Bo", "")
	bo.form("/account/post/delete", url.Values{"id": {p.ID}})
	if _, err := posts.Get(p.ID); err != nil {
		t.Error("another member deleted a post")
	}
}

func TestDeletingAnAccountDeletesItsPosts(t *testing.T) {
	st, _, posts := boardSite(t, "post")
	ada := &visitor{t: t, st: st, site: "same-origin"}
	signUp(t, ada, newDevice(t), "Ada", "")
	say(ada, "index", "goodbye")
	id := ada.memberID(t)
	ada.form("/account/delete", url.Values{"confirm": {"delete"}})
	if n := len(posts.ByAuthor(id)); n != 0 {
		t.Errorf("%d posts outlived their author's account", n)
	}
	if strings.Contains((&visitor{t: t, st: st}).do(http.MethodGet, "/", nil, "").Body.String(), "goodbye") {
		t.Error("the deleted account's post is still on the page")
	}
}

// With no accounts, a board shows what is there and offers no form.
func TestWithoutAccountsABoardOffersNoForm(t *testing.T) {
	st, _, _ := boardSite(t, "post")
	st.Members.Mode = "off"
	if body := (&visitor{t: t, st: st}).do(http.MethodGet, "/", nil, "").Body.String(); strings.Contains(body, "<form") {
		t.Error("a form to post was offered on a site with no accounts")
	}
}
