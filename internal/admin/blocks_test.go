// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
)

func sectionsDo(t *testing.T, srv *Server, token string, v url.Values) (int, string) {
	t.Helper()
	v.Set("base", srv.Store.GetRef(site.RefDraft))
	return postFormLoc(t, srv, token, "/sections/edit", v)
}

// refused reports whether a redirect carries an error to show.
func refused(loc string) bool {
	u, err := url.Parse(loc)
	return err == nil && u.Query().Get("e") != ""
}

// A page made a block from the Sections screen is offered on the others,
// reused there, listed with where it is used, and cannot be deleted or
// made a page again while a page reuses it.
func TestABlockIsMadeAndReusedFromTheSectionsScreen(t *testing.T) {
	srv, token := setup(t)
	if _, loc := sectionsDo(t, srv, token, url.Values{"page": {"about"}, "do": {"block"}}); refused(loc) {
		t.Fatalf("not made a block: %s", loc)
	}
	pages, _ := site.PagesAt(srv.Store, site.RefDraft)
	if !site.IsBlock(pages["about"]) {
		t.Fatal("about is not a block")
	}
	if _, loc := sectionsDo(t, srv, token, url.Values{"page": {"index"}, "do": {"block"}}); !refused(loc) {
		t.Fatal("the home page made a block")
	}
	if body := get(t, srv, "/sections?page=index", token).Body.String(); !strings.Contains(body, "Reuse a block") ||
		!strings.Contains(body, "<option>about</option>") {
		t.Fatal("the block is not offered")
	}
	if _, loc := sectionsDo(t, srv, token, url.Values{"page": {"index"}, "do": {"reuse"}, "block": {"about"}}); refused(loc) {
		t.Fatalf("not reused: %s", loc)
	}
	if _, loc := sectionsDo(t, srv, token, url.Values{"page": {"about"}, "do": {"reuse"}, "block": {"index"}}); !refused(loc) {
		t.Fatal("a page that is not a block reused")
	}
	pages, _ = site.PagesAt(srv.Store, site.RefDraft)
	if site.BlockUses(pages)["about"][0] != "index" {
		t.Fatalf("%v", site.BlockUses(pages))
	}
	body := get(t, srv, "/sections?page=about", token).Body.String()
	if !strings.Contains(body, "reusable block") || !strings.Contains(body, `href="/sections?page=index"`) {
		t.Fatal("the block does not say where it is used")
	}
	if body := get(t, srv, "/sections?page=index", token).Body.String(); !strings.Contains(body, "Edit the block") {
		t.Fatal("the reuse is not listed as the block")
	}
	if _, loc := sectionsDo(t, srv, token, url.Values{"page": {"about"}, "do": {"unblock"}}); !refused(loc) {
		t.Fatal("made a page again while reused")
	}
	w := postForm(t, srv, "/page/delete", token, url.Values{"page": {"about"}, "name": {"about"},
		"base": {srv.Store.GetRef(site.RefDraft)}}.Encode())
	pages, _ = site.PagesAt(srv.Store, site.RefDraft)
	if _, there := pages["about"]; !there {
		t.Fatalf("a block a page reuses was deleted: %d", w.Code)
	}
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "reuses it as a block") {
		t.Fatalf("the refusal does not say why: %d %s", w.Code, loc)
	}
}
