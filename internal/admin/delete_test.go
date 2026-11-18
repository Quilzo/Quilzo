// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"

	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/site"
)

// Removing a page through the interface.
//
// The capability existed on the command line and not in the browser, and no
// test noticed for the same reason nobody did: every test here opens the
// screens that exist and checks they work. A screen that was never built has
// nothing to fail. See TestEveryCommandHasAnInterface in this package for the
// check that now asks the question the other way round.

func TestRemovingAPageTakesItOutOfTheDraft(t *testing.T) {
	srv, token := setup(t)

	if _, err := site.PagesAt(srv.Store, site.RefDraft); err != nil {
		t.Fatal(err)
	}
	w := postForm(t, srv, "/page/delete", token, "name=about")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("removing a page answered %d\n%s", w.Code,
			firstLines(w.Body.String(), 6))
	}
	pages := mustPages(t, srv)
	if _, there := pages["about"]; there {
		t.Fatal("the page is still in the draft")
	}
	if _, there := pages["index"]; !there {
		t.Fatal("removing one page removed another")
	}
}

// Nothing is erased, which is what the store guarantees and what the screen
// claims. The previous commit still has the page.
func TestARemovedPageIsStillInTheHistory(t *testing.T) {
	srv, token := setup(t)
	before := srv.Store.GetRef(site.RefDraft)

	if w := postForm(t, srv, "/page/delete", token, "name=about"); w.Code != http.StatusSeeOther {
		t.Fatalf("removing answered %d", w.Code)
	}
	old, err := site.PagesAt(srv.Store, before)
	if err != nil {
		t.Fatal(err)
	}
	if _, there := old["about"]; !there {
		t.Fatal("the commit that had the page no longer has it, so this store " +
			"is not append-only after all")
	}
}

// A page a menu points at cannot simply vanish.
func TestRemovingAPageAMenuPointsAtIsRefused(t *testing.T) {
	srv, token := setup(t)

	set := &menu.Set{}
	if err := set.Add(menu.Menu{Name: "main", Label: "Main", Items: []menu.Item{
		{ID: "a", Label: "About us", Kind: menu.Page, Target: "about"},
	}}); err != nil {
		t.Fatal(err)
	}
	srv.Structure = &Structure{
		Menus:     func() (*menu.Set, error) { return set, nil },
		SaveMenus: func(*menu.Set) error { return nil },
	}

	w := postForm(t, srv, "/page/delete", token, "name=about")
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "e=") {
		t.Fatalf("a page a menu points at was removed anyway: %q", loc)
	}
	// The refusal has to name the entry, not just say that something objects.
	if !strings.Contains(loc, "About") || !strings.Contains(loc, "main") {
		t.Errorf("the refusal does not say which menu entry: %q", loc)
	}
	if _, there := mustPages(t, srv)["about"]; !there {
		t.Fatal("the page was removed despite the refusal")
	}
}

// Removing something that is not there says so rather than committing nothing.
func TestRemovingAPageThatIsNotThere(t *testing.T) {
	srv, token := setup(t)
	before := srv.Store.GetRef(site.RefDraft)

	w := postForm(t, srv, "/page/delete", token, "name=never-existed")
	if !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Error("removing a nonexistent page reported success")
	}
	if srv.Store.GetRef(site.RefDraft) != before {
		t.Error("a commit was made for a removal that did not happen")
	}
}

// A reader may not remove pages.
func TestRemovingAPageNeedsPermissionToEdit(t *testing.T) {
	srv, _ := setup(t)

	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "onlooker", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	token, _, err := ts.IssueSession("t", "onlooker", auth.RoleReader, "/",
		time.Hour, auth.RoleReader, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	srv.Policy, srv.Tokens = pol, ts

	w := postForm(t, srv, "/page/delete", token, "name=about")
	if w.Code != http.StatusForbidden {
		t.Fatalf("a reader removing a page answered %d, want 403", w.Code)
	}
	if _, there := mustPages(t, srv)["about"]; !there {
		t.Fatal("a reader removed a page")
	}
}

// A person's change cannot say a machine wrote it, saved or removed here as
// on the command line.
//
// The approval gate reads who wrote a change from its message
// (collab.MachineWrote), and both the editor's message and a removal's took
// any: a page saved with "mcp: write about" was read as a change the
// person's client made for them, which is not what happened. Only the
// machines write those prefixes, and they write them themselves.
func TestAPersonsChangeHereCannotSayAMachineWroteIt(t *testing.T) {
	srv, token := setup(t)
	before := srv.Store.GetRef(site.RefDraft)

	w := save(t, srv, token, url.Values{"__name": {"about"}, "title": {"About"}, "body": {"b"},
		"__message": {"mcp: write about"}})
	if after := srv.Store.GetRef(site.RefDraft); after != before {
		c, _ := srv.Store.GetCommit(after)
		t.Fatalf("a save in the editor was recorded as a machine's: %q (%d)", c.Message, w.Code)
	}
	postForm(t, srv, "/page/delete", token, "name=about&message="+url.QueryEscape("agent: tidy wrote about for lee"))
	if after := srv.Store.GetRef(site.RefDraft); after != before {
		c, _ := srv.Store.GetCommit(after)
		t.Fatalf("a removal in the editor was recorded as a machine's: %q", c.Message)
	}

	// And a message of the person's own is saved as it was.
	save(t, srv, token, url.Values{"__name": {"about"}, "title": {"About"}, "body": {"b"},
		"__message": {"tidy the about page"}})
	if c, err := srv.Store.GetCommit(srv.Store.GetRef(site.RefDraft)); err != nil || c.Message != "tidy the about page" {
		t.Errorf("an ordinary message was not saved: %q %v", c.Message, err)
	}
}
