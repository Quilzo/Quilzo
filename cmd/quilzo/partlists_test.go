// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/site"
)

// partStore is a store with a page under /blog and one under /legal, each
// changed in the draft since it was published, in a commit of its own, and
// each claimed by somebody.
func partStore(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	root := connectStore(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index":       map[string]any{"title": "Home"},
		"blog/first":  map[string]any{"title": "First post"},
		"legal/terms": map[string]any{"title": "Terms of sale"},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"blog/first", "legal/terms"} {
		pages[page] = map[string]any{"title": "Changed " + page}
		if _, err := site.SaveDraft(s, pages, "edit "+page, "test"); err != nil {
			t.Fatal(err)
		}
	}
	locks := &collab.Locks{}
	locks.Claim("blog/first", "someone", "", time.Now())
	locks.Claim("legal/terms", "someone", "", time.Now())
	if err := saveJSON(locksPath(root), locks); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"grant", "boss", "admin"}); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "boss")
	for _, g := range [][]string{
		{"grant", "bea", "reader", "--on", "/blog"},
		{"grant", "sam", "analyst", "--for", "30d"},
	} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatalf("%v: %v", g, err)
		}
	}
	return root
}

// confinedTo presents a token for who, confined to on, as the caller.
func confinedTo(t *testing.T, root, who, on string) {
	t.Helper()
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("t", who, auth.RoleAdmin, on, time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", secret)
}

// Somebody granted part of the site, or holding a token confined to it, is
// shown the lists of that part, and only of that part.
//
// diff, log, find, lock list, checked list and note list asked for view on
// "/", which a grant on /blog does not cover and a token issued `--on /blog`
// does not reach, so they were refused every one, though diff, checked list
// and note list leave out each page the caller may not read. Now they are
// asked whether the caller may read somewhere in the site's content, and
// log, find and lock list leave out what is not theirs to read, as the
// others did.
func TestPartOfTheSiteIsListedToWhoeverHoldsIt(t *testing.T) {
	root := partStore(t)
	lists := [][]string{{"diff"}, {"log"}, {"find", "terms"}, {"lock", "list"}, {"locks", "list"},
		{"lock"}, {"checked", "list"}, {"checked", "due"}, {"checked"}, {"note", "list"},
		{"notes", "list"}, {"note"}}

	for _, who := range []struct{ name, on string }{{"bea", "/"}, {"boss", "/blog"}} {
		confinedTo(t, root, who.name, who.on)
		for _, c := range lists {
			if err := authoriseCommand(root, c[0], c[1:]); err != nil {
				t.Errorf("%s on %s may not run %v: %v", who.name, who.on, c, err)
			}
		}
		said := map[string]string{}
		for name, run := range map[string]func() error{
			"diff":      func() error { return cmdDiff(root) },
			"log":       func() error { return cmdLog(root, nil) },
			"find":      func() error { return cmdFind(root, []string{"changed"}) },
			"lock list": func() error { return lockList(root) },
		} {
			doc, err := jsonAnswer(t, run)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			said[name] = fmt.Sprint(doc)
		}
		for name, got := range said {
			if strings.Contains(got, "legal") {
				t.Errorf("%s on %s is shown /legal by %s: %s", who.name, who.on, name, got)
			}
			if !strings.Contains(got, "blog/first") {
				t.Errorf("%s on %s is not shown /blog by %s: %s", who.name, who.on, name, got)
			}
		}
	}

	// Somebody with nothing in the content is refused them, as before.
	confinedTo(t, root, "sam", "/")
	for _, c := range lists {
		if err := authoriseCommand(root, c[0], c[1:]); err == nil {
			t.Errorf("the analyst may run %v", c)
		}
	}
}

// A reader of the whole site who is denied part of it is shown no commit to
// that part by the log, as diff, find and lock list show them nothing of it.
//
// The log showed its whole history to whoever was let read "/", and a deny
// on /legal does not reach "/", so a reader denied /legal was listed each
// commit to the terms by its message and its author, which every other
// list left out.
func TestALogLeavesOutWhatADenyKeepsFromTheReader(t *testing.T) {
	root := partStore(t)
	for _, g := range [][]string{{"grant", "rex", "reader"}, {"deny", "rex", "reader", "--on", "/legal"}} {
		if err := cmdAuth(root, g); err != nil {
			t.Fatalf("%v: %v", g, err)
		}
	}
	confinedTo(t, root, "rex", "/")
	doc, err := jsonAnswer(t, func() error { return cmdLog(root, nil) })
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(doc)
	if strings.Contains(got, "legal") {
		t.Errorf("a reader denied /legal is listed its commits: %s", got)
	}
	if !strings.Contains(got, "edit blog/first") {
		t.Errorf("a reader denied /legal is not listed the commit to the blog: %s", got)
	}

	// Denied only writing there, they read it, and are listed it all.
	if err := cmdAuth(root, []string{"grant", "ada", "reader"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAuth(root, []string{"deny", "ada", "author", "--on", "/legal"}); err != nil {
		t.Fatal(err)
	}
	confinedTo(t, root, "ada", "/")
	doc, err = jsonAnswer(t, func() error { return cmdLog(root, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(doc); !strings.Contains(got, "edit legal/terms") || !strings.Contains(got, "message:first") {
		t.Errorf("a reader denied only writing /legal is not listed the whole history: %s", got)
	}
}
