// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// shareDesign is a design of one layout, for rendering a shared page.
func shareDesign(t *testing.T) *Design {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "page.html"),
		[]byte(`<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head><body><h1>{{ page.title }}</h1></body></html>`), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := loadDesign(dir)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A link shows the page as the draft was when it was shared, and nothing
// once it has expired or been revoked; it is to a page that exists, and
// lives a month at the most.
func TestALinkShowsThePageAsItWasShared(t *testing.T) {
	root := demoStore(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	pages["offer"] = map[string]any{"title": "The first offer"}
	if _, err := site.SaveDraft(s, pages, "an offer", "test"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sh, err := newShare(root, s, "offer", "editor", 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reShareID.MatchString(sh.ID) {
		t.Fatalf("id %q", sh.ID)
	}
	// Changed after it was shared: the link still shows what was shared.
	pages["offer"] = map[string]any{"title": "A second offer, not for them"}
	if _, err := site.SaveDraft(s, pages, "changed", "test"); err != nil {
		t.Fatal(err)
	}
	d := shareDesign(t)
	got, ok := renderShared(root, d, sh.ID, now.Add(time.Hour))
	if !ok || !strings.Contains(got, "The first offer") || strings.Contains(got, "second offer") {
		t.Fatalf("%v %s", ok, got)
	}
	if _, ok := renderShared(root, d, sh.ID, now.Add(8*24*time.Hour)); ok {
		t.Error("shown after it expired")
	}
	if _, ok := renderShared(root, d, strings.Repeat("0", 32), now); ok {
		t.Error("a link nobody made")
	}
	if _, ok := renderShared(root, d, "../shares", now); ok {
		t.Error("not an id")
	}
	// Revoked for another page: not found, still live.
	if _, err := revokeShare(root, "index", sh.ID, now); err == nil {
		t.Error("revoked through another page")
	}
	if _, ok := renderShared(root, d, sh.ID, now); !ok {
		t.Fatal("gone after a refused revoke")
	}
	if _, err := revokeShare(root, "offer", sh.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := renderShared(root, d, sh.ID, now); ok {
		t.Error("shown after it was revoked")
	}
	if _, err := newShare(root, s, "offer", "editor", MaxShareDays+1, now); err == nil {
		t.Error("a link for longer than a month")
	}
	if _, err := newShare(root, s, "nowhere", "editor", 1, now); err == nil {
		t.Error("a link to a page there is not")
	}
	info, err := os.Stat(sharesPath(root))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
}

// The editor's hooks list a page's links and revoke only that page's.
func TestTheEditorSharesThroughTheCommand(t *testing.T) {
	root := demoStore(t)
	c := sharesCapability(root)
	link, err := c.Create("index", "editor", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(link.URL, "/shared/"+link.ID) || !link.Live {
		t.Fatalf("%+v", link)
	}
	got, _ := c.For("index")
	if len(got) != 1 || got[0].ID != link.ID {
		t.Fatalf("%+v", got)
	}
	if other, _ := c.For("about"); len(other) != 0 {
		t.Fatalf("another page's links: %+v", other)
	}
	if err := c.Revoke("about", link.ID, "editor"); err == nil {
		t.Error("revoked through another page")
	}
	if err := c.Revoke("index", "not-an-id", "editor"); err == nil {
		t.Error("revoked something that is not a link")
	}
	if err := c.Revoke("index", link.ID, "editor"); err != nil {
		t.Fatal(err)
	}
	got, _ = c.For("index")
	if len(got) != 1 || got[0].Live {
		t.Fatalf("an ended link is listed a while, as ended: %+v", got)
	}
}
