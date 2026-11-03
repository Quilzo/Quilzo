// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/out"
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
	sh, secret, err := newShare(root, s, "offer", "editor", 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reShareID.MatchString(secret) || sh.ID != shareIDFor(secret) {
		t.Fatalf("secret %q, id %q", secret, sh.ID)
	}
	// Changed after it was shared: the link still shows what was shared.
	pages["offer"] = map[string]any{"title": "A second offer, not for them"}
	if _, err := site.SaveDraft(s, pages, "changed", "test"); err != nil {
		t.Fatal(err)
	}
	d := shareDesign(t)
	got, ok := renderShared(root, d, secret, now.Add(time.Hour))
	if !ok || !strings.Contains(got, "The first offer") || strings.Contains(got, "second offer") {
		t.Fatalf("%v %s", ok, got)
	}
	if _, ok := renderShared(root, d, secret, now.Add(8*24*time.Hour)); ok {
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
	if _, ok := renderShared(root, d, secret, now); !ok {
		t.Fatal("gone after a refused revoke")
	}
	if _, err := revokeShare(root, "offer", sh.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := renderShared(root, d, secret, now); ok {
		t.Error("shown after it was revoked")
	}
	if _, _, err := newShare(root, s, "offer", "editor", MaxShareDays+1, now); err == nil {
		t.Error("a link for longer than a month")
	}
	if _, _, err := newShare(root, s, "nowhere", "editor", 1, now); err == nil {
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
	// The address carries the secret, this once; the id is its digest.
	secret := link.URL[strings.LastIndex(link.URL, "/")+1:]
	if !strings.Contains(link.URL, "/shared/") || shareIDFor(secret) != link.ID || !link.Live {
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

// A shared draft's menus are the published site's: a link to one draft
// page does not show the names of the others.
func TestASharedDraftShowsOnlyPublishedMenus(t *testing.T) {
	root := demoStore(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, _ := site.PagesAt(s, site.RefDraft)
	pages["secret-launch"] = map[string]any{"title": "Secret launch"}
	pages["offer"] = map[string]any{"title": "The offer"}
	if _, err := site.SaveDraft(s, pages, "drafts", "test"); err != nil {
		t.Fatal(err)
	}
	set := `{"menus":[{"name":"main","items":[{"id":"a","label":"Secret launch","kind":"page","target":"secret-launch"},` +
		`{"id":"b","label":"Home","kind":"page","target":"index"}]}]}`
	if err := os.WriteFile(menuPath(root), []byte(set), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tpl := `<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head><body>` +
		`<nav>{% for m in menus.main %}<a href="{{ m.href }}">{{ m.label }}</a>{% end %}</nav><h1>{{ page.title }}</h1></body></html>`
	if err := os.WriteFile(filepath.Join(dir, "page.html"), []byte(tpl), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := loadDesign(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, secret, err := newShare(root, s, "offer", "editor", 1, now)
	if err != nil {
		t.Fatal(err)
	}
	out, ok := renderShared(root, d, secret, now)
	if !ok || !strings.Contains(out, "The offer") {
		t.Fatalf("%v %s", ok, out)
	}
	if strings.Contains(out, "Secret launch") {
		t.Fatalf("a shared draft shows another draft page in its menu:\n%s", out)
	}
}

// shareSaid runs one share command and returns what it answered in JSON.
func shareSaid(t *testing.T, root string, args ...string) []byte {
	t.Helper()
	old := w
	w = out.New(true)
	defer func() { w = old }()
	var buf bytes.Buffer
	w.Out = &buf
	if err := cmdShare(root, args); err != nil {
		t.Fatalf("share %v: %v", args, err)
	}
	return buf.Bytes()
}

// A link's secret is in its address and nowhere else.
//
// shares.json held each link's address in clear, and the public site found
// a link by comparing the address with ==: anybody who read the store, or
// a backup of it, could open every draft shared from it, and the audit log
// carried each one under "share". Huddle invitations and handoffs keep a
// digest of theirs. The id a link is listed, logged and revoked by is now a
// digest, which opens nothing.
func TestALinksSecretIsKeptNowhere(t *testing.T) {
	root := demoStore(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	var made struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(shareSaid(t, root, "index", "--days", "1"), &made); err != nil {
		t.Fatal(err)
	}
	secret := made.URL[strings.LastIndex(made.URL, "/")+1:]
	if !reShareID.MatchString(secret) {
		t.Fatalf("the link is %s", made.URL)
	}
	d := shareDesign(t)
	now := time.Now()
	if _, ok := renderShared(root, d, secret, now); !ok {
		t.Fatal("the link does not open the page")
	}
	for _, path := range []string{sharesPath(root), auditPath(root)} {
		if b, _ := os.ReadFile(path); bytes.Contains(b, []byte(secret)) {
			t.Errorf("%s holds the link's secret", filepath.Base(path))
		}
	}
	if made.ID == secret {
		t.Error("the id the link is listed and revoked by is its secret")
	}
	if _, ok := renderShared(root, d, made.ID, now); ok {
		t.Error("the id a list shows opens the draft")
	}
	// Listed without it, on the command line and in the editor.
	if b := shareSaid(t, root, "list"); bytes.Contains(b, []byte(secret)) {
		t.Errorf("share list shows the link's secret: %s", b)
	}
	links, err := sharesCapability(root).For("index")
	if err != nil || len(links) != 1 {
		t.Fatalf("%v %+v", err, links)
	}
	if strings.Contains(links[0].URL+links[0].ID, secret) {
		t.Errorf("the editor lists the link's secret: %+v", links[0])
	}
	// Revoked by the id it is listed by.
	shareSaid(t, root, "revoke", made.ID)
	if _, ok := renderShared(root, d, secret, now); ok {
		t.Error("the link opens after it was revoked by its listed id")
	}
}

// A link made before the store kept digests still opens, and its secret
// leaves the store the next time anybody manages links.
func TestALinkMadeBeforeDigestsStillOpens(t *testing.T) {
	root := demoStore(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	given := strings.Repeat("5e", 16) // the address somebody was sent
	before := `{"shares":[{"id":"` + given + `","page":"index","commit":"` +
		s.GetRef(site.RefDraft) + `","by":"editor","created":"` +
		now.UTC().Format(time.RFC3339) + `","expires":"` +
		now.Add(24*time.Hour).UTC().Format(time.RFC3339) + `"}]}`
	if err := os.WriteFile(sharesPath(root), []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	d := shareDesign(t)
	if _, ok := renderShared(root, d, given, now); !ok {
		t.Fatal("a link already given out stopped opening")
	}
	if links, _ := sharesCapability(root).For("index"); len(links) != 1 ||
		strings.Contains(links[0].URL+links[0].ID, given) {
		t.Errorf("the editor lists an old link's secret: %+v", links)
	}
	shareSaid(t, root, "list")
	if b, _ := os.ReadFile(sharesPath(root)); bytes.Contains(b, []byte(given)) {
		t.Errorf("an old link's secret is still in the store:\n%s", b)
	}
	if _, ok := renderShared(root, d, given, now); !ok {
		t.Fatal("a link already given out stopped opening once it was kept as a digest")
	}
	// The command printed the address as the id to revoke it by, so that
	// still revokes it.
	shareSaid(t, root, "revoke", given)
	if _, ok := renderShared(root, d, given, now); ok {
		t.Error("revoking an old link by the id it was given out with did nothing")
	}
}
