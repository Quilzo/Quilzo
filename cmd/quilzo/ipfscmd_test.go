// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/ipfs"
)

// bundleTemplates is a template directory of one layout, for rendering a
// copy of the site.
func bundleTemplates(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "page.html"),
		[]byte(`<!doctype html><html lang="en"><head><title>{{ page.title }}</title></head><body><h1>{{ page.title }}</h1></body></html>`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// An agent card that does not validate leaves the site without a card, not
// without a copy.
//
// The builder handed a card that failed validation back as an error, the
// public server answered that with 500, and the static copy refuses any
// optional address that answers neither 200 nor 404. So turning the card on
// for a site whose address is not https yet — any site before its
// certificate — failed `quilzo ipfs id`, `ipfs write` and the content_id
// tool alike, with a message about the card.
func TestAnAgentCardThatDoesNotValidateDoesNotStopACopy(t *testing.T) {
	root := publishedShop(t)
	tpl := bundleTemplates(t)
	if err := cmdConfig(root, []string{"set", "site.agent_card", "true"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdConfig(root, []string{"set", "site.base_url", "http://marginalia.example"}); err != nil {
		t.Fatal(err)
	}
	files, err := renderBundle(root, tpl)
	if err != nil {
		t.Fatalf("a card that does not validate stopped the copy: %v", err)
	}
	if _, ok := files[".well-known/agent-card.json"]; ok {
		t.Error("a card that does not validate went into the copy")
	}

	// At an https address the card validates, and is copied.
	if err := cmdConfig(root, []string{"set", "site.base_url", "https://marginalia.example"}); err != nil {
		t.Fatal(err)
	}
	if files, err = renderBundle(root, tpl); err != nil {
		t.Fatal(err)
	}
	if _, ok := files[".well-known/agent-card.json"]; !ok {
		t.Error("a valid card is missing from the copy")
	}
}

// The Permanent web screen, `quilzo ipfs id` and the content_id tool give
// one identifier for one site.
//
// # What this found
//
// The screen rendered a bundle of its own: the pages through render.Bundle,
// the stylesheet, and the asset library under bare hashes. The command line
// and the tool render the site the public server serves — its sitemap,
// robots.txt, manifest, service worker, feeds and the structured data on
// each page — name each asset by its format, and add the fonts. So the
// screen gave one identifier and the terminal another for the same site,
// and a pinning service checked against one was told it had stored
// something else.
func TestThePermanentWebScreenGivesTheCommandLinesIdentifier(t *testing.T) {
	root := publishedShop(t)
	tpl := bundleTemplates(t)
	files, err := renderBundle(root, tpl)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ipfs.Tree(files)
	if err != nil {
		t.Fatal(err)
	}
	cli := node.Block.CID

	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	text, merr := callTool(t, buildMCP(root, s, asAdmin("dana"), tpl), "quilzo_read", "content_id",
		map[string]any{"templates": tpl})
	if merr != nil {
		t.Fatal(merr.Message)
	}
	if tool, _, _ := strings.Cut(text, "\n"); tool != cli {
		t.Errorf("the content_id tool says %s and quilzo ipfs id says %s", tool, cli)
	}

	// The screen, wired as `quilzo serve` wires it.
	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.IssueSession("test", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, ts, design.Layouts)
	if err != nil {
		t.Fatal(err)
	}
	srv.Decentralised = decentralisedFor(root, tpl, s, func() *Design { return design })
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+secret)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, r)
		return rec
	}
	rec := get("/decentralised/bundle")
	if rec.Code != http.StatusOK {
		t.Fatalf("the download answered %d: %s", rec.Code, rec.Body)
	}
	if screen := rec.Header().Get("X-Content-Id"); screen != cli {
		t.Errorf("the Permanent web screen's download says %s and quilzo ipfs id says %s "+
			"for the same site", screen, cli)
	}
	if page := get("/decentralised"); !strings.Contains(page.Body.String(), cli) {
		t.Errorf("the Permanent web screen does not show %s, the identifier quilzo ipfs id gives", cli)
	}
}

// A caller at the agent interface gets the identifier of the site this
// admin serves, rendered with its own templates, and cannot choose which
// directory on the server is read instead.
//
// content_id took a templates argument and opened whatever it named, so a
// reader's token was a probe of the server's filesystem ("not a
// directory", "no such file", "no layout in") and a way to render the site
// with another store's templates. And it ignored the templates the admin
// was started with, reading ./templates of wherever the process ran.
// scan_content took the same argument, and scanned whatever it named.
func TestContentIDReadsOnlyTheAdminsOwnTemplatesFromAfar(t *testing.T) {
	root := publishedShop(t)
	tpl := bundleTemplates(t)
	seedPolicy(t, root, [2]string{"rae", "reader"}, [2]string{"dana", "admin"})
	files, err := renderBundle(root, tpl)
	if err != nil {
		t.Fatal(err)
	}
	node, err := ipfs.Tree(files)
	if err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, remoteCaller(auth.Token{Principal: "rae", Role: auth.RoleReader, Resource: "/"}), tpl)

	text, merr := callTool(t, srv, "quilzo_read", "content_id", map[string]any{})
	if merr != nil {
		t.Fatalf("the admin's own site could not be identified: %s", merr.Message)
	}
	if got, _, _ := strings.Cut(text, "\n"); got != node.Block.CID {
		t.Errorf("content_id says %s, and the site rendered with the admin's templates is %s", got, node.Block.CID)
	}
	// Naming the admin's own directory is naming nothing new.
	if _, merr := callTool(t, srv, "quilzo_read", "content_id", map[string]any{"templates": tpl}); merr != nil {
		t.Errorf("naming the admin's own templates was refused: %s", merr.Message)
	}

	var answers []string
	for _, dir := range []string{"/etc/passwd", "/nonexistent", t.TempDir(), root, bundleTemplates(t), "../" + filepath.Base(tpl)} {
		_, merr := callTool(t, srv, "quilzo_read", "content_id", map[string]any{"templates": dir})
		if merr == nil {
			t.Errorf("the site was rendered with %s, a directory a remote caller chose", dir)
			continue
		}
		if strings.Contains(merr.Message, dir) {
			t.Errorf("the refusal names the directory asked about: %s", merr.Message)
		}
		answers = append(answers, merr.Message)
	}
	for _, a := range answers[1:] {
		if a != answers[0] {
			t.Errorf("the refusals tell directories apart:\n  %s\n  %s", answers[0], a)
		}
	}

	// The scan, by an administrator from afar with an hour's token.
	now := time.Now().Unix()
	admin := buildMCP(root, s, remoteCaller(auth.Token{Principal: "dana", Role: auth.RoleAdmin, Resource: "/",
		CreatedAt: now, ExpiresAt: now + 3600}), tpl)
	if _, merr := callTool(t, admin, "quilzo_read", "scan_content", map[string]any{}); merr != nil {
		t.Errorf("the scan of the admin's own templates was refused: %s", merr.Message)
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "page.html"), []byte(`<script>eval(location.hash)</script>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if text, merr := callTool(t, admin, "quilzo_read", "scan_content", map[string]any{"templates": other}); merr == nil {
		t.Errorf("a directory a remote caller chose was scanned: %s", text)
	}
}
