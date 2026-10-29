// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A folder of Markdown, zipped, is read, kept as a package naming its posts
// by their hash, and installed as the site with its blog: the pages, the
// posts as records with the picture the folder held, the blog its feed. A
// second install of the same package brings nothing twice.
func TestASitesExportIsBroughtWithItsPosts(t *testing.T) {
	root, _ := siteStore(t)
	files := map[string][]byte{
		"notes/hugo.toml":                  []byte("title = \"Crumb notes\"\n"),
		"notes/content/_index.md":          []byte("---\ntitle: Welcome\n---\nBread notes, weekly.\n"),
		"notes/content/about.md":           []byte("---\ntitle: About\n---\nWe bake, and write about it in [the blog](/posts/).\n"),
		"notes/content/posts/rye.md":       []byte("---\ntitle: Rye, at last\ndate: 2026-10-27\nimage: /images/rye.png\nimage_alt: Three rye loaves\ntags: [rye]\n---\nThe rye took **three** tries.\n"),
		"notes/content/posts/mondays.md":   []byte("---\ntitle: Why we close on Mondays\ndate: 2026-10-20\n---\nFor the starter.\n"),
		"notes/static/images/rye.png":      tinyPNG(t),
		"notes/content/posts/unwritten.md": []byte("---\ntitle: Unwritten\ndraft: true\n---\nNot yet.\n"),
	}
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	for name, body := range files {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	src, err := exportOf("notes.zip", zipped.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := importExport(context.Background(), root, src, "", "", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	p := b.Package
	if p.Site.Name != "Crumb notes" || p.Blog != "latest_posts" || len(p.Records) != 1 || p.Records[0].Count != 2 {
		t.Fatalf("the package: %+v, blog %q, records %+v", p.Site, p.Blog, p.Records)
	}
	path := filepath.Join(t.TempDir(), "notes.json")
	body, _ := jsonMarshalIndent(p)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installFeatureFile(root, path, "", "", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	cfg, _ := loadConfig(root)
	if cfg.Raw("site.blog") != "latest_posts" || cfg.Raw("site.feed") != "latest_posts" {
		t.Fatalf("site.blog %q, site.feed %q", cfg.Raw("site.blog"), cfg.Raw("site.feed"))
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := draftTree(s)
	if err != nil {
		t.Fatal(err)
	}
	recs, _, err := collection.List(s, tree, "posts", collection.Query{Sort: "published", Descending: true})
	if err != nil || len(recs) != 2 {
		t.Fatalf("posts in the draft: %v %v", recs, err)
	}
	rye := recs[0].Fields
	if rye["title"] != "Rye, at last" || rye["body"] != "The rye took **three** tries." || rye["alt"] != "Three rye loaves" ||
		len(rye["image"].(string)) != 64 {
		t.Fatalf("the rye post: %v", rye)
	}
	lib, _ := openMedia(root)
	if f, _, err := lib.Get(rye["image"].(string)); err != nil || f.Alt != "Three rye loaves" {
		t.Fatalf("the post's picture in the library: %+v %v", f, err)
	}
	if _, err := os.Stat(stagedPath(root, p.Records[0].SHA256)); !os.IsNotExist(err) {
		t.Error("the staged posts were kept after they were brought")
	}
	pages, _ := draftPages(root)
	for _, n := range []string{"index", "about", "blog", "post"} {
		if pages[n] == nil {
			t.Errorf("no %s page: %v", n, sortedNames(pages))
		}
	}
	if about, _ := json.Marshal(pages["about"]); !strings.Contains(string(about), "[the blog](/blog)") {
		t.Errorf("the about page's link to the posts' folder does not go to the blog: %s", about)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	if rows, total, _, err := latestPosts(root, 10); err != nil || total != 2 || rows[0]["slug"] != "rye" {
		t.Fatalf("the blog, published: %v %d %v", rows, total, err)
	}
}

// An export is a WordPress, Squarespace or Ghost file or a zip, and
// anything else is said not to be one.
func TestOnlyAnExportIsReadAsOne(t *testing.T) {
	if _, err := exportOf("notes.txt", []byte("hello")); err == nil {
		t.Fatal("a text file was read as an export")
	}
	if _, err := exportOf("bad.zip", []byte("PK\x03\x04 not really")); err == nil {
		t.Fatal("a broken zip was read")
	}
}
