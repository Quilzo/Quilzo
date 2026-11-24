// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Setting a blog up is one feature, installed as one decision: the type, its
// collection, the listing, the pages, the site's blog and, as it had none,
// its feed. Taking the feature away takes the blog and that feed with it,
// and leaves the posts.
func TestABlogIsSetUpAsOneFeature(t *testing.T) {
	root, _ := siteStore(t)
	if err := blogCmd(root, []string{"setup"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Raw("site.blog") != "latest_posts" || cfg.Raw("site.feed") != "latest_posts" {
		t.Fatalf("site.blog %q, site.feed %q", cfg.Raw("site.blog"), cfg.Raw("site.feed"))
	}
	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pages["blog"]; !ok {
		t.Fatal("no blog page in the draft")
	}
	if p, _ := pages["post"].(map[string]any); p["detail"] != "latest_posts" {
		t.Fatalf("no page for each post: %v", pages["post"])
	}
	// Written by Quilzo itself, and marked so, so they can be published.
	idx, err := loadProvenance(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"blog", "post"} {
		if r, ok := idx.Get(name); !ok || r.SourceType != provenance.AlgorithmicMedia {
			t.Errorf("the %s page has no provenance, so it cannot be published: %+v", name, r)
		}
	}

	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	putTestRecords(t, s, "posts", []collection.Record{
		{Fields: map[string]any{"title": "Older", "slug": "older", "published": "2026-01-01"}},
		{Fields: map[string]any{"title": "Newer", "slug": "newer", "published": "2026-02-01"}},
	})
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	rows, total, name, err := latestPosts(root, 50)
	if err != nil || name != "latest_posts" || total != 2 || rows[0]["title"] != "Newer" {
		t.Fatalf("the newest posts: %v %d %s %v", rows, total, name, err)
	}

	if err := removeFeature(root, "blog", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadConfig(root)
	if cfg.Raw("site.blog") != "" || cfg.Raw("site.feed") != "" {
		t.Fatalf("the blog is gone and site.blog %q, site.feed %q remain", cfg.Raw("site.blog"), cfg.Raw("site.feed"))
	}
}

// A feed somebody chose is theirs: a blog set up later does not take it.
func TestABlogLeavesAFeedSomebodyChose(t *testing.T) {
	root, _ := siteStore(t)
	cfg, _ := loadConfig(root)
	if err := cfg.Set("site.feed", "journal", "", "dana"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	if err := setSiteBlog(root, "latest_posts", "test", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if err := setSiteBlog(root, "", "test", asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadConfig(root)
	if cfg.Raw("site.feed") != "journal" {
		t.Fatalf("the feed somebody chose became %q", cfg.Raw("site.feed"))
	}
}

// A list is given on the command line as JSON; anything else in brackets
// is the words it is.
func TestAListIsTypedAsJSON(t *testing.T) {
	if got, ok := typed(`["rye","bread"]`).([]any); !ok || len(got) != 2 || got[0] != "rye" {
		t.Errorf("a list: %#v", typed(`["rye","bread"]`))
	}
	for _, s := range []string{"[Draft] Rye", "[", "[1,"} {
		if typed(s) != s {
			t.Errorf("%q became %#v", s, typed(s))
		}
	}
}

// The pages the blog and the events install pass the checks this program
// makes of every page. Each had a list headed by an h2 and nothing above it,
// so a site that installed them was told at every publish that its blog and
// its events had headings and no h1.
func TestTheBlogAndEventsPagesHaveAnH1(t *testing.T) {
	root, design := siteStore(t)
	if _, err := installStarter(design, "sections"); err != nil {
		t.Fatal(err)
	}
	if err := blogCmd(root, []string{"setup"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	if err := eventsCmd(root, []string{"setup"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	reports, err := checkAccessibility(root, s, s.GetRef(site.RefDraft), design)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range reports {
		seen[r.Page] = true
		for _, f := range r.Findings {
			if (r.Page == "blog" || r.Page == "events") && (f.Rule == "no-h1" || f.Severity == a11y.Blocking) {
				t.Errorf("%s: %s (%s) %s", r.Page, f.Rule, f.Criterion, f.Detail)
			}
		}
	}
	if !seen["blog"] || !seen["events"] {
		t.Fatalf("the blog and events pages were not checked: %v", seen)
	}
}
