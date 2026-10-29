// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A blog (internal/public/posts.go): records whose listing site.blog names.
// What makes them posts is that one setting and the fields they are read
// by; everything else is a type, a collection, a listing and pages, which
// `quilzo blog setup` installs as one feature package, and which an agent
// can propose the same way.

// blogPackage is the ready-made blog: a type for a post, its collection,
// the listing of them newest first, a blog page and a page for each post.
func blogPackage() *feature.Package {
	f := func(name string, kind schema.Kind, label, help string, required bool) schema.Field {
		return schema.Field{Name: name, Kind: kind, Label: label, Help: help, Required: required}
	}
	post := schema.Type{Name: "post", Description: "A piece of writing on the site's blog, with when it went out.",
		Fields: []schema.Field{
			f("title", schema.Text, "Title", "", true),
			f("slug", schema.Slug, "Page link", "The end of the post's own page link: /post/this-part.", true),
			f("published", schema.Date, "Published", "The day it went out. Posts are listed newest first.", true),
			f("byline", schema.Text, "Written by", "As it should read under the title.", false),
			f("summary", schema.Text, "Summary", "A sentence or two for the list of posts, feeds and search results.",
				false),
			f("body", schema.LongText, "The post", "A blank line between paragraphs; ## before a heading, - before "+
				"each item of a list, **bold**, *italic* and [a link](https://example.com).", false),
			f("image", schema.Text, "Picture", "A picture from the media library.", false),
			{Name: "alt", Kind: schema.Text, Label: "What the picture shows", AltFor: "image"},
			f("tags", schema.List, "Tags", "Words a reader might look for it by.", false),
			f("revised", schema.Date, "Last changed", "When it was changed in a way a reader should know.", false),
		}}
	public := []string{"title", "slug", "published", "byline", "summary", "body", "image", "alt", "tags", "revised"}
	return &feature.Package{Format: feature.Format, Name: "blog", Version: "1.0", Title: "Blog",
		Purpose: "Posts, newest first: a page for each, older ones a page at a time, a feed readers follow, and " +
			"when each went out and who wrote it for search engines.",
		Types:       []schema.Type{post},
		Collections: []feature.Collection{{Name: "posts", Type: "post"}},
		Listings: []listing.Listing{
			{Name: "latest_posts", Label: "Latest posts", Collection: "posts", Fields: public,
				Sort: "published", Descending: true, Rows: 20},
		},
		Pages: []feature.Page{
			{Name: "blog", Body: map[string]any{"title": "Blog",
				"description": "Everything written here, newest first.",
				"sections": []any{map[string]any{"posts": map[string]any{"title": "Blog", "rows": float64(10),
					"intro": ""}}}}},
			// No title of its own: it stands for whichever post is being
			// read, and the heading comes from the record.
			{Name: "post", Body: map[string]any{"detail": "latest_posts", "detail_key": "slug"}},
		},
		Blog: "latest_posts",
	}
}

// cmdBlog is `quilzo blog …`.
func cmdBlog(root string, args []string) error {
	return blogCmd(root, args, resolveCaller(root, flagToken))
}

func blogCmd(root string, args []string, caller *Caller) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return blogList(root, caller)
	case "setup":
		return blogSetup(root, caller)
	case "example":
		body, _ := json.MarshalIndent(blogPackage(), "", "  ")
		w.Human("%s\n", body)
		return nil
	default:
		return fmt.Errorf("unknown blog command %q; try list, setup or example", args[0])
	}
}

// blogSetup installs the ready-made blog, as `quilzo feature install`
// would: one decision, on the record.
func blogSetup(root string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
		return fmt.Errorf("a blog is added as a feature, by whoever may install one: %w", err)
	}
	if caller.Kind == audit.KindAI {
		return errors.New("a feature is installed by a person. A model may propose one; it may not install one")
	}
	body, err := readyPackage(root, blogPackage())
	if err != nil {
		return err
	}
	p, body, err := readFeatureBytes(root, body, "")
	if err != nil {
		return err
	}
	o, err := requestFeature(root, p, body, caller, false, false, nil)
	if err := printOutcome(p, o, err, caller); err != nil {
		return err
	}
	// A layout written before the blog existed has nowhere to show it.
	if b, err := os.ReadFile(filepath.Join(newsletterDesignDir, "page.html")); err == nil &&
		!strings.Contains(string(b), "s.posts") {
		w.Human("%syour layout was made before the blog: choose your starter again under Design, or run "+
			"quilzo template use sections --force, for the list of posts and each post's page%s\n", yellow, reset)
	}
	if o.Waiting == nil {
		w.Human("write posts on the Data screen (collection posts) or with quilzo records add posts " +
			"title=… slug=… published=2026-11-14 body=…; publish the draft for the Blog page, and the feed " +
			"is at /feed.xml\n")
	}
	return nil
}

// latestPosts is the posts the site's blog listing shows now, at the live
// site, newest first.
func latestPosts(root string, max int) ([]listing.Row, int, string, error) {
	cfg, err := loadConfig(root)
	if err != nil {
		return nil, 0, "", err
	}
	name := strings.TrimSpace(cfg.Raw("site.blog"))
	if name == "" {
		return nil, 0, "", nil
	}
	set, err := loadListings(root)
	if err != nil {
		return nil, 0, name, err
	}
	l, ok := set.Get(name)
	if !ok {
		return nil, 0, name, fmt.Errorf("site.blog names %q and no listing has that name", name)
	}
	s, err := store.Open(root)
	if err != nil {
		return nil, 0, name, err
	}
	c, err := s.GetCommit(s.GetRef(site.RefLive))
	if err != nil {
		return nil, 0, name, nil
	}
	idx, err := collection.Build(s, c.Tree, l.Collection, nil)
	if err != nil {
		return nil, 0, name, err
	}
	rows, total, err := listing.Every(l, idx, nil, max)
	return rows, total, name, err
}

func blogList(root string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	rows, total, name, err := latestPosts(root, 50)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"listing": name, "posts": rows, "total": total}) {
		return nil
	}
	if name == "" {
		w.Human("this site has no blog yet: quilzo blog setup adds one\n")
		return nil
	}
	if len(rows) == 0 {
		w.Human("nothing has been published in %s\n", name)
		return nil
	}
	for _, r := range rows {
		str := func(k string) string { v, _ := r[k].(string); return v }
		by := ""
		if b := str("byline"); b != "" {
			by = "  " + b
		}
		w.Human("%s  %s%s\n", str("published"), str("title"), by)
	}
	if total > len(rows) {
		w.Human("%sand %d older%s\n", dim, total-len(rows), reset)
	}
	return nil
}

// setSiteBlog names the site's blog listing, or none, on the record. A
// site with no feed gets the blog as its feed; taking the blog away takes a
// feed that was the blog with it, since its listing goes too.
func setSiteBlog(root, name, why string, caller *Caller) error {
	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	old := strings.TrimSpace(cfg.Raw("site.blog"))
	feed := strings.TrimSpace(cfg.Raw("site.feed"))
	if name == "" {
		err = cfg.Unset("site.blog")
		if err == nil && old != "" && feed == old {
			err = cfg.Unset("site.feed")
		}
	} else {
		err = cfg.Set("site.blog", name, why, caller.Name)
		if err == nil && (feed == "" || feed == old) {
			err = cfg.Set("site.feed", name, why, caller.Name)
		}
	}
	if err != nil {
		return err
	}
	if err := saveConfig(root, cfg); err != nil {
		return err
	}
	return recordE(root, caller.auditRecord("site.blog", "/", audit.Success,
		map[string]string{"listing": name, "why": why}))
}
