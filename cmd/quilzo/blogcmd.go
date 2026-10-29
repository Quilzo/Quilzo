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
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A blog (internal/public/posts.go): records whose listing site.blog names.
// What makes them posts is that one setting and the fields they are read
// by; everything else is a type, a collection, a listing and pages, which
// `quilzo blog setup` installs as one feature package, and which an agent
// can propose the same way.

// blogPackage is the ready-made blog (internal/feature/blog.go).
func blogPackage() *feature.Package { return feature.BlogPackage() }

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
