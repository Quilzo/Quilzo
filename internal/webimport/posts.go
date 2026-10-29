// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// A blog brought from an export: its posts become records of the ready-made
// blog (internal/feature/blog.go), each at /post/its-slug, with a redirect
// from where it was. Records rather than pages, because a blog is hundreds
// of posts, and a package is something a person reads.

// Row is one record an import brings, with the id it keeps: the same post
// brought twice is the same record, not two.
type Row struct {
	ID     string
	Fields map[string]any
}

// postPage is the page each post is shown on.
const postPage = "post"

// rowID is a stable id for something brought from where it was.
func rowID(key string) string {
	sum := sha256.Sum256([]byte("webimport:" + key))
	return hex.EncodeToString(sum[:16])
}

// postRows makes a blog's posts records, keeping each one's main picture
// and its words in the prose subset; link rewrites where the words link.
func postRows(s *Site, picture func(*url.URL, string) string, link func(string) string,
	note func(string, ...any)) ([]Row, []seo.Redirect) {

	var rows []Row
	var redirects []seo.Redirect
	slugs := postSlugs(s.Posts)
	for i, pst := range s.Posts {
		slug := slugs[i]
		if slug == "" {
			note("a post with no title, page link or date was left out: %s", pst.Title)
			continue
		}
		f := map[string]any{"title": clip(strings.TrimSpace(pst.Title), 200), "slug": slug, "published": pst.Published}
		for k, v := range map[string]string{"byline": pst.Byline, "summary": pst.Summary, "revised": pst.Revised} {
			if v = strings.TrimSpace(v); v != "" {
				f[k] = clip(v, 300)
			}
		}
		img, alt := pst.Image, pst.Alt
		var words []string
		listing := false
		for _, b := range pst.Blocks {
			md := linksIn(b.MD, link)
			if md == "" {
				md = tmpl.EscapeProse(b.Text)
			}
			sep := "\n\n"
			switch {
			case len(words) == 0:
				sep = ""
			case b.Kind == "li" && listing:
				sep = "\n"
			}
			listing = b.Kind == "li"
			switch b.Kind {
			case "h1":
				if strings.EqualFold(strings.TrimSpace(b.Text), strings.TrimSpace(pst.Title)) {
					continue
				}
				words = append(words, sep, "## "+md)
			case "h2":
				words = append(words, sep, "## "+md)
			case "h3", "h4", "h5", "h6":
				words = append(words, sep, "### "+md)
			case "img":
				// The first picture is the post's own when it has none; the
				// rest stay where they were among its words, from the
				// library, with what they show.
				if img == nil && b.Src != nil {
					img, alt = b.Src, b.Text
					continue
				}
				if b.Src == nil {
					continue
				}
				desc := strings.NewReplacer("[", "", "]", "", "\n", " ").Replace(strings.TrimSpace(b.Text))
				if path := picture(b.Src, desc); strings.HasPrefix(path, "/media/") {
					words = append(words, sep, "!["+clip(desc, 400)+"]("+path+")")
				}
			case "li":
				words = append(words, sep, "- "+md)
			case "quote":
				words = append(words, sep, "> "+md)
			case "pre":
				words = append(words, sep, tmpl.EscapeProse(b.Text))
			default:
				words = append(words, sep, md)
			}
		}
		if body := strings.TrimSpace(strings.Join(words, "")); body != "" {
			f["body"] = body
		}
		if f["summary"] == nil {
			for _, b := range pst.Blocks {
				if b.Kind == "p" && b.Text != "" {
					f["summary"] = clip(b.Text, 280)
					break
				}
			}
		}
		if img != nil {
			if path := picture(img, alt); path != "" {
				f["image"], f["alt"] = strings.TrimPrefix(path, "/media/"), alt
			}
		}
		var tags []any
		for _, t := range pst.Tags {
			if t = strings.TrimSpace(t); t != "" && len(tags) < 20 {
				tags = append(tags, clip(t, 60))
			}
		}
		if len(tags) > 0 {
			f["tags"] = tags
		}
		key := slug
		if pst.URL != nil {
			key = pst.URL.String()
		}
		rows = append(rows, Row{ID: rowID(key), Fields: f})
		now := feature.PagePath(postPage) + "/" + slug
		olds := pst.Aliases
		if pst.URL != nil {
			olds = append([]string{pst.URL.EscapedPath()}, olds...)
		}
		for _, old := range olds {
			if trimmed := strings.TrimSuffix(old, "/"); strings.HasPrefix(old, "/") && trimmed != "" && trimmed != now {
				redirects = append(redirects, seo.Redirect{From: old, To: now, Permanent: true})
			}
		}
	}
	return rows, redirects
}

// postSlugs is the page link each post keeps, one each, or "" for one that
// cannot be brought.
func postSlugs(posts []Post) []string {
	out := make([]string, len(posts))
	taken := map[string]bool{}
	for i, pst := range posts {
		slug := slugOf(pst.Slug)
		if slug == "" {
			slug = slugOf(pst.Title)
		}
		if slug == "" || strings.TrimSpace(pst.Title) == "" || pst.Published == "" {
			continue
		}
		base := slug
		for k := 2; taken[slug]; k++ {
			slug = fmt.Sprintf("%s-%d", base, k)
		}
		taken[slug] = true
		out[i] = slug
	}
	return out
}

// slugOf is a page link made from words: lower case, hyphens between.
func slugOf(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r < 128 && (r >= 'a' && r <= 'z' || r >= '0' && r <= '9'):
			b.WriteRune(r)
			dash = false
		case r == '\'' || r == '’':
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	return clip(strings.Trim(b.String(), "-"), 80)
}

// addBlog puts the ready-made blog in a package bringing posts: its type,
// collection, listing and page for each post, and a page listing them,
// which is the site's own blog page when it has one.
func addBlog(p *feature.Package) {
	bp := feature.BlogPackage()
	p.Types = append(p.Types, bp.Types...)
	p.Collections = append(p.Collections, bp.Collections...)
	p.Listings = append(p.Listings, bp.Listings...)
	p.Blog = bp.Blog
	posts := map[string]any{"posts": map[string]any{"title": "Latest posts", "rows": float64(10), "intro": ""}}
	for _, pg := range bp.Pages {
		if pg.Name != "blog" {
			p.Pages = append(p.Pages, pg)
			continue
		}
		if i := pageIndex(p, "blog"); i >= 0 {
			secs, _ := p.Pages[i].Body["sections"].([]any)
			p.Pages[i].Body["sections"] = append(secs, posts)
			continue
		}
		p.Pages = append(p.Pages, pg)
	}
}

func pageIndex(p *feature.Package, name string) int {
	for i, pg := range p.Pages {
		if pg.Name == name {
			return i
		}
	}
	return -1
}
