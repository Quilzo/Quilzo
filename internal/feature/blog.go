// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"fmt"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/schema"
)

// The blog block: which of the package's listings is the site's posts
// (site.blog), so a site built, brought or proposed with a blog arrives with
// its posts on their own pages, newest first, a feed to follow, and an
// article's data on each post's page. One site has one blog, so one package
// owns it, and one somebody set by hand is theirs.

// BlogRef is the blog block's ref.
var BlogRef = Ref{Kind: "blog", Name: "blog"}

func validateBlog(p *Package, bad func(string, ...any)) {
	if p.Blog == "" {
		return
	}
	for _, l := range p.Listings {
		if l.Name != p.Blog {
			continue
		}
		if l.Exposes() {
			return
		}
		have := map[string]bool{}
		for _, f := range l.Fields {
			have[f] = true
		}
		for _, need := range []string{"title", "slug", "published"} {
			if !have[need] {
				bad("blog: listing %q does not show %q, which every post needs", l.Name, need)
			}
		}
		return
	}
	bad("blog: %q is not a listing this package declares", p.Blog)
}

// blogLine is what the card says the block shows.
func blogLine(p *Package) Line {
	return Line{Text: fmt.Sprintf("Listing %q is the site's blog: each post on its own page, newest first, a "+
		"feed at /feed.xml to follow it, and an article's date and author for search engines and assistants", p.Blog),
		Flag: "public"}
}

// BlogPackage is the ready-made blog: a type for a post, its collection,
// the listing of them newest first, a blog page and a page for each post.
func BlogPackage() *Package {
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
	return &Package{Format: Format, Name: "blog", Version: "1.0", Title: "Blog",
		Purpose: "Posts, newest first: a page for each, older ones a page at a time, a feed readers follow, and " +
			"when each went out and who wrote it for search engines.",
		Types:       []schema.Type{post},
		Collections: []Collection{{Name: "posts", Type: "post"}},
		Listings: []listing.Listing{
			{Name: "latest_posts", Label: "Latest posts", Collection: "posts", Fields: public,
				Sort: "published", Descending: true, Rows: 20},
		},
		Pages: []Page{
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
