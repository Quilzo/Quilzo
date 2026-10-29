// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import "fmt"

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
