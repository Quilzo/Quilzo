// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/starter"
)

// blogSite is a bakery's blog of 25 posts, one a day through January 2026,
// listed ten at a time on its blog page, with a page for each.
func blogSite(t *testing.T) *Site {
	t.Helper()
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Crumb"},
		"blog":  map[string]any{"title": "Blog", "sections": []any{map[string]any{"posts": map[string]any{"title": "From the oven", "rows": float64(10)}}}},
		"post":  map[string]any{"detail": "latest_posts", "detail_key": "slug"},
	})
	tpl, _ := starter.Get("sections")
	html, err := tpl.HTML()
	if err != nil {
		t.Fatal(err)
	}
	st.Layouts = render.OneLayout(html)
	st.Name, st.Index, st.BaseURL = "Crumb", "index", "https://crumb.example"
	var recs []collection.Record
	for i := 1; i <= 25; i++ {
		f := map[string]any{"title": fmt.Sprintf("Day %d", i), "slug": fmt.Sprintf("day-%d", i),
			"published": fmt.Sprintf("2026-01-%02d", i), "byline": "Sam Baker",
			"summary": fmt.Sprintf("What came out of the oven on day %d.", i), "secret": "do not publish"}
		if i == 25 {
			f["title"], f["slug"] = "Rye, at last", "rye"
			f["body"] = "The rye took three tries.\n\n## What changed\n\n- a longer proof\n- a hotter oven\n\nRead **more** on [the flour](https://flour.example)."
			f["tags"] = []any{"rye", "bread"}
			f["revised"] = "2026-02-02"
		}
		recs = append(recs, collection.Record{ID: fmt.Sprintf("%032d", i), Fields: f})
	}
	tree, _, err := collection.PutMany(st.Store, "", "posts", recs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	set := &listing.Set{}
	if err := set.Add(listing.Listing{Name: "latest_posts", Collection: "posts", Sort: "published", Descending: true,
		Rows: 20, Fields: []string{"title", "slug", "published", "byline", "summary", "body", "image", "alt", "tags",
			"revised"}}); err != nil {
		t.Fatal(err)
	}
	st.Listings = &listing.Resolver{Store: st.Store, Set: set, Live: func() string { return tree }}
	st.Blog, st.Feed = "latest_posts", "latest_posts"
	return st
}

var rePostName = regexp.MustCompile(`<h3 class="blog-name"><a href="([^"]+)">([^<]+)</a>`)

// The blog page lists the newest ten, and every older post a page at a
// time, with the way either side.
func TestTheBlogListsEveryPostAPageAtATime(t *testing.T) {
	st := blogSite(t)
	first := getPage(st, "/blog")
	body := first.Body.String()
	names := rePostName.FindAllStringSubmatch(body, -1)
	if first.Code != 200 || len(names) != 10 || names[0][2] != "Rye, at last" || names[9][2] != "Day 16" {
		t.Fatalf("the first page: %d %v", first.Code, names)
	}
	if names[0][1] != "/post/rye" {
		t.Errorf("a post's own page: %q", names[0][1])
	}
	for _, want := range []string{`<time datetime="2026-01-25">25 January 2026</time>`, "Sam Baker",
		`href="/blog?page=2" rel="next">Older posts`, `href="/feed.xml">Follow these`} {
		if !strings.Contains(body, want) {
			t.Errorf("the first page lacks %q", want)
		}
	}
	if strings.Contains(body, "Newer posts") || strings.Contains(body, "do not publish") {
		t.Error("the first page offers newer posts, or a field the listing keeps private")
	}
	if rep := a11y.Check("blog", body); rep.Blocks() {
		t.Fatalf("the blog page is not usable by everybody: %+v", rep)
	}
	third := getPage(st, "/blog?page=3").Body.String()
	names = rePostName.FindAllStringSubmatch(third, -1)
	if len(names) != 5 || names[4][2] != "Day 1" || !strings.Contains(third, `href="/blog?page=2" rel="prev">Newer posts`) ||
		strings.Contains(third, "Older posts") {
		t.Fatalf("the last page: %v", names)
	}
	if !strings.Contains(getPage(st, "/blog?page=2").Body.String(), `href="/blog" rel="prev">Newer posts`) {
		t.Error("the second page does not lead back to the first")
	}
	if far := getPage(st, "/blog?page=9").Body.String(); !strings.Contains(far, "no posts this far back") ||
		!strings.Contains(far, `href="/blog" rel="prev"`) {
		t.Error("a page past the oldest post does not say so, or lead back")
	}
	if first.Header().Get("ETag") == getPage(st, "/blog?page=2").Header().Get("ETag") {
		t.Error("two pages of posts share a validator")
	}
}

// Every post has its own page, the oldest too, past the rows its listing
// shows at once: its words, when it went out, who wrote it, the posts
// either side, and an article's data for search engines.
func TestEveryPostHasItsOwnPage(t *testing.T) {
	st := blogSite(t)
	oldest := getPage(st, "/post/day-1")
	if oldest.Code != 200 || !strings.Contains(oldest.Body.String(), "<h1>Day 1</h1>") {
		t.Fatalf("the oldest post, past the listing's twenty rows: %d", oldest.Code)
	}
	res := getPage(st, "/post/rye")
	body := res.Body.String()
	for _, want := range []string{"<title>Rye, at last — Crumb</title>", `<meta property="og:type" content="article">`,
		`<meta name="description" content="What came out of the oven on day 25.">`,
		"<h2>What changed</h2>", "<li>a longer proof</li>", "<strong>more</strong>", `<a href="https://flour.example">the flour</a>`,
		"<li>rye</li>", `Updated <time datetime="2026-02-02">2 February 2026</time>`,
		`href="/post/day-24" rel="next"><span class="pager-label">Older</span> Day 24`, `href="/blog">All posts`} {
		if !strings.Contains(body, want) {
			t.Errorf("the post's page lacks %q", want)
		}
	}
	if strings.Contains(body, "Newer</span>") {
		t.Error("the newest post offers a newer one")
	}
	if !strings.Contains(oldest.Body.String(), `href="/post/day-2" rel="prev"><span class="pager-label">Newer</span> Day 2`) {
		t.Error("the oldest post does not lead to the next")
	}
	if rep := a11y.Check("post", body); rep.Blocks() {
		t.Fatalf("a post's page is not usable by everybody: %+v", rep)
	}
	m := regexp.MustCompile(`<script type="application/ld\+json">(\{"@context":"https://schema.org","@type":"BlogPosting".*?)</script>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no BlogPosting data:\n%s", body)
	}
	if strings.Contains(body, `"@type":"Product"`) {
		t.Error("a post was described as a product")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(m[1]), &doc); err != nil {
		t.Fatal(err)
	}
	author, _ := doc["author"].(map[string]any)
	if doc["headline"] != "Rye, at last" || doc["datePublished"] != "2026-01-25" || doc["dateModified"] != "2026-02-02" ||
		author["name"] != "Sam Baker" || doc["keywords"] != "rye, bread" || doc["url"] != "https://crumb.example/post/rye" {
		t.Fatalf("the article: %v", doc)
	}
	if getPage(st, "/post/nothing").Code != http.StatusNotFound {
		t.Error("a post that is not there has a page")
	}
}

// With no blog set, a posts section says so and a post page is a record
// page like any other.
func TestASiteWithNoBlogSaysSo(t *testing.T) {
	st := blogSite(t)
	st.Blog = ""
	if body := getPage(st, "/blog").Body.String(); !strings.Contains(body, "No posts are listed here yet.") {
		t.Error("a posts section on a site with no blog does not say so")
	}
	if body := getPage(st, "/post/rye").Body.String(); strings.Contains(body, "BlogPosting") {
		t.Error("a record read through a listing that is not the blog was described as a post")
	}
}

// The sitemap lists each post's page, the oldest too, and not the page that
// stands for them all, which is no address of its own.
func TestTheSitemapListsEveryPostsPage(t *testing.T) {
	st := blogSite(t)
	res := getPage(st, "/sitemap.xml")
	body := res.Body.String()
	if res.Code != 200 {
		t.Fatalf("the sitemap: %d %s", res.Code, body)
	}
	for _, want := range []string{"<loc>https://crumb.example/post/rye</loc>", "<loc>https://crumb.example/post/day-1</loc>",
		"<loc>https://crumb.example/blog</loc>"} {
		if !strings.Contains(body, want) {
			t.Errorf("the sitemap lacks %s", want)
		}
	}
	if strings.Contains(body, "<loc>https://crumb.example/post</loc>") {
		t.Error("the sitemap lists the page that stands for the posts")
	}
	if n := strings.Count(body, "/post/"); n != 25 {
		t.Errorf("%d post pages listed, of 25", n)
	}
}

// A post with no summary is listed by the start of its words, and its own
// page does not repeat them as a summary nobody wrote.
func TestAPostWithNoSummaryIsListedByItsFirstWords(t *testing.T) {
	v := postView(listing.Row{"title": "Rye", "published": "2026-10-27",
		"body": "## What changed\n\n- a list\n\nThe rye took **three** tries, see [the flour](https://e.test/).\n\nMore."}, recordLink{})
	if v["excerpt"] != "The rye took three tries, see the flour." || v["summary"] != nil {
		t.Fatalf("excerpt %q, summary %v", v["excerpt"], v["summary"])
	}
	if v := postView(listing.Row{"title": "Rye", "summary": "Written.", "body": "Words."}, recordLink{}); v["excerpt"] != "Written." {
		t.Fatalf("a written summary is not the excerpt: %v", v["excerpt"])
	}
}
