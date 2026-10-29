// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"net/url"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/section"
)

const wxr = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:excerpt="http://wordpress.org/export/1.2/excerpt/" xmlns:content="http://purl.org/rss/1.0/modules/content/"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:wp="http://wordpress.org/export/1.2/">
<channel>
<title>The Old Bakery</title><link>https://oldbakery.example</link><description>Bread &amp; cake since 1952</description>
<wp:author><wp:author_login>sam</wp:author_login><wp:author_display_name><![CDATA[Sam Baker]]></wp:author_display_name></wp:author>
<item><title>rye.jpg</title><wp:post_id>10</wp:post_id><wp:post_type>attachment</wp:post_type><wp:status>inherit</wp:status>
 <wp:attachment_url>https://oldbakery.example/wp-content/uploads/rye.jpg</wp:attachment_url>
 <wp:postmeta><wp:meta_key>_wp_attachment_image_alt</wp:meta_key><wp:meta_value><![CDATA[Three rye loaves]]></wp:meta_value></wp:postmeta></item>
<item><title>Home</title><link>https://oldbakery.example/</link><wp:post_id>2</wp:post_id><wp:post_name>home</wp:post_name>
 <wp:post_type>page</wp:post_type><wp:status>publish</wp:status>
 <content:encoded><![CDATA[Bread baked before dawn.

We open at seven.]]></content:encoded></item>
<item><title>About us</title><link>https://oldbakery.example/about-us/</link><wp:post_id>3</wp:post_id><wp:post_name>about-us</wp:post_name>
 <wp:post_type>page</wp:post_type><wp:status>publish</wp:status>
 <content:encoded><![CDATA[We are a <strong>family</strong> bakery.

[gallery ids="4,5"]

[caption id="x"]Our first oven[/caption]]]></content:encoded></item>
<item><title>Rye, at last</title><link>https://oldbakery.example/2026/10/rye-at-last/</link><dc:creator>sam</dc:creator>
 <wp:post_id>20</wp:post_id><wp:post_name>rye-at-last</wp:post_name><wp:post_type>post</wp:post_type><wp:status>publish</wp:status>
 <wp:post_date>2026-10-27 09:00:00</wp:post_date><wp:post_modified>2026-10-28 10:00:00</wp:post_modified>
 <content:encoded><![CDATA[<!-- wp:paragraph --><p>The <em>rye</em> took three tries. See <a href="https://oldbakery.example/about-us/">who we are</a>.</p><!-- /wp:paragraph -->
<!-- wp:heading --><h2>What changed</h2><!-- /wp:heading --><ul><li>a longer proof</li><li>a hotter oven</li></ul>]]></content:encoded>
 <excerpt:encoded><![CDATA[How the rye came right.]]></excerpt:encoded>
 <category domain="category" nicename="bread"><![CDATA[Bread]]></category><category domain="post_tag" nicename="rye"><![CDATA[rye]]></category>
 <category domain="category" nicename="uncategorized"><![CDATA[Uncategorized]]></category>
 <wp:postmeta><wp:meta_key>_thumbnail_id</wp:meta_key><wp:meta_value>10</wp:meta_value></wp:postmeta>
 <wp:comment><wp:comment_id>1</wp:comment_id></wp:comment></item>
<item><title>Not yet</title><wp:post_id>21</wp:post_id><wp:post_type>post</wp:post_type><wp:status>draft</wp:status></item>
<item><title>Loaf</title><wp:post_id>30</wp:post_id><wp:post_type>product</wp:post_type><wp:status>publish</wp:status></item>
<item><title></title><wp:post_id>40</wp:post_id><wp:post_type>nav_menu_item</wp:post_type><wp:menu_order>1</wp:menu_order>
 <category domain="nav_menu" nicename="main"><![CDATA[Main]]></category>
 <wp:postmeta><wp:meta_key>_menu_item_type</wp:meta_key><wp:meta_value>post_type</wp:meta_value></wp:postmeta>
 <wp:postmeta><wp:meta_key>_menu_item_object_id</wp:meta_key><wp:meta_value>3</wp:meta_value></wp:postmeta>
 <wp:postmeta><wp:meta_key>_menu_item_menu_item_parent</wp:meta_key><wp:meta_value>0</wp:meta_value></wp:postmeta></item>
</channel></rss>`

// stored stands for the media library: every picture kept, at one id.
func stored(got *[]string) Picture {
	return func(src *url.URL, alt string) (string, error) {
		*got = append(*got, src.String()+"="+alt)
		return "/media/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil
	}
}

// A WordPress export is its pages, its posts as the blog's records with
// their pictures, authors and tags, its menu, and a redirect from where each
// post was; what was not published, the comments and the shortcodes are
// said to have been left behind.
func TestAWordPressExportBecomesASiteWithItsBlog(t *testing.T) {
	if Detect([]byte(wxr)) != KindWordPress {
		t.Fatal("not detected as a WordPress export")
	}
	s, err := FromWordPress([]byte(wxr), "oldbakery.WordPress.xml")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "The Old Bakery" || s.Description != "Bread & cake since 1952" || len(s.Posts) != 1 || len(s.Pages) != 2 {
		t.Fatalf("read %q %q, %d posts, %d pages", s.Name, s.Description, len(s.Posts), len(s.Pages))
	}
	notes := strings.Join(s.Notes, " | ")
	for _, want := range []string{"1 draft", "1 comment", "shortcode", "1 product"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes do not say %q: %s", want, notes)
		}
	}
	var pics []string
	b, err := Package(s, "", "dana", stored(&pics), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := b.Package
	if err := p.Validate(feature.Checks{}); err != nil {
		t.Fatal(err)
	}
	if p.Blog != "latest_posts" || len(b.Posts) != 1 || !strings.Contains(p.Purpose, "its posts") {
		t.Fatalf("the blog: %q, %d posts, %q", p.Blog, len(b.Posts), p.Purpose)
	}
	post := b.Posts[0].Fields
	if post["title"] != "Rye, at last" || post["slug"] != "rye-at-last" || post["published"] != "2026-10-27" ||
		post["revised"] != "2026-10-28" || post["byline"] != "Sam Baker" || post["summary"] != "How the rye came right." ||
		post["alt"] != "Three rye loaves" || !strings.HasPrefix(post["image"].(string), "0123") {
		t.Fatalf("the post: %v", post)
	}
	if tags := post["tags"].([]any); len(tags) != 2 || tags[0] != "Bread" || tags[1] != "rye" {
		t.Errorf("the tags: %v", tags)
	}
	body := post["body"].(string)
	for _, want := range []string{"The *rye* took three tries. See [who we are](/about-us).", "## What changed",
		"- a longer proof\n- a hotter oven"} {
		if !strings.Contains(body, want) {
			t.Errorf("the post's words lack %q:\n%s", want, body)
		}
	}
	if pics[0] != "https://oldbakery.example/wp-content/uploads/rye.jpg=Three rye loaves" {
		t.Errorf("pictures: %v", pics)
	}
	pages := map[string]map[string]any{}
	for _, pg := range p.Pages {
		pages[pg.Name] = pg.Body
		if bad, _ := section.Validate(pg.Body); len(bad) > 0 {
			t.Errorf("page %s: %v", pg.Name, bad)
		}
	}
	for _, n := range []string{"index", "about-us", "blog", "post"} {
		if pages[n] == nil {
			t.Fatalf("no %s page: %v", n, p.Pages)
		}
	}
	about := pages["about-us"]["sections"].([]any)[0].(map[string]any)["prose"].(map[string]any)["body"].(string)
	if !strings.Contains(about, "Our first oven") || strings.Contains(about, "gallery") {
		t.Errorf("the about page: %q", about)
	}
	redirects := map[string]string{}
	for _, r := range b.Redirects {
		redirects[r.From] = r.To
	}
	if redirects["/2026/10/rye-at-last/"] != "/post/rye-at-last" {
		t.Errorf("redirects: %v", redirects)
	}
	var menu []string
	for _, m := range p.Menus {
		if m.Name == "main" {
			for _, it := range m.Items {
				menu = append(menu, it.Label+">"+it.Target)
			}
		}
	}
	if strings.Join(menu, ",") != "About us>about-us,Blog>blog" {
		t.Errorf("the main menu: %v", menu)
	}
}

const ghost = `{"db":[{"meta":{"exported_on":1761700000000,"version":"5.98.0"},"data":{
"posts":[
 {"id":"p1","title":"Rye, at last","slug":"rye","html":"<p>The rye took <strong>three</strong> tries.</p>","feature_image":"__GHOST_URL__/content/images/rye.jpg",
  "type":"post","status":"published","visibility":"public","published_at":"2026-10-27T09:00:00.000Z","updated_at":"2026-10-28T09:00:00.000Z","custom_excerpt":"How it came right."},
 {"id":"p2","title":"For members","slug":"members-only","html":"<p>Secret.</p>","type":"post","status":"published","visibility":"members","published_at":"2026-10-20T09:00:00.000Z"},
 {"id":"p3","title":"Soon","slug":"soon","html":"<p>Soon.</p>","type":"post","status":"draft","visibility":"public"},
 {"id":"p4","title":"About","slug":"about","html":"<p>We bake.</p>","type":"page","status":"published","visibility":"public"}],
"posts_meta":[{"post_id":"p1","feature_image_alt":"Three rye loaves"}],
"tags":[{"id":"t1","name":"Bread"},{"id":"t2","name":"#hidden"}],
"posts_tags":[{"post_id":"p1","tag_id":"t2","sort_order":0},{"post_id":"p1","tag_id":"t1","sort_order":1}],
"users":[{"id":"u1","name":"Sam Baker","email":"sam@example.com"}],
"posts_authors":[{"post_id":"p1","author_id":"u1","sort_order":0}],
"settings":[{"key":"title","value":"Crumb"},{"key":"description","value":"Notes from the oven"},{"key":"accent_color","value":"#7a2e12"},
 {"key":"navigation","value":"[{\"label\":\"Home\",\"url\":\"/\"},{\"label\":\"About\",\"url\":\"/about/\"}]"}]}}]}`

// A Ghost export is its public posts and pages, its navigation and its
// look; a post for members is not made public by moving it.
func TestAGhostExportKeepsMembersPostsBehind(t *testing.T) {
	if Detect([]byte(ghost)) != KindGhost {
		t.Fatal("not detected as a Ghost export")
	}
	base, _ := url.Parse("https://crumb.example")
	s, err := FromGhost([]byte(ghost), "crumb.ghost.json", base)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "Crumb" || s.Description != "Notes from the oven" || s.Colour != "#7a2e12" || len(s.Posts) != 1 ||
		len(s.Pages) != 2 {
		t.Fatalf("read %q %q %q, %d posts, %d pages", s.Name, s.Description, s.Colour, len(s.Posts), len(s.Pages))
	}
	pst := s.Posts[0]
	if pst.Published != "2026-10-27" || pst.Revised != "2026-10-28" || pst.Byline != "Sam Baker" ||
		pst.Image.String() != "https://crumb.example/content/images/rye.jpg" || pst.Alt != "Three rye loaves" ||
		strings.Join(pst.Tags, ",") != "Bread" || pst.Summary != "How it came right." {
		t.Fatalf("the post: %+v", pst)
	}
	notes := strings.Join(s.Notes, " | ")
	if !strings.Contains(notes, "1 post(s) for members") || !strings.Contains(notes, "1 draft") {
		t.Errorf("notes: %s", notes)
	}
	if len(s.Pages[0].Navs) != 1 || len(s.Pages[0].Navs[0].Links) != 2 {
		t.Errorf("navigation: %+v", s.Pages[0].Navs)
	}
	var pics []string
	b, err := Package(s, "", "dana", stored(&pics), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Package.Validate(feature.Checks{}); err != nil {
		t.Fatal(err)
	}
	if b.Package.Site.Colour != "#7a2e12" || len(b.Posts) != 1 || b.Posts[0].Fields["body"] != "The rye took **three** tries." {
		t.Fatalf("the package: %+v, %v", b.Package.Site, b.Posts)
	}
	// The home page was the newest posts, as a Ghost site's is.
	for _, pg := range b.Package.Pages {
		if pg.Name == "index" {
			secs := pg.Body["sections"].([]any)
			if _, ok := secs[0].(map[string]any)["posts"]; !ok {
				t.Errorf("the home page does not list the posts: %v", pg.Body)
			}
		}
	}
}

// A folder of Markdown is read as the site it builds: its pages, its posts
// with their front matter, its pictures as the folder's files, and its
// links to where its pages are now.
func TestAFolderOfMarkdownBecomesASite(t *testing.T) {
	fsys := fstest.MapFS{
		"hugo.toml":         {Data: []byte("baseURL = \"https://notes.example/\"\ntitle = \"Crumb notes\"\n")},
		"README.md":         {Data: []byte("# How to build this site\n")},
		"content/_index.md": {Data: []byte("---\ntitle: Welcome\n---\nBread notes, weekly.\n")},
		"content/about.md": {Data: []byte("---\ntitle: About\nweight: 1\n---\nWe write about [the blog](/posts/) and " +
			"[rye](posts/rye.md).\n\n![Our oven](/images/oven.jpg)\n\n| Day | Bread |\n|---|---|\n| Mon | Rye |\n")},
		"content/posts/rye.md": {Data: []byte("+++\ntitle = \"Rye\"\ndate = 2026-10-27\ntags = [\"rye\", \"bread\"]\n" +
			"aliases = [\"/old/rye/\"]\n+++\nSome __bold__ and _italic_ and a [link][1]. {{< figure src=\"/images/oven.jpg\" alt=\"The oven\" >}}\n\n" +
			"```\ncode *stays*\n```\n\n[1]: https://flour.example\n")},
		"content/posts/draft.md": {Data: []byte("---\ntitle: Draft\ndraft: true\n---\nNot yet.\n")},
		"static/images/oven.jpg": {Data: []byte("jpeg")},
	}
	s, err := FromFiles(fsys, "notes")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "Crumb notes" || len(s.Posts) != 1 || len(s.Pages) != 2 {
		t.Fatalf("read %q, %d posts, %d pages: %+v", s.Name, len(s.Posts), len(s.Pages), s.Pages)
	}
	pst := s.Posts[0]
	if pst.Title != "Rye" || pst.Published != "2026-10-27" || strings.Join(pst.Tags, ",") != "rye,bread" ||
		strings.Join(pst.Aliases, ",") != "/old/rye/" || pst.URL.Path != "/posts/rye" {
		t.Fatalf("the post: %+v", pst)
	}
	if !strings.Contains(strings.Join(s.Notes, " "), "1 draft") {
		t.Errorf("notes: %v", s.Notes)
	}
	var kinds []string
	for _, b := range pst.Blocks {
		kinds = append(kinds, b.Kind+":"+b.MD)
		if b.Kind == "img" && b.Src.String() != "file:///static/images/oven.jpg" {
			t.Errorf("the figure: %v", b.Src)
		}
	}
	if !slices.Contains(kinds, "p:Some **bold** and *italic* and a [link](https://flour.example).") ||
		!slices.Contains(kinds, "pre:") {
		t.Errorf("the post's blocks: %q", kinds)
	}
	var pics []string
	b, err := Package(s, "", "dana", stored(&pics), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Package.Validate(feature.Checks{}); err != nil {
		t.Fatal(err)
	}
	var about map[string]any
	for _, pg := range b.Package.Pages {
		if pg.Name == "about" {
			about = pg.Body
		}
	}
	if words := wordsOf(about); !strings.Contains(words, "Mon · Rye") || !strings.Contains(words, "[the blog](/blog)") ||
		!strings.Contains(words, "[rye](/post/rye)") {
		t.Errorf("the about page: %s", words)
	}
	if !slices.Contains(pics, "file:///static/images/oven.jpg=Our oven") {
		t.Errorf("pictures: %v", pics)
	}
	redirects := map[string]string{}
	for _, r := range b.Redirects {
		redirects[r.From] = r.To
	}
	if redirects["/old/rye/"] != "/post/rye" || redirects["/posts/rye"] != "/post/rye" {
		t.Errorf("redirects: %v", redirects)
	}
}

// A Jekyll post is where Jekyll put it, and a folder of web pages is read as
// its pages are.
func TestJekyllAndWebPagesAreReadWhereTheyWere(t *testing.T) {
	s, err := FromFiles(fstest.MapFS{
		"_config.yml":                 {Data: []byte("title: Jekyll bakery\n")},
		"index.md":                    {Data: []byte("---\nlayout: home\n---\nHello.\n")},
		"_posts/2024-01-05-hello.md":  {Data: []byte("---\ntitle: Hello\n---\nFirst post.\n")},
		"_drafts/2024-02-01-later.md": {Data: []byte("---\ntitle: Later\n---\nNot yet.\n")},
	}, "jekyll")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Posts) != 1 || s.Posts[0].URL.Path != "/2024/01/05/hello.html" || s.Posts[0].Published != "2024-01-05" ||
		s.Posts[0].Slug != "hello" {
		t.Fatalf("the Jekyll post: %+v", s.Posts)
	}
	s, err = FromFiles(fstest.MapFS{
		"index.html": {Data: []byte(`<html><head><title>Home</title><meta property="og:site_name" content="Flow bakery"></head><body>` +
			`<nav><a href="about.html">About</a></nav><main><h1>Welcome</h1><p>We bake <a href="about.html">by hand</a>.</p>` +
			`<img src="images/loaf.png" alt="A loaf"></main></body></html>`)},
		"about.html":      {Data: []byte(`<html><head><title>About</title></head><body><main><h1>About</h1><p>Since 1952.</p></main></body></html>`)},
		"images/loaf.png": {Data: []byte("png")},
	}, "webflow")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "Flow bakery" || len(s.Pages) != 2 || s.Pages[0].URL.Path != "/" {
		t.Fatalf("the pages: %q %+v", s.Name, s.Pages)
	}
	var pics []string
	b, err := Package(s, "", "dana", stored(&pics), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pics, ",") != "file:///images/loaf.png=A loaf" {
		t.Errorf("pictures: %v", pics)
	}
	for _, pg := range b.Package.Pages {
		if pg.Name == "index" && !strings.Contains(wordsOf(pg.Body), "We bake [by hand](/about).") {
			t.Errorf("the home page: %s", wordsOf(pg.Body))
		}
	}
}

// wordsOf is a page's words: its lead and its prose.
func wordsOf(body map[string]any) string {
	var out []string
	if hero, ok := body["hero"].(map[string]any); ok {
		if lead, ok := hero["lead"].(string); ok {
			out = append(out, lead)
		}
	}
	secs, _ := body["sections"].([]any)
	for _, sec := range secs {
		if pr, ok := sec.(map[string]any)["prose"].(map[string]any); ok {
			if b, ok := pr["body"].(string); ok {
				out = append(out, b)
			}
		}
	}
	return strings.Join(out, "\n\n")
}
