// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/tmpl"
)

// The site's blog.
//
// # Records that know they are posts
//
// A journal was a listing like any other. A page showed its newest few,
// and every older post was a page nobody could reach from the site; nothing
// said when a post went out or who wrote it, to a reader's eye or to a
// search engine's.
//
// site.blog names the listing whose records are the site's posts, as
// site.events names the events'. Its fields are read by name — title, slug,
// published, byline, summary, body, image, alt, tags and revised — and from
// them come a posts section on any page, newest first and a page at a time
// back to the first, each post's own page with its words, and an article's
// data on that page. The feed is the listing site.feed names, which a blog
// set up as a feature is.
//
// # Through the listing, like everything else
//
// Every row comes through the listing, so its field allow-list applies to
// the section and the structured data exactly as to the post's page.

// postPageMax bounds how far back the posts section pages: far enough for
// any blog, and not a number that makes a request read the world.
const postPageMax = 10000

// postsListing is the listing site.blog names, when it exists.
func (st *Site) postsListing() (*listing.Listing, bool) {
	if st.Blog == "" || st.Listings == nil || st.Listings.Set == nil {
		return nil, false
	}
	return st.Listings.Set.Get(st.Blog)
}

// postsSection says whether a page has a posts section.
func postsSection(body any) bool {
	m, ok := body.(map[string]any)
	if !ok {
		return false
	}
	sections, _ := m["sections"].([]any)
	for _, s := range sections {
		if sec, _ := s.(map[string]any); sec["posts"] != nil {
			return true
		}
	}
	return false
}

// postDay reads a date field as the day it names.
func postDay(row listing.Row, field string) (time.Time, bool) {
	v, _ := row[field].(string)
	d, err := time.Parse("2006-01-02", strings.TrimSpace(v))
	return d, err == nil
}

// postView is a post as a page shows it.
func postView(row listing.Row, links recordLink) map[string]any {
	str := func(k string) string { v, _ := row[k].(string); return strings.TrimSpace(v) }
	title := str("title")
	if title == "" {
		return nil
	}
	out := map[string]any{"title": title}
	for _, k := range []string{"byline", "summary"} {
		if v := str(k); v != "" {
			out[k] = v
		}
	}
	// What a list of posts and a search result say of it: its summary, or
	// the start of its words when it has none. Its own page shows only a
	// summary somebody wrote, never its first paragraph twice.
	if ex := postExcerpt(row); ex != "" {
		out["excerpt"] = ex
	}
	published, dated := postDay(row, "published")
	if dated {
		out["date"], out["when"] = published.Format("2006-01-02"), published.Format("2 January 2006")
	}
	// Changed after it went out, as the reader should be told.
	if u, ok := postDay(row, "revised"); ok && (!dated || u.After(published)) {
		out["revised"], out["revised_when"] = u.Format("2006-01-02"), u.Format("2 January 2006")
	}
	// A picture from the library is named by its id; anything else is not
	// one this site serves.
	if img := str("image"); img != "" && !strings.ContainsAny(img, "/:") {
		out["image"], out["alt"] = img, str("alt")
	}
	var tags []any
	if list, ok := row["tags"].([]any); ok {
		for _, t := range list {
			if s, ok := t.(string); ok && strings.TrimSpace(s) != "" {
				tags = append(tags, strings.TrimSpace(s))
			}
		}
	}
	if len(tags) > 0 {
		out["tags"] = tags
	}
	if href := links.href(row); href != "" {
		out["href"] = href
	} else {
		out["plain"] = true
	}
	return out
}

// postsData is what a posts section on a page shows: rows posts, newest
// first, at the page of them the address asks for, with the way to the
// ones either side.
func (st *Site) postsData(page string, rows int, args map[string]string) map[string]any {
	l, ok := st.postsListing()
	if !ok {
		return map[string]any{"closed": true}
	}
	if rows <= 0 || rows > 50 {
		rows = 10
	}
	n := 1
	if v, err := strconv.Atoi(strings.TrimSpace(args["page"])); err == nil && v > 1 && v <= postPageMax {
		n = v
	}
	idx, err := st.Listings.Index.For(st.Listings.Store, st.Listings.At(), l.Collection)
	if err != nil {
		return map[string]any{"closed": true}
	}
	offset := (n - 1) * rows
	found, total, err := listing.Every(l, idx, nil, offset+rows)
	if err != nil {
		return map[string]any{"closed": true}
	}
	links := st.linksFor(st.Blog)
	var items []any
	if offset < len(found) {
		for _, r := range found[offset:] {
			if v := postView(r, links); v != nil {
				items = append(items, v)
			}
		}
	}
	path := "/" + page
	if page == "index" {
		path = "/"
	}
	out := map[string]any{"none": len(items) == 0 && n == 1, "far": len(items) == 0 && n > 1}
	if len(items) > 0 {
		out["items"] = items
	}
	if total > offset+rows && len(items) > 0 {
		out["older"] = path + "?page=" + strconv.Itoa(n+1)
	}
	switch {
	case n == 2 || (n > 2 && len(items) == 0):
		out["newer"] = path
	case n > 2:
		out["newer"] = path + "?page=" + strconv.Itoa(n-1)
	}
	out["pager"] = out["older"] != nil || out["newer"] != nil
	if n > 1 {
		out["page_n"] = float64(n)
	}
	if st.Feed != "" && st.Feed == st.Blog && st.BaseURL != "" {
		out["feed"] = atomPath
	}
	return out
}

// postLD is a post's schema.org data, from the row its page shows.
func (st *Site) postLD(row listing.Row) string {
	str := func(k string) string { v, _ := row[k].(string); return strings.TrimSpace(v) }
	title := str("title")
	published, dated := postDay(row, "published")
	if title == "" || !dated {
		return ""
	}
	doc := map[string]any{"@context": "https://schema.org", "@type": "BlogPosting", "headline": title,
		"datePublished": published.Format("2006-01-02")}
	if u, ok := postDay(row, "revised"); ok && u.After(published) {
		doc["dateModified"] = u.Format("2006-01-02")
	}
	if by := str("byline"); by != "" {
		doc["author"] = map[string]any{"@type": "Person", "name": by}
	}
	if d := postExcerpt(row); d != "" {
		doc["description"] = d
	}
	if img := str("image"); img != "" && !strings.ContainsAny(img, "/:") {
		doc["image"] = st.absoluteURL("/media/" + img)
	}
	var tags []string
	if list, ok := row["tags"].([]any); ok {
		for _, t := range list {
			if s, ok := t.(string); ok && strings.TrimSpace(s) != "" {
				tags = append(tags, strings.TrimSpace(s))
			}
		}
	}
	if len(tags) > 0 {
		doc["keywords"] = strings.Join(tags, ", ")
	}
	if st.Name != "" {
		org := map[string]any{"@type": "Organization", "name": st.Name}
		if st.BaseURL != "" {
			org["url"] = strings.TrimSuffix(st.BaseURL, "/") + "/"
		}
		doc["publisher"] = org
	}
	if href := st.linksFor(st.Blog).href(row); href != "" {
		doc["url"] = st.absoluteURL(href)
		doc["mainEntityOfPage"] = doc["url"]
	}
	b, err := json.Marshal(doc)
	if err != nil || strings.Contains(strings.ToLower(string(b)), "</script") {
		return ""
	}
	return `<script type="application/ld+json">` + string(b) + `</script>`
}

// blogPage is the published page with a posts section on it, to go back
// to from a post: the blog page itself.
func (st *Site) blogPage() string {
	pages, _, err := st.pages()
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(pages))
	for n := range pages {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if postsSection(pages[n]) {
			if n == "index" {
				return "/"
			}
			return "/" + n
		}
	}
	return ""
}

// aroundPost adds to a post's view the way back to the blog and to the
// posts either side of it, newer and older, in the listing's order.
func (st *Site) aroundPost(view map[string]any, row listing.Row) {
	if href := st.blogPage(); href != "" {
		view["blog_href"] = href
	}
	l, ok := st.postsListing()
	if !ok {
		return
	}
	idx, err := st.Listings.Index.For(st.Listings.Store, st.Listings.At(), l.Collection)
	if err != nil {
		return
	}
	all, _, err := listing.Every(l, idx, nil, len(idx.Records)+1)
	if err != nil {
		return
	}
	id, _ := row["id"].(string)
	links := st.linksFor(st.Blog)
	side := func(r listing.Row) map[string]any {
		title, _ := r["title"].(string)
		href := links.href(r)
		if strings.TrimSpace(title) == "" || href == "" {
			return nil
		}
		return map[string]any{"title": strings.TrimSpace(title), "href": href}
	}
	for i, r := range all {
		if r["id"] != id {
			continue
		}
		if i > 0 {
			if v := side(all[i-1]); v != nil {
				view["newer"] = v
			}
		}
		if i+1 < len(all) {
			if v := side(all[i+1]); v != nil {
				view["older"] = v
			}
		}
		break
	}
	view["around"] = view["newer"] != nil || view["older"] != nil
}

// postExcerpt is a post's summary, or the start of its words: its first
// paragraph without the prose subset's markers, cut at a word.
func postExcerpt(row listing.Row) string {
	if s, _ := row["summary"].(string); strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	body, _ := row["body"].(string)
	for _, para := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n\n") {
		para = strings.TrimSpace(para)
		if para == "" || strings.ContainsAny(para[:1], "#->!|") || startsNumbered(para) {
			continue
		}
		words := strings.Fields(tmpl.PlainProse(para))
		var b strings.Builder
		for _, w := range words {
			if b.Len()+len(w) > 240 {
				b.WriteString("…")
				break
			}
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(w)
		}
		return b.String()
	}
	return ""
}

// startsNumbered says whether a paragraph is a numbered list.
func startsNumbered(s string) bool {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i > 0 && strings.HasPrefix(s[i:], ". ")
}
