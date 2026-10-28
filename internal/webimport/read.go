// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package webimport brings a live website in by its address.
//
// Most sites somebody wants to move have no export file: a Wix, Squarespace
// or Webflow site, a dotCMS or Drupal install nobody can reach the database
// of, pages written by hand years ago. What every one of them has is its
// pages. So this reads them the way a person does: the site's own map of
// itself when it publishes one, its links when it does not, each page's
// headings, paragraphs, lists and pictures, its navigation, its name and its
// colour, and turns them into a site package (internal/feature/site.go) that
// is read, approved and installed as one decision, and taken back as one.
//
// It reads what anybody may read and nothing more: only the address it was
// given and pages on that host, never one robots.txt asks it not to, through
// the fetcher that refuses private addresses (internal/fetch), at a polite
// pace, and within a page and byte budget. A page's scripts, styles, frames
// and forms are not content and are left behind, and said to be.
package webimport

import (
	"html"
	"net/url"
	"strings"
	"unicode"
)

// Page is what one page of a site says, read as a person reads it.
type Page struct {
	// URL is where it was read from, after redirects.
	URL *url.URL
	// Title is the document's title, Description its meta description,
	// Lang its language.
	Title, Description, Lang string
	// SiteName and ThemeColour are what the page says about its site.
	SiteName, ThemeColour string
	// Canonical is the address the page says it is really at.
	Canonical string
	// Blocks are its content, in order: what is inside <main>, or else
	// <article>, or else the body without its header, navigation, footer
	// and asides.
	Blocks []Block
	// Navs are the link lists in its navigation, header and footer.
	Navs []Nav
	// Links are every address its content and navigation link to.
	Links []*url.URL
	// Left are what was not content, by kind: a script, a form, a frame.
	Left map[string]int
}

// Block is one piece of content.
type Block struct {
	// Kind is h1 to h6, p, li, quote, pre or img.
	Kind string
	// Text is its words; for a picture, its description (alt).
	Text string
	// Src is a picture's address.
	Src *url.URL
}

// Nav is a list of links in a page's chrome.
type Nav struct {
	// Foot is a footer's navigation, as against the main one.
	Foot  bool
	Links []Link
}

// Link is a labelled address.
type Link struct {
	Label string
	URL   *url.URL
}

// skipped are elements whose content is not the page's prose.
var skipped = map[string]bool{
	"script": true, "style": true, "noscript": true, "template": true, "svg": true,
	"iframe": true, "object": true, "embed": true, "canvas": true, "form": true,
	"select": true, "button": true, "dialog": true, "math": true, "video": true, "audio": true,
}

// chrome are the regions around content.
var chrome = map[string]bool{"header": true, "nav": true, "footer": true, "aside": true}

// blockTags start or end a piece of content.
var blockTags = map[string]string{
	"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4", "h5": "h5", "h6": "h6",
	"p": "p", "li": "li", "blockquote": "quote", "pre": "pre", "dd": "p", "dt": "p",
	"figcaption": "p", "td": "p", "th": "p", "caption": "p", "summary": "p",
	"div": "p", "section": "p", "article": "p", "main": "p", "address": "p", "br": "",
}

// void are elements with no closing tag.
var void = map[string]bool{"img": true, "br": true, "hr": true, "meta": true, "link": true,
	"input": true, "source": true, "area": true, "base": true, "col": true, "wbr": true, "track": true}

// MaxPageBytes bounds the markup of one page that is read.
const MaxPageBytes = 4 << 20

// Read reads one page. base is where it came from, for its relative links.
func Read(body []byte, base *url.URL) Page {
	if len(body) > MaxPageBytes {
		body = body[:MaxPageBytes]
	}
	r := &reader{page: Page{URL: base, Left: map[string]int{}}, base: base}
	r.scan(string(body))
	r.flush()
	r.finish()
	return r.page
}

type reader struct {
	page Page
	base *url.URL
	// open is the stack of open elements.
	open []string
	// skipping is the element whose content is being left behind.
	skipping string
	// text is the block being written, and kind what it is; prose says some
	// of it is not a link's text.
	text  strings.Builder
	kind  string
	prose bool
	// region counts, for each block, whether it is in chrome, main, article.
	blocks []regionBlock
	// head text being read: the title.
	inTitle bool
	title   strings.Builder
	// nav being read, and the link in it.
	nav      *Nav
	navDepth int
	link     *Link
	linkText strings.Builder
	hasMain  bool
	hasArt   bool
	baseSet  bool
}

type regionBlock struct {
	Block
	chrome, main, article bool
}

func (r *reader) in(name string) bool {
	for _, o := range r.open {
		if o == name {
			return true
		}
	}
	return false
}

func (r *reader) inChrome() bool {
	for _, o := range r.open {
		if chrome[o] {
			return true
		}
	}
	return false
}

// scan walks the markup: text, tags, comments.
func (r *reader) scan(s string) {
	for i := 0; i < len(s); {
		if s[i] != '<' {
			j := strings.IndexByte(s[i:], '<')
			if j < 0 {
				j = len(s) - i
			}
			r.textRun(s[i : i+j])
			i += j
			continue
		}
		if strings.HasPrefix(s[i:], "<!--") {
			end := strings.Index(s[i+4:], "-->")
			if end < 0 {
				return
			}
			i += 4 + end + 3
			continue
		}
		// A tag runs to the first > outside quotes.
		j, quote := i+1, byte(0)
		for ; j < len(s); j++ {
			c := s[j]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
				continue
			}
			if c == '"' || c == '\'' {
				quote = c
			} else if c == '>' {
				break
			}
		}
		if j >= len(s) {
			return
		}
		r.tag(s[i+1 : j])
		i = j + 1
	}
}

func (r *reader) textRun(t string) {
	if r.skipping != "" {
		return
	}
	if r.inTitle {
		r.title.WriteString(t)
		return
	}
	if r.link != nil {
		r.linkText.WriteString(t)
	}
	if r.in("head") {
		return
	}
	if r.link == nil && strings.TrimSpace(t) != "" {
		r.prose = true
	}
	r.text.WriteString(t)
}

func (r *reader) tag(raw string) {
	if strings.HasPrefix(raw, "!") || strings.HasPrefix(raw, "?") {
		return
	}
	closing := strings.HasPrefix(raw, "/")
	name, attrs := parseTag(raw)
	if name == "" {
		return
	}
	if r.skipping != "" {
		if closing && name == r.skipping {
			r.skipping = ""
		}
		return
	}
	if closing {
		r.close(name)
		return
	}
	if skipped[name] {
		r.flush()
		r.page.Left[name]++
		if !void[name] && !strings.HasSuffix(raw, "/") {
			r.skipping = name
		}
		return
	}
	switch name {
	case "html":
		r.page.Lang = attrs["lang"]
	case "title":
		r.inTitle = true
	case "meta":
		content := strings.TrimSpace(attrs["content"])
		switch strings.ToLower(attrs["name"] + attrs["property"]) {
		case "description", "og:description":
			if r.page.Description == "" {
				r.page.Description = content
			}
		case "og:site_name", "application-name":
			if r.page.SiteName == "" {
				r.page.SiteName = content
			}
		case "theme-color":
			if r.page.ThemeColour == "" {
				r.page.ThemeColour = content
			}
		}
	case "link":
		if strings.EqualFold(attrs["rel"], "canonical") {
			r.page.Canonical = attrs["href"]
		}
	case "base":
		if u, err := r.base.Parse(attrs["href"]); err == nil && !r.baseSet && (u.Scheme == "http" || u.Scheme == "https") {
			r.base, r.baseSet = u, true
		}
	case "main":
		r.hasMain = true
	case "article":
		r.hasArt = true
	case "img":
		src := attrs["src"]
		if src == "" {
			src = firstSrc(attrs["srcset"])
		}
		if u := r.resolve(src); u != nil {
			r.flush()
			r.add(Block{Kind: "img", Text: clean(attrs["alt"]), Src: u})
		}
		return
	case "a":
		if u := r.resolve(attrs["href"]); u != nil {
			r.page.Links = append(r.page.Links, u)
			r.link = &Link{URL: u}
			r.linkText.Reset()
		}
	case "nav":
		if r.nav == nil {
			r.nav = &Nav{Foot: r.in("footer")}
			r.navDepth = len(r.open)
		}
	}
	if kind, ok := blockTags[name]; ok {
		r.flush()
		if kind != "" {
			r.kind = kind
		}
	}
	if !void[name] && !strings.HasSuffix(raw, "/") {
		r.open = append(r.open, name)
	}
}

func (r *reader) close(name string) {
	switch name {
	case "title":
		r.inTitle = false
		r.page.Title = clean(r.title.String())
		return
	case "a":
		if r.link != nil {
			r.link.Label = clean(r.linkText.String())
			if r.nav != nil && r.link.Label != "" {
				r.nav.Links = append(r.nav.Links, *r.link)
			}
			r.link = nil
		}
	}
	if _, ok := blockTags[name]; ok {
		r.flush()
	}
	// Close back to the matching element; a stray closing tag closes nothing.
	for i := len(r.open) - 1; i >= 0; i-- {
		if r.open[i] == name {
			r.open = r.open[:i]
			break
		}
	}
	if r.nav != nil && len(r.open) < r.navDepth+1 && name == "nav" {
		if len(r.nav.Links) > 0 {
			r.page.Navs = append(r.page.Navs, *r.nav)
		}
		r.nav = nil
	}
}

// flush ends the block being written.
func (r *reader) flush() {
	t := clean(r.text.String())
	prose := r.prose
	r.text.Reset()
	kind := r.kind
	r.kind, r.prose = "", false
	if t == "" {
		return
	}
	if kind == "" {
		kind = "p"
	}
	// A short run of nothing but links is navigation that wandered into the
	// content, "Read more" or "Print PDF", and not a paragraph anybody wrote.
	if kind == "p" && !prose && len(strings.Fields(t)) <= 8 {
		return
	}
	r.add(Block{Kind: kind, Text: t})
}

func (r *reader) add(b Block) {
	r.blocks = append(r.blocks, regionBlock{Block: b, chrome: r.inChrome(), main: r.in("main"), article: r.in("article")})
}

// finish keeps the blocks that are the page's content.
func (r *reader) finish() {
	if r.nav != nil && len(r.nav.Links) > 0 {
		r.page.Navs = append(r.page.Navs, *r.nav)
	}
	for _, b := range r.blocks {
		switch {
		case r.hasMain && !b.main, !r.hasMain && r.hasArt && !b.article,
			!r.hasMain && !r.hasArt && b.chrome:
			continue
		}
		r.page.Blocks = append(r.page.Blocks, b.Block)
	}
	if u := r.resolve(r.page.Canonical); u != nil {
		r.page.Canonical = u.String()
	} else {
		r.page.Canonical = ""
	}
}

// resolve makes an address absolute against the page, keeping only web
// addresses: a javascript:, mailto: or data: address is not a page.
func (r *reader) resolve(href string) *url.URL {
	href = strings.TrimSpace(html.UnescapeString(href))
	if href == "" || strings.HasPrefix(href, "#") {
		return nil
	}
	u, err := r.base.Parse(href)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil
	}
	u.Fragment = ""
	return u
}

func firstSrc(srcset string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(srcset), ",")
	f := strings.Fields(first)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// clean decodes entities once, after tags are gone, and closes up space.
func clean(s string) string {
	s = html.UnescapeString(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// parseTag reads a tag's name and attributes.
func parseTag(s string) (name string, attrs map[string]string) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "/"), "/"))
	attrs = map[string]string{}
	end := strings.IndexFunc(s, unicode.IsSpace)
	if end < 0 {
		return strings.ToLower(s), attrs
	}
	name, s = strings.ToLower(s[:end]), s[end:]
	for len(s) > 0 {
		s = strings.TrimLeftFunc(s, unicode.IsSpace)
		if s == "" {
			break
		}
		eq := strings.IndexAny(s, "= \t\n\r")
		if eq < 0 {
			attrs[strings.ToLower(s)] = ""
			break
		}
		key := strings.ToLower(s[:eq])
		s = strings.TrimLeftFunc(s[eq:], unicode.IsSpace)
		if !strings.HasPrefix(s, "=") {
			attrs[key] = ""
			continue
		}
		s = strings.TrimLeftFunc(s[1:], unicode.IsSpace)
		var val string
		if s != "" && (s[0] == '"' || s[0] == '\'') {
			q := s[0]
			end := strings.IndexByte(s[1:], q)
			if end < 0 {
				val, s = s[1:], ""
			} else {
				val, s = s[1:1+end], s[2+end:]
			}
		} else {
			end := strings.IndexFunc(s, unicode.IsSpace)
			if end < 0 {
				end = len(s)
			}
			val, s = s[:end], s[end:]
		}
		if _, seen := attrs[key]; !seen {
			attrs[key] = val
		}
	}
	return name, attrs
}
