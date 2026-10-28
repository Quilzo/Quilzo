// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/section"
	"github.com/quilzo/quilzo/internal/seo"
)

// Picture stores a picture a page shows, with the description the page gave
// it, and answers the path a page refers to it by. Nil leaves pictures out.
type Picture func(src *url.URL, alt string) (path string, err error)

// Brought is a site as a package, and what came with it.
type Brought struct {
	Package *feature.Package
	// Redirects take every old address that changed to its new one, so
	// links and search results keep working.
	Redirects []seo.Redirect
	// Notes say what was left behind or decided, for the card.
	Notes []string
}

// Limits on what one page brings, so a page that is a whole archive is
// still a page somebody can read and the package stays one a person can
// approve.
const (
	maxParagraphs = 300
	// maxPictures bounds the pictures one import fetches, across the site.
	maxPictures  = 300
	maxLeadRunes = 280
)

// Package turns a site that was read into a site package. name overrides
// the name the site gives itself.
func Package(s *Site, name, by string, picture Picture, now time.Time) (*Brought, error) {
	if s == nil || len(s.Pages) == 0 {
		return nil, fmt.Errorf("nothing was read")
	}
	out := &Brought{}
	note := func(format string, a ...any) { out.Notes = append(out.Notes, fmt.Sprintf(format, a...)) }
	home := s.Pages[0]

	siteName := strings.TrimSpace(name)
	if siteName == "" {
		siteName = nameOf(s)
	}
	if len([]rune(siteName)) > feature.MaxSiteName {
		siteName = string([]rune(siteName)[:feature.MaxSiteName])
	}
	desc := home.Description
	if len([]rune(desc)) > feature.MaxSiteDescription {
		desc = ""
	}
	site := &feature.Site{Name: siteName, Description: desc, Starter: "sections"}
	if c := colour(home.ThemeColour); c != "" {
		site.Colour = c
		if len(site.LookRefused()) > 0 {
			note("the site's own colour %s is hard to read on its background here, so the starter's palette is used", c)
			site.Colour = ""
		}
	}

	p := &feature.Package{
		Format: feature.Format, Name: feature.PackageName(siteName), Version: "1.0.0",
		Title:   clip(siteName, 120),
		Purpose: clip("The website of "+siteName+", brought from "+s.Home.Host+": its pages, its menus and its look.", 600),
		Made:    &feature.Made{By: by, From: s.Home.String(), At: now.UTC()},
		Site:    site,
	}

	// Each page gets a name from its address, and keeps it if it can.
	names := map[string]string{}
	taken := map[string]bool{}
	for i, pg := range s.Pages {
		n := pageName(pg.URL)
		if i == 0 {
			n = "index"
		}
		base := n
		for k := 2; taken[n]; k++ {
			n = fmt.Sprintf("%s-%d", base, k)
		}
		taken[n] = true
		names[keyOf(pg.URL)] = n
	}

	pictures, undescribed, failed := 0, 0, 0
	for _, pg := range s.Pages {
		n := names[keyOf(pg.URL)]
		body, empty := pageBody(pg, siteName, func(src *url.URL, alt string) string {
			if picture == nil {
				return ""
			}
			if alt == "" {
				undescribed++
				return ""
			}
			if pictures >= maxPictures {
				return ""
			}
			path, err := picture(src, alt)
			if err != nil {
				failed++
				return ""
			}
			pictures++
			return path
		})
		if empty {
			note("page %s was left out: it had no words to bring", pg.URL.Path)
			continue
		}
		if n == "index" {
			// The home page opens on a tinted hero, as a built site's does;
			// the rest open on their words.
			hero := body["hero"].(map[string]any)
			hero["surface"] = "surface-wash"
			if hero["image"] == nil {
				hero["style"] = "center"
			} else {
				delete(hero, "style")
			}
		}
		p.Pages = append(p.Pages, feature.Page{Name: n, Body: body})
		// Only where the address changed: /about-us/ is /about-us already.
		old, now := pg.URL.EscapedPath(), feature.PagePath(n)
		if trimmed := strings.TrimSuffix(old, "/"); trimmed != "" && trimmed != now && old != "" &&
			len(out.Redirects) < feature.MaxSiteRedirects {
			out.Redirects = append(out.Redirects, seo.Redirect{From: old, To: now, Permanent: true})
		}
	}
	if picture == nil {
		note("pictures were left out, as asked; import again with pictures to keep the ones the site describes")
	}
	if undescribed > 0 {
		note("%d picture(s) had no description (alt text), so they were left out rather than given one nobody wrote; add them with quilzo media add FILE --alt", undescribed)
	}
	if failed > 0 {
		note("%d picture(s) could not be fetched or are not a format this keeps", failed)
	}

	exists := map[string]bool{}
	for _, pg := range p.Pages {
		exists[pg.Name] = true
	}
	for _, nav := range home.Navs {
		m := menuOf(nav, names, exists)
		if len(m.Items) == 0 {
			continue
		}
		if nav.Foot {
			if !hasMenu(p, "foot") {
				m.Name, m.Label = "foot", "Footer"
				p.Menus = append(p.Menus, m)
			}
		} else if !hasMenu(p, "main") {
			m.Name, m.Label = "main", "Main"
			p.Menus = append(p.Menus, m)
		}
	}
	if !hasMenu(p, "main") {
		note("the home page has no navigation this could read, so the site has no main menu yet")
	}

	p.Chatbots = []assistant.Assistant{feature.QuestionBox(siteName, nil, false)}

	left := map[string]int{}
	for _, pg := range s.Pages {
		for k, v := range pg.Left {
			left[k] += v
		}
	}
	if left["form"] > 0 {
		note("%d form(s) were left behind: a form here is declared with its questions, purpose and how long answers are kept (quilzo form add)", left["form"])
	}
	var kinds []string
	for k, v := range left {
		if k != "form" && v > 0 {
			kinds = append(kinds, fmt.Sprintf("%d %s", v, k))
		}
	}
	sort.Strings(kinds)
	if len(kinds) > 0 {
		note("not content, so left behind: %s", strings.Join(kinds, ", "))
	}
	if len(s.Refused) > 0 {
		note("%d page(s) were not read because the site's robots.txt asks readers not to", len(s.Refused))
	}
	if len(s.Failed) > 0 {
		note("%d page(s) could not be read: %s", len(s.Failed), strings.Join(first(s.Failed, 3), "; "))
	}
	if s.Capped {
		note("the site has more pages than were read; read more with --pages")
	}

	// A package a person can read: the pages that fit, the rest named.
	for size(p) > feature.MaxBytes || p.Blocks() > feature.MaxBlocks {
		if len(p.Pages) <= 1 {
			return nil, fmt.Errorf("the home page alone is larger than a package may be")
		}
		gone := p.Pages[len(p.Pages)-1]
		p.Pages = p.Pages[:len(p.Pages)-1]
		note("page %s was left out to keep the package within what one may hold", gone.Name)
		for i := range p.Menus {
			kept := p.Menus[i].Items[:0]
			for _, it := range p.Menus[i].Items {
				if it.Target != gone.Name {
					kept = append(kept, it)
				}
			}
			p.Menus[i].Items = kept
		}
	}
	// Redirects only to pages the package still holds, and none from one of
	// them: redirects are served first, so it would hide the page.
	own := map[string]bool{}
	for _, pg := range p.Pages {
		own[feature.PagePath(pg.Name)] = true
	}
	kept := out.Redirects[:0]
	for _, r := range out.Redirects {
		from, err := seo.Path(r.From)
		if err != nil || own[from] {
			continue
		}
		if name := strings.TrimPrefix(r.To, "/"); name == "" || hasPage(p, name) {
			kept = append(kept, r)
		}
	}
	out.Redirects = kept
	site.Redirects = out.Redirects
	out.Package = p
	return out, nil
}

func hasPage(p *feature.Package, name string) bool {
	for _, pg := range p.Pages {
		if pg.Name == name {
			return true
		}
	}
	return false
}

// pageBody turns a page's content into a hero and sections. empty says
// there were no words.
func pageBody(pg Page, siteName string, picture func(*url.URL, string) string) (map[string]any, bool) {
	title := strings.TrimSpace(trimSiteName(pg.Title, siteName))
	blocks := pg.Blocks
	hero := map[string]any{"style": "plain"}
	// The first heading is the page's, and the paragraph after it its lead.
	for i, b := range blocks {
		if b.Kind == "h1" {
			title = b.Text
			blocks = append(append([]Block{}, blocks[:i]...), blocks[i+1:]...)
			break
		}
	}
	if title == "" {
		title = siteName
	}
	var sections []any
	cur := map[string]any{}
	var paras []any
	var gallery []any
	total := 0
	flush := func() {
		if len(paras) > 0 {
			cur["paragraphs"] = paras
			sections = append(sections, map[string]any{"prose": cur})
		}
		if len(gallery) > 0 {
			sections = append(sections, map[string]any{"gallery": map[string]any{"title": "", "shape": "", "items": gallery}})
		}
		cur, paras, gallery = map[string]any{"title": ""}, nil, nil
	}
	cur["title"] = ""
	leadTaken := false
	for _, b := range blocks {
		if total >= maxParagraphs || len(sections) >= section.MaxSections-2 {
			break
		}
		switch b.Kind {
		case "h2", "h3", "h4", "h5", "h6":
			flush()
			cur["title"] = clip(b.Text, 200)
		case "img":
			path := picture(b.Src, b.Text)
			if path == "" {
				continue
			}
			if _, ok := hero["image"]; !ok && len(sections) == 0 && len(paras) == 0 {
				hero["image"], hero["alt"] = path, b.Text
				continue
			}
			gallery = append(gallery, map[string]any{"image": path, "alt": b.Text, "caption": ""})
		default:
			text := b.Text
			if b.Kind == "li" {
				text = "• " + text
			}
			if !leadTaken && len(sections) == 0 && len(paras) == 0 && b.Kind == "p" && utf8.RuneCountInString(text) <= maxLeadRunes {
				hero["lead"] = text
				leadTaken = true
				continue
			}
			paras = append(paras, text)
			total++
		}
	}
	flush()
	if len(sections) == 0 && hero["lead"] == nil {
		return nil, true
	}
	body := map[string]any{"title": clip(title, 200), "hero": hero, "sections": sections}
	if d := strings.TrimSpace(pg.Description); d != "" {
		body["description"] = clip(d, 300)
	}
	return body, false
}

func menuOf(nav Nav, names map[string]string, exists map[string]bool) menu.Menu {
	var m menu.Menu
	seen := map[string]bool{}
	for _, l := range nav.Links {
		target, ok := names[keyOf(l.URL)]
		if !ok || !exists[target] || seen[target] || len(m.Items) >= 12 {
			continue
		}
		seen[target] = true
		label := clip(l.Label, menu.MaxLabel)
		m.Items = append(m.Items, menu.Item{ID: strings.ReplaceAll(target, "/", "-"), Label: label,
			Kind: menu.Page, Target: target, Order: (len(m.Items) + 1) * 10})
	}
	return m
}

func hasMenu(p *feature.Package, name string) bool {
	for _, m := range p.Menus {
		if m.Name == name {
			return true
		}
	}
	return false
}

// nameOf is what the site calls itself: its declared name, or the part of
// its titles every page shares, or its home page's title, or its host.
func nameOf(s *Site) string {
	if n := strings.TrimSpace(s.Pages[0].SiteName); n != "" {
		return n
	}
	counts := map[string]int{}
	for _, pg := range s.Pages {
		for _, part := range titleParts(pg.Title) {
			counts[part]++
		}
	}
	best, n := "", 0
	for part, c := range counts {
		if c > n || (c == n && part < best) {
			best, n = part, c
		}
	}
	if n >= 2 && n*2 >= len(s.Pages) {
		return best
	}
	if t := strings.TrimSpace(s.Pages[0].Title); t != "" {
		return t
	}
	return strings.TrimPrefix(s.Home.Host, "www.")
}

var titleSep = regexp.MustCompile(`\s+[|–—·•-]\s+`)

func titleParts(t string) []string {
	parts := titleSep.Split(t, -1)
	if len(parts) < 2 {
		return nil
	}
	return []string{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[len(parts)-1])}
}

// trimSiteName takes the site's name off a page's title: "About | Hart's".
func trimSiteName(title, site string) string {
	parts := titleSep.Split(title, -1)
	if len(parts) < 2 {
		return title
	}
	var kept []string
	for _, p := range parts {
		if !strings.EqualFold(strings.TrimSpace(p), site) {
			kept = append(kept, strings.TrimSpace(p))
		}
	}
	return strings.Join(kept, " — ")
}

// pageName is a page's name from its address: /About_Us.html is about-us,
// /blog/2024/a-post/ is blog/2024/a-post.
func pageName(u *url.URL) string {
	p := strings.Trim(u.Path, "/")
	for _, ext := range []string{".html", ".htm", ".php", ".aspx", ".asp", ".shtml"} {
		p = strings.TrimSuffix(strings.ToLower(p), ext)
	}
	p = strings.TrimSuffix(p, "/index")
	if p == "" || p == "index" {
		return "index"
	}
	var parts []string
	for _, seg := range strings.Split(p, "/") {
		var b strings.Builder
		dash := false
		for _, r := range strings.ToLower(seg) {
			switch {
			case r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)):
				b.WriteRune(r)
				dash = false
			case r == '\'' || r == '’':
			case !dash && b.Len() > 0:
				b.WriteByte('-')
				dash = true
			}
		}
		if s := strings.Trim(b.String(), "-"); s != "" {
			parts = append(parts, clip(s, 60))
		}
	}
	if len(parts) == 0 {
		return "page"
	}
	if len(parts) > 4 {
		parts = parts[len(parts)-4:]
	}
	return strings.Join(parts, "/")
}

// keyOf is a page's address as the crawl knows it.
func keyOf(u *url.URL) string {
	return strings.TrimPrefix(strings.ToLower(u.Host), "www.") + strings.TrimSuffix(u.EscapedPath(), "/")
}

var hexColour = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// colour reads a theme colour this can build a palette from: #rgb or
// #rrggbb, as #rrggbb.
func colour(c string) string {
	c = strings.TrimSpace(c)
	if !hexColour.MatchString(c) {
		return ""
	}
	if len(c) == 4 {
		c = "#" + strings.Repeat(c[1:2], 2) + strings.Repeat(c[2:3], 2) + strings.Repeat(c[3:4], 2)
	}
	return strings.ToLower(c)
}

func size(p *feature.Package) int {
	b, err := json.Marshal(p)
	if err != nil {
		return feature.MaxBytes + 1
	}
	return len(b)
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return strings.TrimSpace(string([]rune(s)[:n-1])) + "…"
}

func first(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	return append(append([]string{}, xs[:n]...), fmt.Sprintf("and %d more", len(xs)-n))
}
