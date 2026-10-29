// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// A site brought from the file its last home exported.
//
// What a crawl reads from a live site, an export says outright: which pages
// are pages and which are posts, when each went out and who wrote it, the
// menus, the main picture of each post and what it shows. So an export is
// read into the same Site a crawl makes, with its posts beside its pages,
// and becomes a package the same way, read and approved as one decision.
//
// Nothing in an export is fetched while it is read. Its pictures are
// addresses, fetched afterwards through the fetcher that refuses private
// addresses, as a crawl's are, or files in the same folder.

// MaxExportBytes bounds an export file.
const MaxExportBytes = 256 << 20

// Kinds of export, as Detect names them.
const (
	KindWordPress = "wordpress"
	KindGhost     = "ghost"
	KindFiles     = "files"
)

// Detect says what an export file is from its first bytes: a WordPress
// export (which Squarespace, WordPress.com and others write), a Ghost
// export, a zip of files, or nothing this reads.
func Detect(head []byte) string {
	if len(head) > 8192 {
		head = head[:8192]
	}
	s := strings.TrimSpace(strings.TrimPrefix(string(head), "\ufeff"))
	switch {
	case strings.HasPrefix(s, "PK\x03\x04"):
		return KindFiles
	case strings.HasPrefix(s, "<") && strings.Contains(s, "<rss") &&
		(strings.Contains(s, "wordpress.org/export") || strings.Contains(s, "<wp:")):
		return KindWordPress
	case strings.HasPrefix(s, "{") && (strings.Contains(s, `"db"`) || strings.Contains(s, `"posts"`)) &&
		(strings.Contains(s, `"meta"`) || strings.Contains(s, `"exported_on"`) || strings.Contains(s, `"data"`)):
		return KindGhost
	}
	return ""
}

// -- WordPress ----------------------------------------------------------------

type wxrDoc struct {
	Channel struct {
		Title       string      `xml:"title"`
		Link        string      `xml:"link"`
		Description string      `xml:"description"`
		BaseSite    string      `xml:"base_site_url"`
		Authors     []wxrAuthor `xml:"author"`
		Items       []wxrItem   `xml:"item"`
	} `xml:"channel"`
}

type wxrAuthor struct {
	Login   string `xml:"author_login"`
	Display string `xml:"author_display_name"`
}

type wxrItem struct {
	Title   string `xml:"title"`
	Link    string `xml:"link"`
	Creator string `xml:"creator"`
	// Both content:encoded and excerpt:encoded, told apart by namespace,
	// which changes with the export's version.
	Encoded []struct {
		XMLName xml.Name
		Value   string `xml:",chardata"`
	} `xml:"encoded"`
	ID         string `xml:"post_id"`
	Date       string `xml:"post_date"`
	Modified   string `xml:"post_modified"`
	Name       string `xml:"post_name"`
	Status     string `xml:"status"`
	Parent     string `xml:"post_parent"`
	MenuOrder  int    `xml:"menu_order"`
	Type       string `xml:"post_type"`
	AttachURL  string `xml:"attachment_url"`
	Categories []struct {
		Domain   string `xml:"domain,attr"`
		Nicename string `xml:"nicename,attr"`
		Value    string `xml:",chardata"`
	} `xml:"category"`
	Meta []struct {
		Key   string `xml:"meta_key"`
		Value string `xml:"meta_value"`
	} `xml:"postmeta"`
	Comments []struct {
		ID string `xml:"comment_id"`
	} `xml:"comment"`
}

func (it wxrItem) meta(key string) string {
	for _, m := range it.Meta {
		if m.Key == key {
			return strings.TrimSpace(m.Value)
		}
	}
	return ""
}

func (it wxrItem) encoded(space string) string {
	for _, e := range it.Encoded {
		if strings.Contains(e.XMLName.Space, space) {
			return e.Value
		}
	}
	return ""
}

// FromWordPress reads a WordPress export (WXR): its published pages and
// posts, their main pictures, its main menu, and what it left behind.
func FromWordPress(body []byte, origin string) (*Site, error) {
	if len(body) > MaxExportBytes {
		return nil, fmt.Errorf("the export is larger than %d MB", MaxExportBytes>>20)
	}
	var doc wxrDoc
	dec := xml.NewDecoder(bytes.NewReader(body))
	// Strict, and with no entity table: an entity the document declares is
	// an error, never text expanded from somewhere else (see
	// internal/importer for the attack this is).
	dec.Strict = true
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("this does not read as a WordPress export: %w", err)
	}
	ch := doc.Channel
	home, err := url.Parse(strings.TrimSpace(ch.Link))
	if err != nil || home.Host == "" || (home.Scheme != "http" && home.Scheme != "https") {
		home, _ = url.Parse("https://wordpress.invalid/")
	}
	if home.Path == "" {
		home.Path = "/"
	}
	s := &Site{Home: home, From: KindWordPress, Origin: origin, Name: strings.TrimSpace(html.UnescapeString(ch.Title)),
		Description: strings.TrimSpace(html.UnescapeString(ch.Description))}
	if strings.EqualFold(s.Description, "Just another WordPress site") {
		s.Description = ""
	}
	authors := map[string]string{}
	for _, a := range ch.Authors {
		if d := strings.TrimSpace(a.Display); d != "" {
			authors[a.Login] = d
		}
	}
	type attachment struct{ url, alt string }
	attachments := map[string]attachment{}
	links := map[string]string{}
	for _, it := range ch.Items {
		if it.Type == "attachment" && it.AttachURL != "" {
			alt := it.meta("_wp_attachment_image_alt")
			attachments[it.ID] = attachment{it.AttachURL, alt}
		}
		if it.Link != "" {
			links[it.ID] = it.Link
		}
	}
	held, other, comments, shortcodes := 0, map[string]int{}, 0, 0
	var pages []Page
	homeAt := -1
	type menuItem struct {
		order          int
		label, href    string
		parent, menuID string
	}
	menus := map[string][]menuItem{}
	for _, it := range ch.Items {
		title := strings.TrimSpace(html.UnescapeString(it.Title))
		switch it.Type {
		case "attachment", "revision", "custom_css", "customize_changeset", "wp_global_styles", "wp_template",
			"wp_template_part", "wp_block", "wp_navigation", "oembed_cache", "user_request", "wp_font_family",
			"wp_font_face":
			continue
		case "nav_menu_item":
			menu := ""
			for _, c := range it.Categories {
				if c.Domain == "nav_menu" {
					menu = c.Nicename
				}
			}
			href := it.meta("_menu_item_url")
			if obj := it.meta("_menu_item_object_id"); it.meta("_menu_item_type") != "custom" && links[obj] != "" {
				href = links[obj]
			}
			label := title
			if label == "" {
				for _, o := range ch.Items {
					if o.ID == it.meta("_menu_item_object_id") {
						label = strings.TrimSpace(html.UnescapeString(o.Title))
					}
				}
			}
			if href != "" && label != "" {
				menus[menu] = append(menus[menu], menuItem{it.MenuOrder, label, href, it.meta("_menu_item_menu_item_parent"),
					menu})
			}
			continue
		}
		if it.Type != "page" && it.Type != "post" {
			other[it.Type]++
			continue
		}
		if it.Status != "publish" {
			held++
			continue
		}
		comments += len(it.Comments)
		link, err := url.Parse(strings.TrimSpace(it.Link))
		if err != nil || link.Host == "" {
			link = home.ResolveReference(&url.URL{Path: "/" + it.Name + "/"})
		}
		content, n := wpContent(it.encoded("content"))
		shortcodes += n
		read := Read([]byte("<main>"+content+"</main>"), link)
		if it.Type == "page" {
			pg := Page{URL: link, Title: title, Blocks: append([]Block{{Kind: "h1", Text: title}}, read.Blocks...),
				Left: read.Left}
			if excerpt := plainText(it.encoded("excerpt")); excerpt != "" {
				pg.Description = clip(excerpt, 300)
			}
			pages = append(pages, pg)
			if homeAt < 0 && (strings.TrimSuffix(link.Path, "/") == strings.TrimSuffix(home.Path, "/") ||
				it.Name == "home" || strings.EqualFold(title, "home")) {
				homeAt = len(pages) - 1
			}
			continue
		}
		pst := Post{URL: link, Title: title, Slug: it.Name, Published: day(it.Date), Blocks: read.Blocks,
			Byline: authors[it.Creator]}
		if pst.Title == "" {
			// WordPress shows a post with no title; so does this.
			pst.Title = "Untitled"
			if pst.Slug == "" {
				pst.Slug = "post-" + it.ID
			}
		}
		if pst.Byline == "" {
			pst.Byline = it.Creator
		}
		if m := day(it.Modified); m > pst.Published {
			pst.Revised = m
		}
		pst.Summary = clip(plainText(it.encoded("excerpt")), 300)
		if a, ok := attachments[it.meta("_thumbnail_id")]; ok {
			if u, err := link.Parse(a.url); err == nil {
				pst.Image, pst.Alt = u, a.alt
			}
		}
		for _, c := range it.Categories {
			v := strings.TrimSpace(html.UnescapeString(c.Value))
			if (c.Domain == "category" || c.Domain == "post_tag") && v != "" && !strings.EqualFold(v, "Uncategorized") &&
				!containsFold(pst.Tags, v) {
				pst.Tags = append(pst.Tags, v)
			}
		}
		s.Posts = append(s.Posts, pst)
	}
	// The home page first, as a crawl reads it.
	var front Page
	if homeAt >= 0 {
		front = pages[homeAt]
		front.URL = home
		pages = append(pages[:homeAt:homeAt], pages[homeAt+1:]...)
	} else {
		front = Page{URL: home, Title: s.Name}
	}
	// The main menu: the one with most top-level entries.
	var best []menuItem
	for _, items := range menus {
		var top []menuItem
		for _, m := range items {
			if m.parent == "" || m.parent == "0" {
				top = append(top, m)
			}
		}
		if len(top) > len(best) {
			best = top
		}
	}
	sort.SliceStable(best, func(i, j int) bool { return best[i].order < best[j].order })
	if len(best) > 0 {
		var nav Nav
		for _, m := range best {
			if u, err := home.Parse(m.href); err == nil {
				nav.Links = append(nav.Links, Link{Label: m.label, URL: u})
			}
		}
		front.Navs = []Nav{nav}
	} else {
		// No menu: the top-level pages, in their order.
		var nav Nav
		for _, pg := range pages {
			if len(nav.Links) < 7 && strings.Count(strings.Trim(pg.URL.Path, "/"), "/") == 0 {
				nav.Links = append(nav.Links, Link{Label: pg.Title, URL: pg.URL})
			}
		}
		front.Navs = []Nav{nav}
	}
	s.Pages = append([]Page{front}, pages...)
	if held > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf("%d draft, private, pending or scheduled post(s) and page(s) were not "+
			"brought: only what was published", held))
	}
	if comments > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf("%d comment(s) were not brought: posts here take none yet", comments))
	}
	if shortcodes > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf("%d shortcode(s) were left out, such as galleries and embeds; their "+
			"words were kept", shortcodes))
	}
	var kinds []string
	for k, n := range other {
		kinds = append(kinds, fmt.Sprintf("%d %s", n, k))
	}
	sort.Strings(kinds)
	if len(kinds) > 0 {
		s.Notes = append(s.Notes, "not pages or posts, so not brought: "+strings.Join(kinds, ", "))
	}
	if len(s.Pages) == 1 && len(s.Posts) == 0 && len(front.Blocks) == 0 {
		return nil, errors.New("the export has no published pages or posts")
	}
	return s, nil
}

var (
	reShortcode = regexp.MustCompile(`\[/?([a-zA-Z][\w-]*)((?:\s[^\[\]]*)?)/?\]`)
	reBlockOpen = regexp.MustCompile(`(?i)^<(p|div|h[1-6]|ul|ol|li|blockquote|pre|figure|table|img|hr|section|!--)\b`)
)

// wpContent is a post's content as HTML: shortcodes taken out, keeping what
// is between an opening and a closing one, and paragraphs made of blank
// lines, as WordPress does when it shows a post written in its classic
// editor. It says how many shortcodes were not captions.
func wpContent(s string) (string, int) {
	n := 0
	s = reShortcode.ReplaceAllStringFunc(s, func(m string) string {
		name := reShortcode.FindStringSubmatch(m)[1]
		if name != "caption" && !strings.HasPrefix(m, "[/") {
			n++
		}
		return ""
	})
	if strings.Contains(s, "<p") {
		return s, n
	}
	var b strings.Builder
	for _, para := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n\n") {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}
		if reBlockOpen.MatchString(para) {
			b.WriteString(para + "\n")
			continue
		}
		b.WriteString("<p>" + strings.ReplaceAll(para, "\n", "<br>") + "</p>\n")
	}
	return b.String(), n
}

// plainText is markup as its words.
func plainText(s string) string {
	var words []string
	for _, b := range Read([]byte("<main><p>"+s+"</p></main>"), &url.URL{Scheme: "https", Host: "x.invalid"}).Blocks {
		if b.Text != "" {
			words = append(words, b.Text)
		}
	}
	return strings.Join(words, " ")
}

// day is the date part of a timestamp, or "" when it has none.
func day(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 10 && s[4] == '-' && s[7] == '-' && !strings.HasPrefix(s, "0000") {
		if _, err := time.Parse("2006-01-02", s[:10]); err == nil {
			return s[:10]
		}
	}
	return ""
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// -- Ghost --------------------------------------------------------------------

type ghostDoc struct {
	DB   []struct{ Data ghostData } `json:"db"`
	Data *ghostData                 `json:"data"`
}

type ghostData struct {
	Posts []struct {
		ID              string          `json:"id"`
		Title           string          `json:"title"`
		Slug            string          `json:"slug"`
		HTML            string          `json:"html"`
		Plaintext       string          `json:"plaintext"`
		FeatureImage    string          `json:"feature_image"`
		Type            string          `json:"type"`
		Page            json.RawMessage `json:"page"`
		Status          string          `json:"status"`
		Visibility      string          `json:"visibility"`
		PublishedAt     any             `json:"published_at"`
		UpdatedAt       any             `json:"updated_at"`
		CustomExcerpt   string          `json:"custom_excerpt"`
		MetaDescription string          `json:"meta_description"`
	} `json:"posts"`
	PostsMeta []struct {
		PostID          string `json:"post_id"`
		FeatureImageAlt string `json:"feature_image_alt"`
		MetaDescription string `json:"meta_description"`
	} `json:"posts_meta"`
	Tags []struct {
		ID, Name string
	} `json:"tags"`
	PostsTags []struct {
		PostID    string `json:"post_id"`
		TagID     string `json:"tag_id"`
		SortOrder int    `json:"sort_order"`
	} `json:"posts_tags"`
	Users []struct {
		ID, Name string
	} `json:"users"`
	PostsAuthors []struct {
		PostID    string `json:"post_id"`
		AuthorID  string `json:"author_id"`
		SortOrder int    `json:"sort_order"`
	} `json:"posts_authors"`
	Settings []struct {
		Key   string `json:"key"`
		Value any    `json:"value"`
	} `json:"settings"`
}

// ghostTime reads the times Ghost writes, as text or as milliseconds.
func ghostTime(v any) string {
	switch t := v.(type) {
	case string:
		return day(t)
	case float64:
		return time.UnixMilli(int64(t)).UTC().Format("2006-01-02")
	}
	return ""
}

// FromGhost reads a Ghost export: its published public posts and pages, its
// navigation, name, description and accent colour. base is where the site
// was, which Ghost writes its pictures' addresses relative to; without it
// they cannot be fetched.
func FromGhost(body []byte, origin string, base *url.URL) (*Site, error) {
	if len(body) > MaxExportBytes {
		return nil, fmt.Errorf("the export is larger than %d MB", MaxExportBytes>>20)
	}
	var doc ghostDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("this does not read as a Ghost export: %w", err)
	}
	var d *ghostData
	switch {
	case len(doc.DB) > 0:
		d = &doc.DB[0].Data
	case doc.Data != nil:
		d = doc.Data
	default:
		return nil, errors.New("this does not read as a Ghost export: it has no data")
	}
	home := base
	if home == nil || home.Host == "" {
		home, _ = url.Parse("https://ghost.invalid/")
	}
	if home.Path == "" {
		home = home.JoinPath("/")
	}
	s := &Site{Home: home, From: KindGhost, Origin: origin}
	settings := map[string]string{}
	for _, st := range d.Settings {
		if v, ok := st.Value.(string); ok {
			settings[st.Key] = v
		}
	}
	s.Name, s.Description, s.Colour = settings["title"], settings["description"], settings["accent_color"]
	// Ghost writes its own address as __GHOST_URL__.
	ghostURL := func(raw string) *url.URL {
		raw = strings.Replace(strings.TrimSpace(raw), "__GHOST_URL__", strings.TrimSuffix(home.String(), "/"), 1)
		if raw == "" {
			return nil
		}
		u, err := home.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return nil
		}
		return u
	}
	alts, metaDesc := map[string]string{}, map[string]string{}
	for _, m := range d.PostsMeta {
		alts[m.PostID], metaDesc[m.PostID] = m.FeatureImageAlt, m.MetaDescription
	}
	tagNames := map[string]string{}
	for _, t := range d.Tags {
		tagNames[t.ID] = t.Name
	}
	tags := map[string][]string{}
	sort.SliceStable(d.PostsTags, func(i, j int) bool { return d.PostsTags[i].SortOrder < d.PostsTags[j].SortOrder })
	for _, pt := range d.PostsTags {
		// A tag beginning # is Ghost's own, for its theme, not a reader's.
		if name := tagNames[pt.TagID]; name != "" && !strings.HasPrefix(name, "#") {
			tags[pt.PostID] = append(tags[pt.PostID], name)
		}
	}
	users := map[string]string{}
	for _, u := range d.Users {
		users[u.ID] = u.Name
	}
	byline := map[string]string{}
	sort.SliceStable(d.PostsAuthors, func(i, j int) bool { return d.PostsAuthors[i].SortOrder < d.PostsAuthors[j].SortOrder })
	for _, pa := range d.PostsAuthors {
		if byline[pa.PostID] == "" {
			byline[pa.PostID] = users[pa.AuthorID]
		}
	}
	held, members, noWords := 0, 0, 0
	var pages []Page
	for _, gp := range d.Posts {
		isPage := gp.Type == "page" || string(gp.Page) == "true" || string(gp.Page) == "1"
		switch {
		case gp.Status != "published":
			held++
			continue
		case gp.Visibility != "" && gp.Visibility != "public":
			// A post for members or paying subscribers is not made public
			// by moving it.
			members++
			continue
		}
		link := home.JoinPath(gp.Slug + "/")
		content := gp.HTML
		if strings.TrimSpace(content) == "" && strings.TrimSpace(gp.Plaintext) != "" {
			for _, para := range strings.Split(gp.Plaintext, "\n\n") {
				content += "<p>" + html.EscapeString(para) + "</p>"
			}
		}
		if strings.TrimSpace(content) == "" {
			noWords++
			continue
		}
		content = strings.ReplaceAll(content, "__GHOST_URL__", strings.TrimSuffix(home.String(), "/"))
		read := Read([]byte("<main>"+content+"</main>"), link)
		excerpt := strings.TrimSpace(gp.CustomExcerpt)
		if excerpt == "" {
			excerpt = strings.TrimSpace(metaDesc[gp.ID])
		}
		if excerpt == "" {
			excerpt = strings.TrimSpace(gp.MetaDescription)
		}
		if isPage {
			pages = append(pages, Page{URL: link, Title: gp.Title, Description: clip(excerpt, 300),
				Blocks: append([]Block{{Kind: "h1", Text: gp.Title}}, read.Blocks...), Left: read.Left})
			continue
		}
		pst := Post{URL: link, Title: gp.Title, Slug: gp.Slug, Published: ghostTime(gp.PublishedAt),
			Blocks: read.Blocks, Summary: clip(excerpt, 300), Byline: byline[gp.ID], Tags: tags[gp.ID]}
		if r := ghostTime(gp.UpdatedAt); r > pst.Published {
			pst.Revised = r
		}
		if u := ghostURL(gp.FeatureImage); u != nil {
			pst.Image, pst.Alt = u, alts[gp.ID]
		}
		s.Posts = append(s.Posts, pst)
	}
	front := Page{URL: home, Title: s.Name}
	for _, key := range []string{"navigation", "secondary_navigation"} {
		var items []struct{ Label, URL string }
		if json.Unmarshal([]byte(settings[key]), &items) != nil {
			continue
		}
		nav := Nav{Foot: key != "navigation"}
		for _, it := range items {
			if u := ghostURL(it.URL); u != nil && strings.TrimSpace(it.Label) != "" {
				nav.Links = append(nav.Links, Link{Label: strings.TrimSpace(it.Label), URL: u})
			}
		}
		if len(nav.Links) > 0 {
			front.Navs = append(front.Navs, nav)
		}
	}
	s.Pages = append([]Page{front}, pages...)
	if held > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf("%d draft or scheduled post(s) were not brought: only what was published", held))
	}
	if members > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf("%d post(s) for members or paying subscribers were not brought: a post "+
			"here is public, and moving them must not make them so", members))
	}
	if noWords > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf("%d post(s) had no words in the export, which happens with older Ghost "+
			"versions; export again from Ghost 5", noWords))
	}
	if base == nil || base.Host == "" {
		s.Notes = append(s.Notes, "Ghost names its pictures by its own address: give the address it was at to bring them")
	}
	if len(s.Posts) == 0 && len(pages) == 0 {
		return nil, errors.New("the export has no published public posts or pages")
	}
	return s, nil
}
