// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/yamlite"
)

// A site brought from a folder of files: the Markdown a static site
// generator builds from (Hugo, Jekyll, Eleventy, Astro, Docusaurus, Gatsby),
// a Notion or Obsidian export, or the pages a site builder exports (Webflow)
// or a static site already is. A folder of Markdown is read as its source;
// one with none, as its pages.
//
// The files are read where they are, from a directory or a zip, and never
// executed: a generator's templates, shortcodes and scripts are left behind,
// and so is everything outside the folder.

// LocalHost stands for the folder in the addresses its pages are read at.
// A picture there is a file of the folder, given to the caller as a
// file: address with its path.
const LocalHost = "files.quilzo.invalid"

// Limits on a folder: how many files are looked at, how large one may be,
// and how much is read in all.
const (
	MaxFolderFiles = 20000
	maxFileBytes   = 8 << 20
	maxFolderBytes = 256 << 20
)

// skippedDirs are a folder's parts that are not its content: what a
// generator builds from beside it, builds into, or keeps for itself.
var skippedDirs = map[string]bool{
	"node_modules": true, "vendor": true, "_site": true, "dist": true, "build": true, ".next": true,
	"_includes": true, "_layouts": true, "_data": true, "_sass": true, "layouts": true, "themes": true,
	"archetypes": true, "i18n": true, "resources": true, "partials": true, "components": true,
}

// postDirs hold a blog's posts, by the names the generators give them.
var postDirs = map[string]bool{"_posts": true, "posts": true, "post": true, "blog": true, "news": true,
	"articles": true, "writing": true}

// notContent are files at the top of a folder that describe the project
// rather than the site.
var notContent = map[string]bool{"readme": true, "license": true, "licence": true, "changelog": true,
	"contributing": true, "code_of_conduct": true, "security": true, "authors": true, "notice": true}

var (
	reJekyllDate = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})-(.+)$`)
	reNotionID   = regexp.MustCompile(`\s+[0-9a-f]{32}$`)
)

// FromFiles reads a folder of Markdown, or of web pages.
func FromFiles(fsys fs.FS, origin string) (*Site, error) {
	home := &url.URL{Scheme: "https", Host: LocalHost, Path: "/"}
	s := &Site{Home: home, From: KindFiles, Origin: origin}
	var md, pages, all []string
	total := 0
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if p != "." && (strings.HasPrefix(name, ".") || skippedDirs[name]) {
				return fs.SkipDir
			}
			if name == "_drafts" {
				s.Notes = append(s.Notes, "the drafts in "+p+" were not brought: only what was published")
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasPrefix(name, ".") {
			return nil
		}
		if total++; total > MaxFolderFiles {
			return fmt.Errorf("the folder has more than %d files", MaxFolderFiles)
		}
		all = append(all, p)
		switch strings.ToLower(path.Ext(name)) {
		case ".md", ".markdown", ".mdx", ".mdown":
			base := strings.ToLower(strings.TrimSuffix(name, path.Ext(name)))
			if path.Dir(p) == "." && notContent[base] {
				return nil
			}
			md = append(md, p)
		case ".html", ".htm":
			pages = append(pages, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	f := &folder{fsys: fsys, files: map[string]bool{}}
	for _, p := range all {
		f.files[p] = true
	}
	switch {
	case len(md) > 0:
		err = f.markdown(s, md)
	case len(pages) > 0:
		err = f.pages(s, pages)
	default:
		return nil, errors.New("the folder has no Markdown and no web pages")
	}
	if err != nil {
		return nil, err
	}
	if f.read > maxFolderBytes {
		s.Notes = append(s.Notes, "the folder was larger than is read at once, so some of it was left out")
	}
	return s, nil
}

// folder is a folder being read.
type folder struct {
	fsys  fs.FS
	files map[string]bool
	read  int
}

// readFile reads one file within the limits.
func (f *folder) readFile(p string) ([]byte, bool) {
	if f.read > maxFolderBytes {
		return nil, false
	}
	file, err := f.fsys.Open(p)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil || len(b) > maxFileBytes {
		return nil, false
	}
	f.read += len(b)
	return b, true
}

// fileURL is a file of the folder, as a picture's address.
func fileURL(p string) *url.URL { return &url.URL{Scheme: "file", Path: "/" + p} }

// localURL is where a file of the folder was on the site it built.
func localURL(p string) *url.URL {
	return &url.URL{Scheme: "https", Host: LocalHost, Path: "/" + strings.TrimPrefix(p, "/")}
}

// resolver says where a reference in a file at p is: a picture as a file
// of the folder or an address elsewhere, a link as a page here or an
// address elsewhere. roots are where a reference from the site's root is
// looked for.
func (f *folder) resolver(p, root string, roots []string) func(string, bool) *url.URL {
	dir := path.Dir(p)
	return func(ref string, picture bool) *url.URL {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "#") {
			return nil
		}
		if u, err := url.Parse(ref); err == nil && u.Scheme != "" {
			if u.Scheme == "http" || u.Scheme == "https" || (!picture && (u.Scheme == "mailto" || u.Scheme == "tel")) {
				return u
			}
			return nil
		}
		ref, _, _ = strings.Cut(ref, "#")
		ref, _, _ = strings.Cut(ref, "?")
		if dec, err := url.PathUnescape(ref); err == nil {
			ref = dec
		}
		var candidates []string
		if strings.HasPrefix(ref, "/") {
			for _, r := range roots {
				candidates = append(candidates, path.Join(r, ref))
			}
		} else {
			candidates = append(candidates, path.Join(dir, ref))
		}
		if picture {
			for _, c := range candidates {
				if c = strings.TrimPrefix(c, "/"); f.files[c] {
					return fileURL(c)
				}
			}
			return nil
		}
		// A link: to the page the file it names became. One from the root is
		// already the address it was at; one to a file is the file's place
		// under the content.
		target := ref
		if !strings.HasPrefix(ref, "/") {
			target = path.Join(dir, ref)
			if root != "." {
				target = strings.TrimPrefix(target, root+"/")
			}
		}
		target = strings.TrimPrefix(target, "/")
		for _, ext := range []string{".md", ".markdown", ".mdx", ".html", ".htm"} {
			target = strings.TrimSuffix(target, ext)
		}
		for _, index := range []string{"index", "_index", "README"} {
			if target == index {
				target = ""
			}
			target = strings.TrimSuffix(target, "/"+index)
		}
		return localURL(target)
	}
}

// matter is a file's front matter and the rest of it.
func matter(src string) (map[string]any, string) {
	src = strings.TrimPrefix(strings.ReplaceAll(src, "\r\n", "\n"), "\ufeff")
	for _, fence := range []string{"---", "+++"} {
		if !strings.HasPrefix(src, fence+"\n") {
			continue
		}
		end := strings.Index(src[len(fence)+1:], "\n"+fence)
		if end < 0 {
			return nil, src
		}
		head := src[len(fence)+1 : len(fence)+1+end]
		rest := strings.TrimLeft(src[len(fence)+1+end+len(fence)+1:], "-+")
		if fence == "---" {
			if v, err := yamlite.Parse([]byte(head)); err == nil {
				m, _ := v.(map[string]any)
				return m, rest
			}
			return flatMatter(head, ":"), rest
		}
		return flatMatter(head, "="), rest
	}
	if strings.HasPrefix(src, "{\n") {
		dec := json.NewDecoder(strings.NewReader(src))
		var m map[string]any
		if dec.Decode(&m) == nil {
			return m, src[dec.InputOffset():]
		}
	}
	return nil, src
}

// flatMatter reads key and value lines: TOML front matter, or YAML the
// YAML reader refused, for what can be read of it.
func flatMatter(head, sep string) map[string]any {
	m := map[string]any{}
	for _, line := range strings.Split(head, "\n") {
		k, v, ok := strings.Cut(line, sep)
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" || strings.HasPrefix(k, "#") || strings.HasPrefix(k, "[") {
			continue
		}
		switch {
		case strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]"):
			var list []any
			for _, item := range strings.Split(strings.Trim(v, "[]"), ",") {
				if item = strings.Trim(strings.TrimSpace(item), `"'`); item != "" {
					list = append(list, item)
				}
			}
			m[k] = list
		case v == "true" || v == "false":
			m[k] = v == "true"
		default:
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

// text is a front matter field as words.
func text(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		case map[string]any:
			// cover: {image: …, alt: …}, as some themes write a picture.
			if s := text(v, "image", "src", "url", "name"); s != "" {
				return s
			}
		case []any:
			if len(v) > 0 {
				if s, ok := v[0].(string); ok {
					return strings.TrimSpace(s)
				}
				if mm, ok := v[0].(map[string]any); ok {
					return text(mm, "name")
				}
			}
		}
	}
	return ""
}

// list is a front matter field as a list of words.
func list(m map[string]any, keys ...string) []string {
	var out []string
	for _, k := range keys {
		switch v := m[k].(type) {
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok && strings.TrimSpace(s) != "" && !containsFold(out, s) {
					out = append(out, strings.TrimSpace(s))
				}
			}
		case string:
			for _, s := range strings.Split(v, ",") {
				if s = strings.TrimSpace(s); s != "" && !containsFold(out, s) {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// dateOf reads the dates generators write, as YYYY-MM-DD.
func dateOf(v string) string {
	v = strings.TrimSpace(v)
	if d := day(v); d != "" {
		return d
	}
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, "January 2, 2006", "2 January 2006", "Jan 2, 2006"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.Format("2006-01-02")
		}
	}
	return ""
}

// truthy is a front matter flag.
func truthy(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "yes"
	}
	return false
}

// markdown reads a folder of Markdown.
func (f *folder) markdown(s *Site, files []string) error {
	// Where the content is: Hugo's content, Astro's src/content or
	// src/pages, or the folder itself.
	root := "."
	for _, r := range []string{"content", "src/content", "src/pages"} {
		for _, p := range files {
			if strings.HasPrefix(p, r+"/") {
				root = r
				break
			}
		}
		if root != "." {
			break
		}
	}
	roots := []string{"static", "public", ".", "assets", "src", root}
	jekyll := f.files["_config.yml"] || f.files["_config.yaml"]
	f.config(s)

	type entry struct {
		page   Page
		order  float64
		inMenu bool
	}
	var pages []entry
	var front *Page
	drafts := 0
	for _, p := range files {
		rel := p
		if root != "." {
			if !strings.HasPrefix(p, root+"/") && !strings.HasPrefix(p, "_posts/") {
				continue
			}
			rel = strings.TrimPrefix(p, root+"/")
		}
		raw, ok := f.readFile(p)
		if !ok {
			s.Notes = append(s.Notes, p+" was too large to read")
			continue
		}
		fm, body := matter(string(raw))
		if fm == nil {
			fm = map[string]any{}
		}
		if truthy(fm, "draft") || truthy(fm, "private") || fm["published"] == false {
			drafts++
			continue
		}
		if strings.EqualFold(path.Ext(p), ".mdx") {
			// MDX: its imports and exports are code.
			var kept []string
			for _, l := range strings.Split(body, "\n") {
				if t := strings.TrimSpace(l); !strings.HasPrefix(t, "import ") && !strings.HasPrefix(t, "export ") {
					kept = append(kept, l)
				}
			}
			body = strings.Join(kept, "\n")
		}
		base := strings.TrimSuffix(path.Base(rel), path.Ext(rel))
		base = reNotionID.ReplaceAllString(base, "")
		dir := path.Dir(rel)
		isPost := text(fm, "layout", "type") == "post"
		for _, part := range strings.Split(dir, "/") {
			if postDirs[strings.ToLower(part)] {
				isPost = true
			}
		}
		date := dateOf(text(fm, "date", "publishDate", "pubDate", "published", "created"))
		if m := reJekyllDate.FindStringSubmatch(base); m != nil {
			if date == "" {
				date = m[1] + "-" + m[2] + "-" + m[3]
			}
			base = m[4]
		}
		// A section's own page lists what is in it (Hugo's _index); a
		// folder's index, or its README, is a page at the folder's address,
		// and in Hugo a post with its pictures beside it.
		listPage := base == "_index"
		bundle := base == "index" || strings.EqualFold(base, "readme")
		if listPage && isPost {
			// The posts' own list: the blog lists them now.
			continue
		}
		if bundle && dir != "." && dir != "" {
			base = path.Base(dir)
		}
		// Where it was: what the file said, or where its path put it.
		where := text(fm, "permalink", "url")
		if where == "" || !strings.HasPrefix(where, "/") {
			where = path.Join("/", dir)
			if !listPage && !bundle {
				where = path.Join(where, base)
			}
			if jekyll && isPost && date != "" {
				where = "/" + strings.ReplaceAll(date, "-", "/") + "/" + base + ".html"
			}
		}
		link := localURL(where)
		resolve := f.resolver(p, root, roots)
		blocks := mdBlocks(body, resolve)
		title := text(fm, "title", "linkTitle")
		if title == "" {
			for _, b := range blocks {
				if b.Kind == "h1" {
					title = b.Text
					break
				}
			}
		}
		if title == "" {
			title = strings.TrimSpace(strings.NewReplacer("-", " ", "_", " ").Replace(base))
		}
		summary := text(fm, "description", "summary", "excerpt", "subtitle")
		if isPost {
			if date == "" {
				s.Notes = append(s.Notes, "the post "+p+" has no date, so it was brought as a page")
			} else {
				pst := Post{URL: link, Title: title, Slug: text(fm, "slug"), Published: date, Blocks: blocks,
					Summary: clip(summary, 300), Byline: text(fm, "author", "authors"),
					Revised: dateOf(text(fm, "lastmod", "updated", "updatedDate", "modified", "last_modified_at")),
					Tags:    list(fm, "tags", "categories", "keywords")}
				if pst.Slug == "" {
					pst.Slug = base
				}
				if img := text(fm, "image", "cover", "featured_image", "heroImage", "thumbnail", "banner"); img != "" {
					pst.Image = resolve(img, true)
					pst.Alt = text(fm, "image_alt", "imageAlt", "alt", "cover_alt")
					if c, ok := fm["cover"].(map[string]any); ok && pst.Alt == "" {
						pst.Alt = text(c, "alt", "caption")
					}
				}
				pst.Aliases = list(fm, "aliases", "redirect_from")
				s.Posts = append(s.Posts, pst)
				continue
			}
		}
		if len(blocks) == 0 || blocks[0].Kind != "h1" {
			blocks = append([]Block{{Kind: "h1", Text: title}}, blocks...)
		}
		pg := Page{URL: link, Title: title, Description: clip(summary, 300), Blocks: blocks}
		if (listPage || bundle) && (dir == "." || dir == "") {
			pg.URL = s.Home
			front = &pg
			continue
		}
		order, _ := strconv.ParseFloat(text(fm, "weight", "nav_order", "sidebar_position", "order"), 64)
		_, inMenu := fm["menu"]
		pages = append(pages, entry{pg, order, inMenu})
	}
	if drafts > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf("%d draft(s) were not brought: only what was published", drafts))
	}
	sort.SliceStable(pages, func(i, j int) bool {
		if pages[i].order != pages[j].order {
			return pages[i].order < pages[j].order
		}
		return pages[i].page.URL.Path < pages[j].page.URL.Path
	})
	if front == nil {
		front = &Page{URL: s.Home, Title: s.Name}
	}
	// The main menu: the pages that asked to be in it, or the top-level ones.
	nav := Nav{}
	menued := false
	for _, e := range pages {
		menued = menued || e.inMenu
	}
	for _, e := range pages {
		top := strings.Count(strings.Trim(e.page.URL.Path, "/"), "/") == 0
		if (menued && e.inMenu) || (!menued && top) {
			if len(nav.Links) < 7 {
				nav.Links = append(nav.Links, Link{Label: e.page.Title, URL: e.page.URL})
			}
		}
	}
	if len(nav.Links) > 0 {
		front.Navs = []Nav{nav}
	}
	s.Pages = []Page{*front}
	for _, e := range pages {
		s.Pages = append(s.Pages, e.page)
	}
	return nil
}

// config reads what a generator's settings say the site is called.
func (f *folder) config(s *Site) {
	for _, name := range []string{"hugo.toml", "config.toml", "hugo.yaml", "config.yaml", "hugo.yml", "config.yml",
		"_config.yml", "_config.yaml", "mkdocs.yml"} {
		if !f.files[name] {
			continue
		}
		raw, ok := f.readFile(name)
		if !ok {
			continue
		}
		var m map[string]any
		if strings.HasSuffix(name, ".toml") {
			m = flatMatter(string(raw), "=")
		} else if v, err := yamlite.Parse(raw); err == nil {
			m, _ = v.(map[string]any)
		} else {
			m = flatMatter(string(raw), ":")
		}
		if s.Name == "" {
			s.Name = text(m, "title", "site_name", "name")
		}
		if s.Description == "" {
			s.Description = text(m, "description", "site_description", "tagline")
			if p, ok := m["params"].(map[string]any); ok && s.Description == "" {
				s.Description = text(p, "description")
			}
		}
	}
}

// pages reads a folder of web pages, as a crawl reads a site.
func (f *folder) pages(s *Site, files []string) error {
	sort.SliceStable(files, func(i, j int) bool {
		// The home page first, then the rest by where they are.
		hi, hj := files[i] == "index.html" || files[i] == "index.htm", files[j] == "index.html" || files[j] == "index.htm"
		if hi != hj {
			return hi
		}
		return files[i] < files[j]
	})
	for _, p := range files {
		if len(s.Pages) >= MaxPages {
			s.Capped = true
			break
		}
		raw, ok := f.readFile(p)
		if !ok {
			s.Notes = append(s.Notes, p+" was too large to read")
			continue
		}
		where := "/" + p
		if b := path.Base(p); b == "index.html" || b == "index.htm" {
			where = strings.TrimSuffix(path.Dir(where), "/") + "/"
		}
		pg := Read(raw, localURL(where))
		if len(s.Pages) == 0 {
			pg.URL = s.Home
		}
		// Its pictures are the folder's files.
		resolve := f.resolver(p, ".", []string{"."})
		kept := pg.Blocks[:0]
		for _, b := range pg.Blocks {
			if b.Kind == "img" && b.Src != nil && b.Src.Host == LocalHost {
				if b.Src = resolve(b.Src.Path, true); b.Src == nil {
					continue
				}
			}
			kept = append(kept, b)
		}
		pg.Blocks = kept
		s.Pages = append(s.Pages, pg)
	}
	if len(s.Pages) == 0 {
		return errors.New("none of the folder's web pages could be read")
	}
	if s.Name == "" {
		s.Name = s.Pages[0].SiteName
	}
	return nil
}
