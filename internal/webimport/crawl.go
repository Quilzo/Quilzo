// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// Fetched is what came back for one address.
type Fetched struct {
	FinalURL    string
	Status      int
	ContentType string
	Body        []byte
	// Truncated says the body was cut off at the fetcher's ceiling.
	Truncated bool
}

// Getter fetches one address. The command gives it the fetcher that
// refuses private addresses (internal/fetch); tests give it a site.
type Getter func(ctx context.Context, raw string) (*Fetched, error)

// Options bound a crawl.
type Options struct {
	// Max is how many pages are read; 0 is DefaultPages.
	Max int
	// Delay is the pause between requests, so a small site's host is not
	// hurried; 0 is DefaultDelay, and a test sets it negative for none.
	Delay time.Duration
	Get   Getter
}

// Bounds on a crawl.
const (
	DefaultPages = 60
	MaxPages     = 400
	DefaultDelay = 250 * time.Millisecond
	// agent is how this reader names itself to robots.txt.
	agent = "quilzo"
)

// Site is a site as it was read.
type Site struct {
	// Home is the address the crawl started from.
	Home *url.URL
	// Pages are what was read, the home page first.
	Pages []Page
	// From says how the pages were found: the site's map of itself, or its
	// links.
	From string
	// Refused are addresses robots.txt asked this not to read; Failed are
	// ones that did not answer with a page.
	Refused, Failed []string
	// Capped says there were more pages than the budget.
	Capped bool
}

// Crawl reads a site from its home page.
func Crawl(ctx context.Context, start string, opt Options) (*Site, error) {
	if opt.Get == nil {
		return nil, errors.New("nothing to fetch with")
	}
	if opt.Max <= 0 {
		opt.Max = DefaultPages
	}
	if opt.Max > MaxPages {
		opt.Max = MaxPages
	}
	if opt.Delay == 0 {
		opt.Delay = DefaultDelay
	}
	home, err := url.Parse(strings.TrimSpace(start))
	if err != nil || (home.Scheme != "https" && home.Scheme != "http") || home.Host == "" || home.User != nil {
		return nil, fmt.Errorf("%q is not a web address; give the site's home page, such as https://example.com", start)
	}
	home.Fragment, home.RawQuery = "", ""
	if home.Path == "" {
		home.Path = "/"
	}
	c := &crawler{ctx: ctx, opt: opt, home: home, seen: map[string]bool{}}
	c.robots = c.readRobots()
	site := &Site{Home: home}

	queue := []*url.URL{home}
	if locs := c.sitemap(); len(locs) > 0 {
		site.From = "sitemap"
		queue = append(queue, locs...)
	} else {
		site.From = "links"
	}
	for len(queue) > 0 && len(site.Pages) < opt.Max {
		if err := ctx.Err(); err != nil {
			return site, err
		}
		u := queue[0]
		queue = queue[1:]
		key := c.key(u)
		if c.seen[key] {
			continue
		}
		c.seen[key] = true
		if !c.allowed(u.Path) {
			site.Refused = append(site.Refused, u.String())
			continue
		}
		p, err := c.page(u)
		if err != nil {
			site.Failed = append(site.Failed, fmt.Sprintf("%s: %v", u, err))
			continue
		}
		site.Pages = append(site.Pages, p)
		if site.From == "links" {
			for _, l := range p.Links {
				if c.same(l) && !c.seen[c.key(l)] && pageLike(l) {
					queue = append(queue, l)
				}
			}
		}
	}
	for _, u := range queue {
		if !c.seen[c.key(u)] {
			site.Capped = true
			break
		}
	}
	if len(site.Pages) == 0 {
		return site, fmt.Errorf("no page of %s could be read", home.Host)
	}
	return site, nil
}

type crawler struct {
	ctx    context.Context
	opt    Options
	home   *url.URL
	seen   map[string]bool
	robots []rule
	asked  int
}

// get fetches politely: a pause before every request but the first.
func (c *crawler) get(raw string) (*Fetched, error) {
	if c.asked > 0 && c.opt.Delay > 0 {
		select {
		case <-time.After(c.opt.Delay):
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
		}
	}
	c.asked++
	return c.opt.Get(c.ctx, raw)
}

// same is whether an address is on the site being read: the same host, or
// the same host with or without www.
func (c *crawler) same(u *url.URL) bool {
	strip := func(h string) string { return strings.TrimPrefix(strings.ToLower(h), "www.") }
	return strip(u.Host) == strip(c.home.Host) && (u.Scheme == "https" || u.Scheme == "http")
}

// key is an address as a page is known: no query, no trailing slash.
func (c *crawler) key(u *url.URL) string {
	p := strings.TrimSuffix(u.EscapedPath(), "/")
	return strings.TrimPrefix(strings.ToLower(u.Host), "www.") + p
}

// pageLike leaves out what is plainly not a page: files by their suffix,
// and addresses with a query, which are usually the same page again.
func pageLike(u *url.URL) bool {
	if u.RawQuery != "" {
		return false
	}
	switch strings.ToLower(path.Ext(u.Path)) {
	case "", ".html", ".htm", ".php", ".asp", ".aspx", ".shtml":
		return true
	}
	return false
}

func (c *crawler) page(u *url.URL) (Page, error) {
	res, err := c.get(u.String())
	if err != nil {
		return Page{}, err
	}
	if res.Status != 200 {
		return Page{}, fmt.Errorf("answered %d", res.Status)
	}
	if ct := strings.ToLower(res.ContentType); ct != "" && !strings.Contains(ct, "html") {
		return Page{}, fmt.Errorf("is %s, not a page", ct)
	}
	final := u
	if f, err := url.Parse(res.FinalURL); err == nil && f.Host != "" {
		if !c.same(f) {
			return Page{}, fmt.Errorf("moved to %s, another site", f.Host)
		}
		final = f
	}
	return Read(res.Body, final), nil
}

// -- robots.txt ---------------------------------------------------------------

type rule struct {
	allow  bool
	prefix string
}

// readRobots reads the rules for this reader, or for every reader when none
// name it. A site with no robots.txt asks nothing.
func (c *crawler) readRobots() []rule {
	res, err := c.get(c.home.ResolveReference(&url.URL{Path: "/robots.txt"}).String())
	if err != nil || res.Status != 200 {
		return nil
	}
	return robotsRules(string(res.Body), agent)
}

func robotsRules(txt, name string) []rule {
	groups := map[string][]rule{}
	var agents []string
	inRules := false
	for _, line := range strings.Split(txt, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "user-agent":
			if inRules {
				agents, inRules = nil, false
			}
			agents = append(agents, strings.ToLower(v))
		case "allow", "disallow":
			inRules = true
			for _, a := range agents {
				if v != "" || k == "allow" {
					groups[a] = append(groups[a], rule{allow: k == "allow", prefix: v})
				} else if _, ok := groups[a]; !ok {
					groups[a] = nil
				}
			}
		}
	}
	if r, ok := groups[name]; ok {
		return r
	}
	return groups["*"]
}

// allowed applies the longest matching rule, as robots.txt is read: * is any
// run of characters, a final $ ends the match, and an allow wins a tie.
func (c *crawler) allowed(p string) bool {
	if p == "" {
		p = "/"
	}
	best, allow := -1, true
	for _, r := range c.robots {
		if !robotsMatch(r.prefix, p) {
			continue
		}
		if n := len(r.prefix); n > best || (n == best && r.allow) {
			best, allow = n, r.allow
		}
	}
	return allow
}

// robotsMatch reports whether a robots.txt path pattern matches a path.
func robotsMatch(pattern, p string) bool {
	anchored := strings.HasSuffix(pattern, "$")
	pattern = strings.TrimSuffix(pattern, "$")
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(p, parts[0]) {
		return false
	}
	rest := p[len(parts[0]):]
	for i, part := range parts[1:] {
		last := i == len(parts)-2
		if last && anchored {
			return strings.HasSuffix(rest, part)
		}
		j := strings.Index(rest, part)
		if j < 0 {
			return false
		}
		rest = rest[j+len(part):]
	}
	return !anchored || rest == ""
}

// -- sitemap ------------------------------------------------------------------

// sitemap reads the site's map of itself, following one level of index, and
// returns the pages on this site it lists.
func (c *crawler) sitemap() []*url.URL {
	type loc struct {
		Loc string `xml:"loc"`
	}
	type doc struct {
		XMLName  xml.Name
		URLs     []loc `xml:"url"`
		Sitemaps []loc `xml:"sitemap"`
	}
	read := func(raw string) *doc {
		res, err := c.get(raw)
		if err != nil || res.Status != 200 {
			return nil
		}
		var d doc
		if xml.Unmarshal(res.Body, &d) != nil {
			return nil
		}
		return &d
	}
	d := read(c.home.ResolveReference(&url.URL{Path: "/sitemap.xml"}).String())
	if d == nil {
		return nil
	}
	locs := d.URLs
	for i, s := range d.Sitemaps {
		if i >= 10 {
			break
		}
		if u, err := url.Parse(strings.TrimSpace(s.Loc)); err == nil && c.same(u) {
			if sub := read(u.String()); sub != nil {
				locs = append(locs, sub.URLs...)
			}
		}
	}
	var out []*url.URL
	seen := map[string]bool{}
	for _, l := range locs {
		u, err := url.Parse(strings.TrimSpace(l.Loc))
		if err != nil || !c.same(u) || !pageLike(u) || seen[c.key(u)] {
			continue
		}
		seen[c.key(u)] = true
		out = append(out, u)
	}
	// Shallow pages first, so a budget smaller than the site keeps its top.
	sort.SliceStable(out, func(i, j int) bool {
		return strings.Count(strings.Trim(out[i].Path, "/"), "/") < strings.Count(strings.Trim(out[j].Path, "/"), "/")
	})
	return out
}
