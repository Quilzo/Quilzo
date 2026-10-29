// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/section"
)

// site is a website in memory, by path.
type site struct {
	pages  map[string]string
	asked  []string
	typeOf map[string]string
}

func (s *site) get(_ context.Context, raw string) (*Fetched, error) {
	u, _ := url.Parse(raw)
	s.asked = append(s.asked, u.Path)
	if u.Host != "hartsbakery.example" && u.Host != "www.hartsbakery.example" {
		return nil, errors.New("another host was asked")
	}
	body, ok := s.pages[u.Path]
	if !ok {
		return &Fetched{FinalURL: raw, Status: 404}, nil
	}
	ct := "text/html; charset=utf-8"
	if t, ok := s.typeOf[u.Path]; ok {
		ct = t
	}
	return &Fetched{FinalURL: raw, Status: 200, ContentType: ct, Body: []byte(body)}, nil
}

const head = `<!doctype html><html lang="en-GB"><head><meta charset="utf-8">
<meta property="og:site_name" content="Hart's Bakery"><meta name="theme-color" content="#c2410c">`

const header = `<header><a href="/">Hart's Bakery</a><nav><a href="/">Home</a> <a href="/menu/">Menu</a>
<a href="/visit.html">Visit</a><a href="https://instagram.example/harts">Instagram</a></nav></header>`

const foot = `<footer><nav><a href="/privacy/">Privacy</a></nav><p>© Hart's Bakery</p></footer>`

func bakery() *site {
	return &site{pages: map[string]string{
		"/robots.txt": "User-agent: *\nDisallow: /private\n",
		"/": head + `<title>Home | Hart's Bakery</title><meta name="description" content="Bread baked before dawn in Leeds."></head><body>` +
			header + `<main><h1>Bread baked before dawn</h1><p>Sourdough, rye and pastries from four o'clock.</p>
<img src="/img/loaf.jpg" alt="A sourdough loaf on a board"><img src="/img/deco.png">
<h2>What we bake</h2><ul><li>Country sourdough</li><li>Seeded rye</li></ul>
<p>Everything is &amp; always has been made by hand.</p>
<script>track('home')</script><form action="/subscribe"><label>Email</label><input name=e></form>
<a href="/private/staff">Staff</a> <a href="/menu/?print=1">Print</a> <a href="/menu.pdf">PDF</a></main>` + foot + `</body></html>`,
		"/menu/": head + `<title>Menu | Hart's Bakery</title></head><body>` + header +
			`<main><h1>Menu</h1><h2>Bread</h2><p>Country sourdough, £4.20.</p><p>Seeded rye, £4.60.</p></main>` + foot + `</body></html>`,
		"/visit.html": head + `<title>Visit | Hart's Bakery</title></head><body>` + header +
			`<article><h1>Visit us</h1><p>4 Mill Lane, Leeds.</p><iframe src="https://maps.example/"></iframe></article>` + foot + `</body></html>`,
		"/privacy/":      head + `<title>Privacy | Hart's Bakery</title></head><body><p>We keep nothing.</p></body></html>`,
		"/private/staff": head + `<title>Staff</title></head><body><p>Rota.</p></body></html>`,
		"/menu.pdf":      "%PDF",
		"/img/loaf.jpg":  "jpeg",
	}, typeOf: map[string]string{"/menu.pdf": "application/pdf"}}
}

func crawlOf(t *testing.T, s *site, max int) *Site {
	t.Helper()
	got, err := Crawl(context.Background(), "https://hartsbakery.example/", Options{Max: max, Delay: -1, Get: s.get})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A page is read as a person reads it: its content, not its header, footer,
// scripts or forms; its navigation; and what it says about its site.
func TestAPageIsReadAsAPersonReadsIt(t *testing.T) {
	base, _ := url.Parse("https://hartsbakery.example/")
	p := Read([]byte(bakery().pages["/"]), base)
	if p.Title != "Home | Hart's Bakery" || p.Description != "Bread baked before dawn in Leeds." || p.SiteName != "Hart's Bakery" ||
		p.ThemeColour != "#c2410c" || p.Lang != "en-GB" {
		t.Fatalf("the page says %+v", p)
	}
	var kinds, texts []string
	for _, b := range p.Blocks {
		kinds = append(kinds, b.Kind)
		texts = append(texts, b.Text)
	}
	if strings.Join(kinds, ",") != "h1,p,img,img,h2,li,li,p" {
		t.Fatalf("the blocks are %v: %q", kinds, texts)
	}
	joined := strings.Join(texts, "|")
	if strings.Contains(joined, "track(") || strings.Contains(joined, "Email") || strings.Contains(joined, "©") ||
		!strings.Contains(joined, "made by hand") || !strings.Contains(joined, "& always") {
		t.Fatalf("the content is %q", joined)
	}
	if p.Left["script"] != 1 || p.Left["form"] != 1 {
		t.Fatalf("left behind %v", p.Left)
	}
	if len(p.Navs) != 2 || p.Navs[0].Foot || !p.Navs[1].Foot || len(p.Navs[0].Links) != 4 || p.Navs[0].Links[1].Label != "Menu" {
		t.Fatalf("the navigation is %+v", p.Navs)
	}
	if p.Blocks[2].Src.String() != "https://hartsbakery.example/img/loaf.jpg" || p.Blocks[2].Text != "A sourdough loaf on a board" {
		t.Fatalf("the picture is %+v", p.Blocks[2])
	}
}

// A crawl reads only this site's pages, never one robots.txt asks it not
// to, never a file or the same page again, and stops at its budget.
func TestACrawlReadsOnlyWhatItMay(t *testing.T) {
	s := bakery()
	got := crawlOf(t, s, 10)
	var read []string
	for _, p := range got.Pages {
		read = append(read, p.URL.Path)
	}
	if strings.Join(read, ",") != "/,/menu/,/visit.html,/privacy/" || got.From != "links" {
		t.Fatalf("read %v from %s", read, got.From)
	}
	if len(got.Refused) != 1 || !strings.Contains(got.Refused[0], "/private/staff") {
		t.Fatalf("refused %v", got.Refused)
	}
	for _, a := range s.asked {
		if strings.HasPrefix(a, "/private") || a == "/menu.pdf" {
			t.Fatalf("asked for %s", a)
		}
	}

	// With a map of itself, the site is read from its map, top first.
	s = bakery()
	s.pages["/sitemap.xml"] = `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://hartsbakery.example/visit.html</loc></url><url><loc>https://elsewhere.example/x</loc></url>
<url><loc>https://www.hartsbakery.example/menu/</loc></url></urlset>`
	got = crawlOf(t, s, 2)
	if got.From != "sitemap" || len(got.Pages) != 2 || got.Pages[1].URL.Path != "/visit.html" || !got.Capped {
		t.Fatalf("from the map: %s, %d pages, capped %v", got.From, len(got.Pages), got.Capped)
	}

	if _, err := Crawl(context.Background(), "javascript:alert(1)", Options{Get: s.get}); err == nil {
		t.Fatal("a script address was crawled")
	}
	if _, err := Crawl(context.Background(), "https://user:pass@hartsbakery.example/", Options{Get: s.get}); err == nil {
		t.Fatal("an address with a password in it was crawled")
	}
}

func TestRobotsRulesAreReadAsCrawlersReadThem(t *testing.T) {
	c := &crawler{robots: robotsRules("User-agent: other\nDisallow: /\n\nUser-agent: *\nDisallow: /a\nAllow: /a/b\nDisallow: /*.pdf$\n", agent)}
	for p, want := range map[string]bool{"/": true, "/a": false, "/a/c": false, "/a/b/c": true, "/x.pdf": false, "/x.pdfs": true} {
		if c.allowed(p) != want {
			t.Errorf("%s allowed is %v", p, !want)
		}
	}
	c = &crawler{robots: robotsRules("User-agent: quilzo\nDisallow:\n\nUser-agent: *\nDisallow: /\n", agent)}
	if !c.allowed("/anything") {
		t.Error("a site that lets this reader in by name was not read")
	}
}

// A site that was read becomes a package that installs: its name, colour,
// pages in sections, menus from its own navigation, pictures with the
// descriptions it gave them, redirects for every address that changed, and
// notes for everything left behind.
func TestASiteBecomesAPackage(t *testing.T) {
	s := crawlOf(t, bakery(), 10)
	var stored []string
	b, err := Package(s, "", "dana", func(src *url.URL, alt string) (string, error) {
		stored = append(stored, src.Path+"="+alt)
		return "/media/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := b.Package
	if err := p.Validate(feature.Checks{}); err != nil {
		t.Fatal(err)
	}
	if p.Site.Name != "Hart's Bakery" || p.Site.Colour != "#c2410c" || p.Site.Description != "Bread baked before dawn in Leeds." ||
		p.Name != "harts-bakery" || p.Made.From != "https://hartsbakery.example/" {
		t.Fatalf("the site is %+v, %s", p.Site, p.Name)
	}
	pages := map[string]map[string]any{}
	for _, pg := range p.Pages {
		pages[pg.Name] = pg.Body
		if bad, _ := section.Validate(pg.Body); len(bad) > 0 {
			t.Errorf("page %s: %v", pg.Name, bad)
		}
	}
	for _, n := range []string{"index", "menu", "visit", "privacy"} {
		if pages[n] == nil {
			t.Fatalf("no %s page: %v", n, p.Pages)
		}
	}
	index := pages["index"]
	hero := index["hero"].(map[string]any)
	if index["title"] != "Bread baked before dawn" || hero["lead"] != "Sourdough, rye and pastries from four o'clock." ||
		hero["alt"] != "A sourdough loaf on a board" || hero["image"] == nil {
		t.Fatalf("the home page is %v", index)
	}
	secs := index["sections"].([]any)
	prose := secs[0].(map[string]any)["prose"].(map[string]any)
	if prose["title"] != "What we bake" ||
		prose["body"] != "- Country sourdough\n- Seeded rye\n\nEverything is & always has been made by hand." {
		t.Fatalf("the first section is %q", prose)
	}
	if strings.Join(stored, ",") != "/img/loaf.jpg=A sourdough loaf on a board" {
		t.Fatalf("pictures stored: %v", stored)
	}
	if pages["visit"]["title"] != "Visit us" || pages["privacy"]["title"] != "Privacy" {
		t.Fatalf("titles: %v, %v", pages["visit"]["title"], pages["privacy"]["title"])
	}

	menus := map[string][]string{}
	for _, m := range p.Menus {
		if err := m.Validate(map[string]any{"index": 1, "menu": 1, "visit": 1, "privacy": 1}); err != nil {
			t.Fatal(err)
		}
		for _, it := range m.Items {
			menus[m.Name] = append(menus[m.Name], it.Label+">"+it.Target)
		}
	}
	if strings.Join(menus["main"], ",") != "Home>index,Menu>menu,Visit>visit" || strings.Join(menus["foot"], ",") != "Privacy>privacy" {
		t.Fatalf("menus %v", menus)
	}

	redirects := map[string]string{}
	for _, r := range b.Redirects {
		redirects[r.From] = r.To
		if !r.Permanent {
			t.Errorf("%s is not a permanent redirect", r.From)
		}
	}
	// Only where an address changed: /menu/ is /menu already.
	if redirects["/visit.html"] != "/visit" || len(redirects) != 1 || len(p.Site.Redirects) != 1 {
		t.Fatalf("redirects %v, in the site %v", redirects, p.Site.Redirects)
	}
	if c := p.MakeCard(); !strings.Contains(c.Shows[0].Text, "keeps 1 old address working") {
		t.Errorf("the card says %q", c.Shows[0].Text)
	}

	notes := strings.Join(b.Notes, "\n")
	for _, want := range []string{"1 picture(s) had no description", "1 form(s) were left behind", "1 script", "1 iframe", "robots.txt"} {
		if !strings.Contains(notes, want) {
			t.Errorf("no note says %q:\n%s", want, notes)
		}
	}
	if len(p.Chatbots) != 1 || p.Chatbots[0].UseModel || len(p.Chatbots[0].Actions) != 0 {
		t.Fatalf("the question box is %+v", p.Chatbots)
	}

	// Without pictures, and with a colour nobody could read text on.
	s.Pages[0].ThemeColour = "#fff"
	b, err = Package(s, "Hart & Co", "dana", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if b.Package.Site.Name != "Hart & Co" || pagesHaveImages(b.Package) {
		t.Fatalf("named %q, with pictures %v", b.Package.Site.Name, pagesHaveImages(b.Package))
	}
	if err := b.Package.Validate(feature.Checks{}); err != nil {
		t.Fatal(err)
	}
}

func pagesHaveImages(p *feature.Package) bool {
	for _, pg := range p.Pages {
		if strings.Contains(strings.ToLower(fmtAny(pg.Body)), "/media/") {
			return true
		}
	}
	return false
}

func fmtAny(v any) string {
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			b.WriteString(t + " ")
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return b.String()
}

func TestPageNamesComeFromAddresses(t *testing.T) {
	for raw, want := range map[string]string{
		"https://x.example/":                  "index",
		"https://x.example/index.html":        "index",
		"https://x.example/About_Us.html":     "about-us",
		"https://x.example/blog/2024/a-post/": "blog/2024/a-post",
		"https://x.example/Hart's%20Story/":   "harts-story",
		"https://x.example/a/b/c/d/e/f":       "c/d/e/f",
	} {
		u, _ := url.Parse(raw)
		if got := pageName(u); got != want {
			t.Errorf("%s is %q, not %q", raw, got, want)
		}
	}
}

// An old address that is another page's new one is not redirected: redirects
// are served before pages, so it would hide that page.
func TestAnOldAddressNeverHidesANewPage(t *testing.T) {
	s := &site{pages: map[string]string{
		"/":              head + `<title>Hart's</title></head><body><main><h1>Hart's</h1><p>Bread.</p><a href="/About_Us.html">About</a><a href="/about-us">Us</a></main></body></html>`,
		"/About_Us.html": head + `<title>About</title></head><body><main><h1>About</h1><p>Since 2019.</p></main></body></html>`,
		"/about-us":      head + `<title>Us</title></head><body><main><h1>Us</h1><p>Four of us.</p></main></body></html>`,
	}}
	b, err := Package(crawlOf(t, s, 10), "", "dana", nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Package.Validate(feature.Checks{}); err != nil {
		t.Fatal(err)
	}
	for _, r := range b.Redirects {
		for _, pg := range b.Package.Pages {
			if feature.PagePath(pg.Name) == strings.TrimSuffix(r.From, "/") {
				t.Fatalf("the redirect %s → %s hides the page %s", r.From, r.To, pg.Name)
			}
		}
	}
	if len(b.Package.Pages) < 3 {
		t.Fatalf("pages %v", b.Package.Pages)
	}
}

// What a page links and emphasises is kept in the prose subset, and words
// that look like markers stay words.
func TestAPagesWordsKeepTheirLinksAndEmphasis(t *testing.T) {
	base, _ := url.Parse("https://hartsbakery.example/blog/")
	p := Read([]byte(`<main><p>Our <strong>rye</strong> is <em>slow</em>: see <a href="/menu/">the menu</a> or `+
		`<a href="https://flour.example/">the <b>mill</b></a>. 5 * 3 [sic]</p><p><a href="/x"><img src="/i.jpg" alt="A loaf"></a></p>`+
		`<p>An <strong> </strong>empty mark, and <code>a*b</code>.</p><pre>keep *this*</pre></main>`), base)
	var mds []string
	for _, b := range p.Blocks {
		mds = append(mds, b.Kind+":"+b.MD)
	}
	want := []string{
		"p:Our **rye** is *slow*: see [the menu](https://hartsbakery.example/menu/) or [the **mill**](https://flour.example/). 5 \\* 3 \\[sic\\]",
		"img:",
		"p:An empty mark, and `a*b`.",
		"pre:",
	}
	if strings.Join(mds, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the words are\n%s\nnot\n%s", strings.Join(mds, "\n"), strings.Join(want, "\n"))
	}
}

// A quotation's paragraphs are a quotation, a table's row reads as one line,
// and a numbered list stays numbered.
func TestQuotationsTablesAndNumberedListsKeepTheirShape(t *testing.T) {
	base, _ := url.Parse("https://hartsbakery.example/")
	p := Read([]byte(`<main><blockquote><p>Stay hungry.</p></blockquote>`+
		`<table><tr><th>Bread</th><th>Price</th></tr><tr><td>Rye</td><td>£4.60</td></tr></table>`+
		`<ol><li>Mix</li><li>Prove</li></ol><ul><li>Rye</li></ul></main>`), base)
	var got []string
	for _, b := range p.Blocks {
		got = append(got, b.Kind+":"+b.Text)
	}
	want := "quote:Stay hungry.|p:Bread · Price|p:Rye · £4.60|ol:Mix|ol:Prove|li:Rye"
	if strings.Join(got, "|") != want {
		t.Fatalf("read %s, not %s", strings.Join(got, "|"), want)
	}
	body, _ := pageBody(Page{URL: base, Title: "Bread", Blocks: append([]Block{{Kind: "p", Text: "x", MD: "[x](/y)"}}, p.Blocks...)},
		"Hart's", func(*url.URL, string) string { return "" }, nil)
	words := body["sections"].([]any)[0].(map[string]any)["prose"].(map[string]any)["body"].(string)
	if !strings.Contains(words, "> Stay hungry.") || !strings.Contains(words, "1. Mix\n1. Prove\n\n- Rye") {
		t.Fatalf("the words: %q", words)
	}
}
