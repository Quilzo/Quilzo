// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/asciifold"
	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/seo"
)

// pageLanguage is the language a page is served in, on a site published in
// more than one: what its html element says, and the address of each
// language the page at its address exists in. Nil on a site in one language
// (no Locales), which is left as its layout wrote it.
//
// A translated page was served as English, left to right. The layouts say
// <html lang="en">, the shipped ones and the demonstration's, and nothing
// told them otherwise, so /ar/about was Arabic declared English: a screen
// reader read it by English rules and its paragraphs, lists and punctuation
// ran the wrong way, which i18n says makes a page unreadable rather than
// merely ugly (WCAG 2.2 3.1.1, Language of Page). Done here, on the page as
// rendered, for the reason the rest of the head is injected: a language that
// depends on every layout remembering it is missing from the one layout
// nobody checked.
type pageLanguage struct {
	lang, dir string
	// alternates is empty for a page in one language: one alternate is the
	// page pointing at itself.
	alternates []i18n.Alternate
}

// languageOf is the language of the page served at the address of the page
// named name, whose words are those of the page stored as served: a rule
// or a test may serve another page there. The language is that of the
// words; the links are to the languages of the address, because a version of
// /about served at /about is still /about, and looked up under its own name
// it linked none. pages is the pages published now, to link the languages
// that are among them, or nil for no links.
func (st *Site) languageOf(name, served string, pages map[string]any) *pageLanguage {
	if st.Locales == nil {
		return nil
	}
	loc, _ := st.Locales.Split(served)
	l := &pageLanguage{lang: string(loc), dir: loc.Dir()}
	if pages == nil || strings.TrimSpace(st.BaseURL) == "" {
		return l
	}
	// The sitemap named the translations and the page did not, so a reader
	// had no way from it to the other languages. Only the ones published,
	// by the sitemap's rule.
	_, page := st.Locales.Split(name)
	present := map[string]bool{}
	for _, in := range st.Locales.Locales {
		stored := st.Locales.Path(page, in)
		if _, published := pages[stored]; published {
			present[stored] = true
		}
	}
	if alts := st.alternates(page, present); len(alts) >= 2 {
		l.alternates = alts
	}
	return l
}

// alternates is the languages a page exists in (i18n's Alternates), each at
// the address this site serves it at.
//
// The home page's address is the root, and its canonical link says so. Its
// languages were named at /index, in the sitemap and then in the page: a
// second address for the same page, so the home page's entry did not name
// itself among its own languages, and a search engine holds a set of links
// like that to be no links at all.
func (st *Site) alternates(page string, present map[string]bool) []i18n.Alternate {
	base := strings.TrimSuffix(st.BaseURL, "/")
	alts := st.Locales.Alternates(page, base, present)
	for i, a := range alts {
		in := a.Locale
		if in == "x-default" {
			in = st.Locales.Default
		}
		alts[i].Href = seo.PageURL(base, st.Locales.Path(page, in), st.Index)
	}
	return alts
}

// tag names what the page says of its language, for the page's validator;
// "" on a site in one language.
//
// The links depend on pages other than this one. A validator made from the
// page's own content told a browser or a crawler holding /about from before
// its Turkish version was published that nothing had changed, so the copy
// with no link to the Turkish page was kept for as long as the English one
// went unedited.
func (l *pageLanguage) tag() string {
	if l == nil {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(l.lang + "\x00" + l.dir + "\x00"))
	for _, a := range l.alternates {
		h.Write([]byte(string(a.Locale) + "\x00" + a.Href + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// announce says the language on the response, for whoever reads the headers
// and not the page.
func (l *pageLanguage) announce(h http.Header) {
	if l != nil {
		h.Set("Content-Language", l.lang)
	}
}

// in is the rendered page in its language: the html element's lang and dir,
// and a link to each language it exists in.
func (l *pageLanguage) in(html string) string {
	if l == nil {
		return html
	}
	html = setHTMLLang(html, l.lang, l.dir)
	if len(l.alternates) == 0 {
		return html
	}
	var b strings.Builder
	for _, a := range l.alternates {
		b.WriteString(`<link rel="alternate" hreflang="` + escape(string(a.Locale)) +
			`" href="` + escape(a.Href) + `">` + "\n")
	}
	return insertBeforeHead(html, strings.TrimSuffix(b.String(), "\n"))
}

// InLanguage is a rendered page with the lang and dir of the language its
// stored name puts it in, on a site published in the languages locales
// names; as it was on a site in one.
//
// For what renders a page without this site's handler: the editor's preview
// and a share link. They showed the Arabic page as English, left to right,
// which is not the page that is published.
func InLanguage(html string, locales *i18n.Config, name string) string {
	if locales == nil || len(locales.Locales) < 2 {
		return html
	}
	loc, _ := locales.Split(name)
	return setHTMLLang(html, string(loc), loc.Dir())
}

// reLangAttr is a lang or dir attribute in an html start tag, in any of the
// three ways an attribute value is written. xml:lang is not one: the colon
// before it is not the space this needs.
var reLangAttr = regexp.MustCompile(`(?i)\s(?:lang|dir)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+)`)

// setHTMLLang gives the document's html element this lang and dir, in place
// of whatever it said, leaving its other attributes as they were. A page
// with no html element is served as it is.
func setHTMLLang(html, lang, dir string) string {
	at := asciifold.Index(html, "<html")
	if at < 0 {
		return html
	}
	name := at + len("<html")
	if name < len(html) && !strings.ContainsRune(" \t\r\n\f>/", rune(html[name])) {
		// <htmlfoo> is not the html element.
		return html
	}
	// The end of the tag, past any > inside a quoted value.
	end, quote := -1, byte(0)
	for i := name; i < len(html); i++ {
		c := html[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			end = i
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return html
	}
	rest := reLangAttr.ReplaceAllString(html[name:end], "")
	return html[:name] + ` lang="` + escape(lang) + `" dir="` + escape(dir) + `"` + rest + html[end:]
}
