// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/asciifold"
)

// inLanguage serves a page in the language it is written in: the html
// element's lang and dir, Content-Language, and with alternates, a link to
// each of the site's languages the page exists in. served is the stored name
// of the page whose words these are, which a rule may serve at another
// page's address.
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
//
// A site in one language (no Locales) is left as its layout wrote it.
func (st *Site) inLanguage(h http.Header, html, served string, alternates bool) string {
	if st.Locales == nil {
		return html
	}
	loc, page := st.Locales.Split(served)
	html = setHTMLLang(html, string(loc), loc.Dir())
	h.Set("Content-Language", string(loc))
	if !alternates || strings.TrimSpace(st.BaseURL) == "" {
		return html
	}
	// The sitemap named the translations and the page did not, so a reader
	// had no way from it to the other languages. Only the ones published,
	// by the sitemap's rule, and none for a page in one language: one
	// alternate is the page pointing at itself.
	pages, _, err := st.pages()
	if err != nil {
		return html
	}
	present := make(map[string]bool, len(pages))
	for name := range pages {
		present[name] = true
	}
	alts := st.Locales.Alternates(page, st.BaseURL, present)
	if len(alts) < 2 {
		return html
	}
	var b strings.Builder
	for _, a := range alts {
		b.WriteString(`<link rel="alternate" hreflang="` + escape(string(a.Locale)) +
			`" href="` + escape(a.Href) + `">` + "\n")
	}
	return insertBeforeHead(html, strings.TrimSuffix(b.String(), "\n"))
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
