// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/personalise"
	"github.com/quilzo/quilzo/internal/site"
)

// A translated page was served as English, left to right: /ar/about came
// out <html lang="en"> with no dir, because the layout said so and nothing
// told it otherwise, so a screen reader read Arabic by English rules and its
// paragraphs ran the wrong way (WCAG 2.2 3.1.1). Nor did the page link its
// translations, which only the sitemap named. A page in one of the site's
// languages is served in it, in its direction, with Content-Language and a
// link to each language it exists in.
func TestATranslatedPageIsServedInItsOwnLanguage(t *testing.T) {
	st := published(t, map[string]any{
		"index":    map[string]any{"title": "Home"},
		"about":    map[string]any{"title": "About"},
		"tr/about": map[string]any{"title": "Hakkında"},
		"ar/about": map[string]any{"title": "من نحن"},
		"contact":  map[string]any{"title": "Contact"},
	})
	st.Locales = &i18n.Config{Default: "en", Locales: []i18n.Locale{"en", "tr", "ar"}}
	html := regexp.MustCompile(`<html[^>]*>`)
	for path, want := range map[string]string{
		"/ar/about": `<html lang="ar" dir="rtl">`,
		"/tr/about": `<html lang="tr" dir="ltr">`,
		"/about":    `<html lang="en" dir="ltr">`,
	} {
		w := get(st, path, nil)
		body := w.Body.String()
		if got := html.FindString(body); got != want {
			t.Errorf("%s opens %s, want %s", path, got, want)
		}
		lang := strings.TrimSuffix(strings.TrimPrefix(want, `<html lang="`), `" dir="rtl">`)
		lang = strings.TrimSuffix(lang, `" dir="ltr">`)
		if cl := w.Header().Get("Content-Language"); cl != lang {
			t.Errorf("%s has Content-Language %q, want %q", path, cl, lang)
		}
		for _, link := range []string{
			`<link rel="alternate" hreflang="en" href="https://example.org/about">`,
			`<link rel="alternate" hreflang="tr" href="https://example.org/tr/about">`,
			`<link rel="alternate" hreflang="ar" href="https://example.org/ar/about">`,
			`<link rel="alternate" hreflang="x-default" href="https://example.org/about">`,
		} {
			if !strings.Contains(body, link) {
				t.Errorf("%s does not carry %s", path, link)
			}
		}
	}
	// A page in one language only links none: a link to itself says nothing.
	if body := get(st, "/contact", nil).Body.String(); strings.Contains(body, "hreflang") {
		t.Errorf("/contact links languages it is not in")
	}

	// Served at another address by a rule, a translation is still in its
	// own language.
	rules := &personalise.Set{}
	if err := rules.Put(personalise.Rule{Name: "about-ar", Page: "about", Variant: "ar/about", Enabled: true,
		When: []personalise.Condition{{Field: personalise.Language, Values: []string{"ar"}}}}); err != nil {
		t.Fatal(err)
	}
	st.Personalise = func() (*personalise.Set, error) { return rules, nil }
	if got := html.FindString(get(st, "/about", map[string]string{"Accept-Language": "ar"}).Body.String()); got != `<html lang="ar" dir="rtl">` {
		t.Errorf("the Arabic page a rule serves at /about opens %s", got)
	}

	// A site in one language is left as its layout wrote it.
	st.Locales = nil
	if got := html.FindString(get(st, "/about", nil).Body.String()); got != `<html lang="en">` {
		t.Errorf("a site in one language had its html element changed: %s", got)
	}
}

// The links to a page's languages name each at its own address, and the
// home page's address is the root: its canonical link says so. They named
// it /index, in the page and in the sitemap, which is a second address for
// the same page, so the home page's own entry did not name itself and a
// search engine holds links like that to be no links at all.
func TestTheHomePagesLanguagesAreNamedAtItsAddress(t *testing.T) {
	st := published(t, map[string]any{
		"index":    map[string]any{"title": "Home"},
		"tr/index": map[string]any{"title": "Ana sayfa"},
	})
	st.Locales = &i18n.Config{Default: "en", Locales: []i18n.Locale{"en", "tr"}}
	for _, path := range []string{"/", "/tr/index", "/sitemap.xml"} {
		body := get(st, path, nil).Body.String()
		for _, want := range []string{
			`hreflang="en" href="https://example.org/"`,
			`hreflang="tr" href="https://example.org/tr/index"`,
			`hreflang="x-default" href="https://example.org/"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s does not carry %s", path, want)
			}
		}
		if strings.Contains(body, `href="https://example.org/index"`) {
			t.Errorf("%s names the home page at /index, which is not its address", path)
		}
	}
}

// A page's validator names what the page says, and the page now says which
// languages it exists in. Made from the page's own content alone, it told a
// browser or a crawler holding /about from before its Turkish version was
// published that nothing had changed, so the copy without the link to the
// Turkish page was kept for as long as the English one went unedited.
func TestAPageHeldFromBeforeItsTranslationWasPublishedIsNotCalledUnchanged(t *testing.T) {
	pages := map[string]any{
		"index": map[string]any{"title": "Home"},
		"about": map[string]any{"title": "About"},
	}
	st := published(t, pages)
	st.Locales = &i18n.Config{Default: "en", Locales: []i18n.Locale{"en", "tr"}}
	first := get(st, "/about", nil)
	tag := first.Header().Get("ETag")
	if tag == "" || strings.Contains(first.Body.String(), "hreflang") {
		t.Fatalf("the page in one language: tag %q, links %v", tag, strings.Contains(first.Body.String(), "hreflang"))
	}
	if w := get(st, "/about", map[string]string{"If-None-Match": tag}); w.Code != http.StatusNotModified {
		t.Fatalf("an unchanged page answered %d to its own tag", w.Code)
	} else if cl := w.Header().Get("Content-Language"); cl != "en" {
		t.Errorf("the answer that nothing changed has Content-Language %q", cl)
	}

	pages["tr/about"] = map[string]any{"title": "Hakkında"}
	if _, err := site.SaveDraft(st.Store, pages, "in Turkish", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(st.Store, ""); err != nil {
		t.Fatal(err)
	}
	w := get(st, "/about", map[string]string{"If-None-Match": tag})
	if w.Code != http.StatusOK {
		t.Fatalf("/about answered %d to the tag it had before its translation was published", w.Code)
	}
	if !strings.Contains(w.Body.String(), `hreflang="tr" href="https://example.org/tr/about"`) {
		t.Error("/about does not link its Turkish version")
	}
}

// The languages a page links are those of the address it is served at. A
// version of /about that a rule or a test serves there is still /about, and
// it linked no language at all, because the links were looked up under the
// version's own name, which has no translations.
func TestAVersionServedAtAnAddressLinksThatAddressesLanguages(t *testing.T) {
	st := published(t, map[string]any{
		"index":       map[string]any{"title": "Home"},
		"about":       map[string]any{"title": "About"},
		"about-short": map[string]any{"title": "About, in short"},
		"tr/about":    map[string]any{"title": "Hakkında"},
	})
	st.Locales = &i18n.Config{Default: "en", Locales: []i18n.Locale{"en", "tr"}}
	rules := &personalise.Set{}
	if err := rules.Put(personalise.Rule{Name: "short", Page: "about", Variant: "about-short", Enabled: true,
		When: []personalise.Condition{{Field: personalise.Language, Values: []string{"de"}}}}); err != nil {
		t.Fatal(err)
	}
	st.Personalise = func() (*personalise.Set, error) { return rules, nil }
	body := get(st, "/about", map[string]string{"Accept-Language": "de"}).Body.String()
	if !strings.Contains(body, "About, in short") {
		t.Fatalf("the rule did not serve its version: %s", body)
	}
	for _, want := range []string{
		`<html lang="en" dir="ltr">`,
		`hreflang="en" href="https://example.org/about"`,
		`hreflang="tr" href="https://example.org/tr/about"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the version served at /about does not carry %s", want)
		}
	}
}

// What renders a page without this site's handler, the editor's preview and
// a share link, shows it in its language too: an editor previewing the
// Arabic page saw it run left to right, which is not what was published.
func TestAPageRenderedElsewhereIsInItsLanguage(t *testing.T) {
	const page = `<!doctype html><html lang="en" class="x"><head></head><body></body></html>`
	locales := &i18n.Config{Default: "en", Locales: []i18n.Locale{"en", "ar"}}
	if got := InLanguage(page, locales, "ar/about"); !strings.Contains(got, `<html lang="ar" dir="rtl" class="x">`) {
		t.Errorf("the Arabic page opens %s", got)
	}
	if got := InLanguage(page, locales, "about"); !strings.Contains(got, `<html lang="en" dir="ltr" class="x">`) {
		t.Errorf("the English page opens %s", got)
	}
	// A site in one language is left as its layout wrote it.
	for _, one := range []*i18n.Config{nil, {Default: "en", Locales: []i18n.Locale{"en"}}} {
		if got := InLanguage(page, one, "ar/about"); got != page {
			t.Errorf("a site in one language had its page changed: %s", got)
		}
	}
}
