// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/personalise"
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
