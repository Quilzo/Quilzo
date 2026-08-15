// Package i18n handles a site in more than one language.
//
// # The problem worth solving is not routing
//
// Serving /fr/about instead of /about is bookkeeping. The bug every
// multilingual CMS has is different and much worse: somebody edits the English
// page, the French translation is now wrong, and nothing anywhere says so. The
// site keeps serving a confident, fluent translation of a paragraph that no
// longer exists. Readers in one language are told something the publisher
// stopped saying, often for months.
//
// Existing systems handle this with a flag somebody sets by hand, or a
// modification timestamp compared between two rows — which moves when a page is
// saved unchanged and so cannot distinguish "edited" from "opened and saved".
// Both degrade to a warning nobody believes.
//
// Here it is exact. A translation records the hash of the source it was made
// from. Change one character of the source and the hash no longer matches, and
// "this translation is out of date" is a fact about two values rather than a
// guess about two clocks. Nothing has to detect the edit.
//
// This is the third time content addressing has given an exact answer where
// everybody else has a heuristic: a content type records the hash of what it
// validated, an approval records the hash of what was agreed, and a translation
// records the hash of what it was translated from.
//
// # What is deliberately not here
//
// No machine translation, no locale detection from Accept-Language, no
// automatic fallback to a default language. The last one is the interesting
// refusal: serving the English page to somebody who asked for French, without
// saying so, is how a reader ends up believing a page exists in their language
// when it does not. A missing translation is a missing translation, and the
// site says which languages a page is actually available in.
package i18n

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// MaxLocales bounds how many languages a site may declare.
//
// A limit because every locale multiplies the pages, the sitemap and the work
// of checking staleness. Sixty-four is far past any real site and short of the
// point where an accident becomes an outage.
const MaxLocales = 64

// Locale is a BCP 47 language tag, restricted to the shapes a website uses.
type Locale string

// ParseLocale validates a tag.
//
// A deliberately small subset: language, optional script, optional region.
// Full BCP 47 has extensions, private use, variants and grandfathered tags, and
// parsing all of it correctly is a library — one whose failure mode here would
// be a tag that means something different to this program than to a browser.
// Refusing the exotic ones costs nothing a website needs.
func ParseLocale(s string) (Locale, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("a locale cannot be empty")
	}
	if len(s) > 20 {
		return "", fmt.Errorf("%q is too long to be a language tag", s)
	}

	parts := strings.Split(s, "-")
	if len(parts) > 3 {
		return "", fmt.Errorf(
			"%q has %d subtags. This accepts language, script and region — "+
				"extensions and variants are refused rather than half-understood",
			s, len(parts))
	}

	lang := strings.ToLower(parts[0])
	if !alpha(lang) || len(lang) < 2 || len(lang) > 3 {
		return "", fmt.Errorf(
			"%q does not start with a two or three letter language code", s)
	}
	out := lang

	for _, p := range parts[1:] {
		switch {
		case len(p) == 4 && alpha(p):
			// Script, title case by convention: zh-Hant.
			out += "-" + strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		case len(p) == 2 && alpha(p):
			// Region, upper case: en-GB.
			out += "-" + strings.ToUpper(p)
		case len(p) == 3 && digits(p):
			// Numeric region: es-419.
			out += "-" + p
		default:
			return "", fmt.Errorf("%q is not a script or region subtag", p)
		}
	}
	return Locale(out), nil
}

func alpha(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return len(s) > 0
}

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// Language is the primary subtag, which is what hreflang and the lang attribute
// most often want.
func (l Locale) Language() string {
	if i := strings.Index(string(l), "-"); i > 0 {
		return string(l)[:i]
	}
	return string(l)
}

// RightToLeft reports whether text in this locale runs right to left.
//
// A short list rather than a lookup table, because the set of RTL scripts in
// active use is small and stable, and getting `dir` wrong makes a page
// unreadable rather than merely ugly.
func (l Locale) RightToLeft() bool {
	// The script is checked first, because it is the more specific statement
	// and it is the one that is actually about direction. The first version had
	// this the other way round with a comment claiming otherwise, and reported
	// ku-Latn as right to left — Kurdish written in Latin script, which is not.
	// The comment described the intent and the code did the opposite.
	switch {
	case strings.Contains(string(l), "-Arab"), strings.Contains(string(l), "-Hebr"),
		strings.Contains(string(l), "-Thaa"), strings.Contains(string(l), "-Syrc"):
		return true
	case strings.Contains(string(l), "-Latn"), strings.Contains(string(l), "-Cyrl"),
		strings.Contains(string(l), "-Grek"):
		return false
	}
	// No script given: fall back to what the language is usually written in.
	switch l.Language() {
	case "ar", "he", "fa", "ur", "ps", "sd", "ug", "yi", "dv", "ku":
		return true
	}
	return false
}

// Dir is the value for the HTML dir attribute.
func (l Locale) Dir() string {
	if l.RightToLeft() {
		return "rtl"
	}
	return "ltr"
}

// -- the site's languages ----------------------------------------------------

// Config is which languages a site is published in.
type Config struct {
	// Default is the locale served at the unprefixed path. Every site has one,
	// including a site that only has one.
	Default Locale `json:"default"`
	// Locales are all the languages, including the default.
	Locales []Locale `json:"locales"`
	// Translations records what each translated page was made from.
	Translations []Translation `json:"translations,omitempty"`
}

// Translation binds a translated page to the exact source it came from.
type Translation struct {
	// Page is the page name, without a locale prefix.
	Page string `json:"page"`
	// Locale is the language this translation is in.
	Locale Locale `json:"locale"`
	// SourceHash is the object id of the source page at the moment it was
	// translated. This is the whole mechanism: it stops matching when the
	// source changes, and nothing has to notice.
	SourceHash string `json:"source_hash"`
	// TranslatedBy and At are for the person who has to decide whether a stale
	// translation needs redoing or was a trivial change.
	TranslatedBy string `json:"translated_by,omitempty"`
	At           int64  `json:"at"`
}

// NewConfig returns a single-language configuration.
func NewConfig(def Locale) *Config {
	return &Config{Default: def, Locales: []Locale{def}}
}

// Add introduces a language.
func (c *Config) Add(l Locale) error {
	if len(c.Locales) >= MaxLocales {
		return fmt.Errorf("a site may have at most %d languages", MaxLocales)
	}
	for _, existing := range c.Locales {
		if existing == l {
			return fmt.Errorf("%s is already configured", l)
		}
	}
	c.Locales = append(c.Locales, l)
	sort.Slice(c.Locales, func(i, j int) bool { return c.Locales[i] < c.Locales[j] })
	return nil
}

// Has reports whether a locale is configured.
func (c *Config) Has(l Locale) bool {
	for _, existing := range c.Locales {
		if existing == l {
			return true
		}
	}
	return false
}

// Path is where a page lives for a locale.
//
// The default language is served unprefixed. That is a choice with a cost —
// /about and /en/about are then two names for one page — and the alternative
// costs more: prefixing everything breaks every existing link on a site that
// adds a second language, which is the moment people decide multilingual
// support is not worth it.
func (c *Config) Path(page string, l Locale) string {
	if l == c.Default {
		return page
	}
	return string(l) + "/" + page
}

// Split takes a stored page name apart into a locale and a page.
func (c *Config) Split(stored string) (Locale, string) {
	prefix, rest, found := strings.Cut(stored, "/")
	if !found {
		return c.Default, stored
	}
	l, err := ParseLocale(prefix)
	if err != nil || !c.Has(l) {
		// Not a locale prefix — a page genuinely called "news/2026" keeps its
		// name. Treating any slash as a locale would rename pages on the day
		// somebody adds a second language.
		return c.Default, stored
	}
	return l, rest
}

// -- staleness ---------------------------------------------------------------

// Status is what a translation currently is.
type Status string

const (
	// Current means the translation was made from the source as it stands.
	Current Status = "current"
	// Stale means the source changed after the translation was made.
	Stale Status = "stale"
	// Missing means the page has no translation in this locale.
	Missing Status = "missing"
	// Untracked means a translation exists with no record of its source, so
	// nothing can be said about whether it is current.
	Untracked Status = "untracked"
)

// State is the answer for one page in one language.
type State struct {
	Page   string `json:"page"`
	Locale Locale `json:"locale"`
	Status Status `json:"status"`
	// SourceHash and TranslatedFrom make a stale result checkable rather than
	// something to take on trust.
	SourceHash     string `json:"source_hash,omitempty"`
	TranslatedFrom string `json:"translated_from,omitempty"`
	TranslatedBy   string `json:"translated_by,omitempty"`
}

// Check reports the state of every translation.
//
// sources maps a page name to the object id of its content in the default
// language; present lists the page names that actually exist, in stored form.
func (c *Config) Check(sources map[string]string, present map[string]bool) []State {
	recorded := map[string]Translation{}
	for _, t := range c.Translations {
		recorded[string(t.Locale)+"/"+t.Page] = t
	}

	pages := make([]string, 0, len(sources))
	for p := range sources {
		pages = append(pages, p)
	}
	sort.Strings(pages)

	var out []State
	for _, page := range pages {
		for _, l := range c.Locales {
			if l == c.Default {
				continue
			}
			st := State{Page: page, Locale: l, SourceHash: sources[page]}
			key := string(l) + "/" + page

			if !present[c.Path(page, l)] {
				st.Status = Missing
				out = append(out, st)
				continue
			}
			t, tracked := recorded[key]
			if !tracked || t.SourceHash == "" {
				st.Status = Untracked
				out = append(out, st)
				continue
			}
			st.TranslatedFrom, st.TranslatedBy = t.SourceHash, t.TranslatedBy
			if t.SourceHash == sources[page] {
				st.Status = Current
			} else {
				st.Status = Stale
			}
			out = append(out, st)
		}
	}
	return out
}

// Record notes that a page was translated from a specific source.
func (c *Config) Record(page string, l Locale, sourceHash, by string, now time.Time) {
	for i := range c.Translations {
		if c.Translations[i].Page == page && c.Translations[i].Locale == l {
			c.Translations[i].SourceHash = sourceHash
			c.Translations[i].TranslatedBy = by
			c.Translations[i].At = now.Unix()
			return
		}
	}
	c.Translations = append(c.Translations, Translation{
		Page: page, Locale: l, SourceHash: sourceHash,
		TranslatedBy: by, At: now.Unix(),
	})
	sort.Slice(c.Translations, func(i, j int) bool {
		if c.Translations[i].Page != c.Translations[j].Page {
			return c.Translations[i].Page < c.Translations[j].Page
		}
		return c.Translations[i].Locale < c.Translations[j].Locale
	})
}

// Counts summarises a check, for a dashboard or an exit code.
func Counts(states []State) map[Status]int {
	out := map[Status]int{}
	for _, s := range states {
		out[s.Status]++
	}
	return out
}

// -- hreflang ----------------------------------------------------------------

// Alternate is one hreflang entry.
type Alternate struct {
	Locale Locale
	Href   string
}

// Alternates lists the languages a page is genuinely available in.
//
// Only the ones that exist. Emitting hreflang for a translation that is missing
// tells a search engine the page is available in a language it is not, which is
// worse than saying nothing — the engine offers the page to a reader who then
// finds it is not there.
func (c *Config) Alternates(page, baseURL string, present map[string]bool) []Alternate {
	base := strings.TrimSuffix(baseURL, "/")
	var out []Alternate
	for _, l := range c.Locales {
		stored := c.Path(page, l)
		if !present[stored] {
			continue
		}
		href := base + "/" + stored
		if stored == "" {
			href = base + "/"
		}
		out = append(out, Alternate{Locale: l, Href: href})
	}
	// x-default points at the default language, which is what a search engine
	// serves to a reader whose language is not among these.
	if len(out) > 1 {
		if present[c.Path(page, c.Default)] {
			out = append(out, Alternate{
				Locale: "x-default",
				Href:   base + "/" + c.Path(page, c.Default),
			})
		}
	}
	return out
}
