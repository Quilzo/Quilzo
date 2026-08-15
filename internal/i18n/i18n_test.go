package i18n

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

// The bug every multilingual CMS has: somebody edits the source, the
// translation is silently wrong, and the site keeps serving a fluent
// translation of a paragraph that no longer exists.
func TestEditingTheSourceMakesItsTranslationsStale(t *testing.T) {
	c := NewConfig("en")
	if err := c.Add("fr"); err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{"about": true, "fr/about": true}

	c.Record("about", "fr", "hash-v1", "dana", now)
	states := c.Check(map[string]string{"about": "hash-v1"}, present)
	if len(states) != 1 || states[0].Status != Current {
		t.Fatalf("a fresh translation is %v", states)
	}

	// The English page is edited. Nothing tells the system; the hash simply
	// stops matching.
	states = c.Check(map[string]string{"about": "hash-v2"}, present)
	if states[0].Status != Stale {
		t.Fatalf("editing the source left the translation %q", states[0].Status)
	}
	// And the result is checkable rather than something to take on trust.
	if states[0].TranslatedFrom != "hash-v1" || states[0].SourceHash != "hash-v2" {
		t.Errorf("the two hashes are not both reported: %#v", states[0])
	}
	if states[0].TranslatedBy != "dana" {
		t.Error("the person who made the translation is not named")
	}

	// Re-translating clears it.
	c.Record("about", "fr", "hash-v2", "sam", now)
	if s := c.Check(map[string]string{"about": "hash-v2"}, present); s[0].Status != Current {
		t.Errorf("re-translating left it %q", s[0].Status)
	}
}

// Saving the source unchanged must not mark translations stale, or the warning
// becomes noise and people stop reading it. This is what a timestamp comparison
// cannot do.
func TestSavingTheSourceUnchangedDoesNotInvalidateAnything(t *testing.T) {
	c := NewConfig("en")
	_ = c.Add("fr")
	present := map[string]bool{"about": true, "fr/about": true}
	c.Record("about", "fr", "same-hash", "dana", now)

	for range 5 {
		states := c.Check(map[string]string{"about": "same-hash"}, present)
		if states[0].Status != Current {
			t.Fatalf("an unchanged source marked the translation %q",
				states[0].Status)
		}
	}
}

// A translation with no record of its source cannot be called current, and
// calling it current would be the flag-set-by-hand failure this replaces.
func TestATranslationWithNoRecordIsUntrackedNotCurrent(t *testing.T) {
	c := NewConfig("en")
	_ = c.Add("fr")
	states := c.Check(map[string]string{"about": "h1"},
		map[string]bool{"about": true, "fr/about": true})

	if states[0].Status != Untracked {
		t.Errorf("an untracked translation is reported as %q", states[0].Status)
	}
}

func TestAMissingTranslationIsMissing(t *testing.T) {
	c := NewConfig("en")
	_ = c.Add("fr")
	_ = c.Add("de")
	states := c.Check(map[string]string{"about": "h1"},
		map[string]bool{"about": true, "fr/about": true})

	counts := Counts(states)
	if counts[Missing] != 1 {
		t.Errorf("expected one missing translation, got %v", counts)
	}
}

// -- locales -----------------------------------------------------------------

func TestLocaleParsingAcceptsWhatAWebsiteUses(t *testing.T) {
	ok := map[string]Locale{
		"en": "en", "EN": "en", "fr": "fr",
		"en-gb": "en-GB", "en-GB": "en-GB",
		"zh-hant": "zh-Hant", "zh-Hant-TW": "zh-Hant-TW",
		"es-419": "es-419", "ast": "ast",
	}
	for in, want := range ok {
		got, err := ParseLocale(in)
		if err != nil {
			t.Errorf("%q was refused: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLocale(%q) = %q, wanted %q", in, got, want)
		}
	}
}

// Extensions and variants are refused rather than half-understood, because a
// tag that means one thing here and another to a browser is worse than a tag
// that was rejected.
func TestExoticTagsAreRefused(t *testing.T) {
	for _, bad := range []string{
		"", "e", "english-language-tag", "en-US-u-ca-gregory",
		"x-private", "en_GB", "../etc", "en-", "-en", "12",
		strings.Repeat("a", 30),
	} {
		if got, err := ParseLocale(bad); err == nil {
			t.Errorf("%q was accepted as %q", bad, got)
		}
	}
}

// Getting dir wrong makes a page unreadable rather than merely ugly.
func TestRightToLeftLocales(t *testing.T) {
	for _, l := range []Locale{"ar", "he", "fa", "ur", "ar-EG", "he-IL"} {
		if !l.RightToLeft() || l.Dir() != "rtl" {
			t.Errorf("%s is not reported as right to left", l)
		}
	}
	for _, l := range []Locale{"en", "fr", "zh-Hant", "ja", "ru", "ku-Latn"} {
		if l.RightToLeft() || l.Dir() != "ltr" {
			t.Errorf("%s is reported as right to left", l)
		}
	}
}

// -- paths -------------------------------------------------------------------

// The default language stays unprefixed. Prefixing everything breaks every
// existing link on the day a site adds a second language, which is the moment
// people decide multilingual support is not worth it.
func TestTheDefaultLanguageKeepsItsPaths(t *testing.T) {
	c := NewConfig("en")
	_ = c.Add("fr")

	if got := c.Path("about", "en"); got != "about" {
		t.Errorf("the default language page is at %q", got)
	}
	if got := c.Path("about", "fr"); got != "fr/about" {
		t.Errorf("the French page is at %q", got)
	}
}

// A page genuinely called news/2026 must keep its name. Treating any slash as a
// locale would rename pages the day somebody adds a second language.
func TestASlashIsOnlyALocaleWhenItIsOne(t *testing.T) {
	c := NewConfig("en")
	_ = c.Add("fr")

	cases := map[string][2]string{
		"about":     {"en", "about"},
		"fr/about":  {"fr", "about"},
		"news/2026": {"en", "news/2026"},
		"de/about":  {"en", "de/about"}, // de is not configured
		"xx/about":  {"en", "xx/about"},
	}
	for stored, want := range cases {
		l, page := c.Split(stored)
		if string(l) != want[0] || page != want[1] {
			t.Errorf("Split(%q) = %q,%q — wanted %q,%q",
				stored, l, page, want[0], want[1])
		}
	}
}

// -- hreflang ----------------------------------------------------------------

// Emitting hreflang for a translation that does not exist tells a search engine
// the page is available in a language it is not, and the engine then offers it
// to a reader who finds it missing.
func TestHreflangOnlyNamesTranslationsThatExist(t *testing.T) {
	c := NewConfig("en")
	_ = c.Add("fr")
	_ = c.Add("de")

	alts := c.Alternates("about", "https://example.com",
		map[string]bool{"about": true, "fr/about": true})

	var locales []string
	for _, a := range alts {
		locales = append(locales, string(a.Locale))
	}
	for _, l := range locales {
		if l == "de" {
			t.Error("hreflang names German, which has no translation")
		}
	}
	if len(alts) != 3 { // en, fr, x-default
		t.Errorf("got %v", locales)
	}

	var sawDefault bool
	for _, a := range alts {
		if a.Locale == "x-default" {
			sawDefault = true
			if a.Href != "https://example.com/about" {
				t.Errorf("x-default points at %q", a.Href)
			}
		}
		if a.Locale == "fr" && a.Href != "https://example.com/fr/about" {
			t.Errorf("the French alternate is %q", a.Href)
		}
	}
	if !sawDefault {
		t.Error("no x-default, so a reader in an unlisted language gets nothing")
	}
}

// A single-language site emits no hreflang at all, rather than one entry
// pointing at itself.
func TestASingleLanguageSiteEmitsNoAlternates(t *testing.T) {
	c := NewConfig("en")
	alts := c.Alternates("about", "https://example.com",
		map[string]bool{"about": true})
	if len(alts) != 1 {
		t.Errorf("a one-language site produced %d alternates", len(alts))
	}
}

// -- bounds ------------------------------------------------------------------

func TestTheLocaleListIsBounded(t *testing.T) {
	c := NewConfig("en")
	for i := range MaxLocales + 10 {
		l, err := ParseLocale(string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)))
		if err != nil {
			continue
		}
		_ = c.Add(l)
	}
	if len(c.Locales) > MaxLocales {
		t.Errorf("%d locales configured, past the limit", len(c.Locales))
	}
}

func TestALocaleCannotBeAddedTwice(t *testing.T) {
	c := NewConfig("en")
	if err := c.Add("fr"); err != nil {
		t.Fatal(err)
	}
	if err := c.Add("fr"); err == nil {
		t.Error("the same locale was added twice")
	}
	if err := c.Add("en"); err == nil {
		t.Error("the default locale was added again")
	}
}

// The script is the more specific statement and it is the one actually about
// direction. Checking the language first reported ku-Latn as right to left —
// Kurdish in Latin script, which is not.
func TestAnExplicitScriptOverridesTheLanguageDefault(t *testing.T) {
	cases := map[Locale]bool{
		"ku":      true,  // usually Arabic script
		"ku-Latn": false, // written in Latin
		"ku-Arab": true,
		"az-Latn": false,
		"az-Arab": true,
		"sr-Cyrl": false,
		"pa-Arab": true, // Punjabi in Arabic script is right to left
		"pa":      false,
	}
	for l, want := range cases {
		if got := l.RightToLeft(); got != want {
			t.Errorf("%s.RightToLeft() = %v, wanted %v", l, got, want)
		}
	}
}
