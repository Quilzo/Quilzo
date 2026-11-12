// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"fmt"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/experiment"
	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/personalise"
)

func experimentSite(t *testing.T) (*Site, *analytics.Counter) {
	t.Helper()
	st := published(t, map[string]any{
		"index":     map[string]any{"title": "Home"},
		"pricing":   map[string]any{"title": "Pricing A"},
		"pricing-b": map[string]any{"title": "Pricing B"},
		"thanks":    map[string]any{"title": "Thanks"},
	})
	c, err := analytics.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	st.Analytics = c
	set := &experiment.Set{}
	if err := set.Put(experiment.Experiment{Name: "price", Page: "pricing", Goal: "page:/thanks",
		Running: true, Variants: []experiment.Variant{
			{Name: "a", Page: "pricing", Weight: 1}, {Name: "b", Page: "pricing-b", Weight: 1}}}); err != nil {
		t.Fatal(err)
	}
	st.Experiments = func() (*experiment.Set, error) { return set, nil }
	return st, c
}

func visitAs(st *Site, path, ip string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = ip + ":1"
	r.Header.Set("User-Agent", browser)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, r)
	return w
}

func TestAVariantIsServedAtTheSameAddress(t *testing.T) {
	st, _ := experimentSite(t)
	saw := map[string]bool{}
	for i := 0; i < 40; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		w := visitAs(st, "/pricing", ip)
		body := w.Body.String()
		switch {
		case strings.Contains(body, "Pricing B"):
			saw["b"] = true
		case strings.Contains(body, "Pricing A"):
			saw["a"] = true
		}
		if !strings.HasPrefix(w.Header().Get("Cache-Control"), "private") {
			t.Fatalf("a variant is cacheable by shared caches: %q", w.Header().Get("Cache-Control"))
		}
		// And the same visitor sees the same variant again.
		if again := visitAs(st, "/pricing", ip).Body.String(); strings.Contains(again, "Pricing B") != strings.Contains(body, "Pricing B") {
			t.Fatal("a visitor switched variants within the day")
		}
	}
	if !saw["a"] || !saw["b"] {
		t.Fatalf("forty visitors did not see both variants: %v", saw)
	}
	// A page with no experiment stays publicly cacheable.
	if cc := visitAs(st, "/thanks", "203.0.113.1").Header().Get("Cache-Control"); !strings.HasPrefix(cc, "public") {
		t.Fatalf("an ordinary page became private: %q", cc)
	}
}

// TestOnlyAVisitorWhoSawAVariantCanConvertForIt.
func TestOnlyAVisitorWhoSawAVariantCanConvertForIt(t *testing.T) {
	st, c := experimentSite(t)
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		visitAs(st, "/pricing", ip)
		if i < 10 {
			visitAs(st, "/thanks", ip)
		}
	}
	// Twenty who never saw the pricing page reach the goal.
	for i := 0; i < 20; i++ {
		visitAs(st, "/thanks", fmt.Sprintf("192.0.2.%d", i))
	}
	d := c.Today()
	seen := d.Goals[experiment.SeenKey("price", "a")] + d.Goals[experiment.SeenKey("price", "b")]
	won := d.Goals[experiment.WonKey("price", "a")] + d.Goals[experiment.WonKey("price", "b")]
	if seen != 20 || won != 10 {
		t.Fatalf("seen %d won %d, want 20 and 10", seen, won)
	}
}

func TestAMissingVariantFallsBackToTheControl(t *testing.T) {
	st, c := experimentSite(t)
	set, _ := st.Experiments()
	e, _ := set.Get("price")
	e.Variants[1].Page = "pricing-z" // not published
	set.Experiments[0] = e
	for i := 0; i < 20; i++ {
		if body := visitAs(st, "/pricing", fmt.Sprintf("203.0.113.%d", i)).Body.String(); !strings.Contains(body, "Pricing A") {
			t.Fatal("a missing variant served something else")
		}
	}
	if c.Today().Goals[experiment.SeenKey("price", "b")] != 0 {
		t.Fatal("exposure was recorded for a variant nobody could see")
	}
}

// A page an experiment or a personalisation rule serves at another page's
// address is a version of that page, not a page of its own. It was listed
// in the sitemap and in llms.txt and named itself as canonical, so search
// engines indexed /pricing-b as a second copy of /pricing and a visitor
// from search landed on the variant outside the test. It still answers at
// its own address, as every published page does.
func TestAVariantNamesThePageItIsServedAt(t *testing.T) {
	st, _ := experimentSite(t)
	rules := &personalise.Set{}
	if err := rules.Put(personalise.Rule{Name: "news", Page: "pricing", Variant: "thanks",
		Enabled: true, When: []personalise.Condition{{Field: personalise.Campaign, Values: []string{"newsletter"}}}}); err != nil {
		t.Fatal(err)
	}
	st.Personalise = func() (*personalise.Set, error) { return rules, nil }
	canonical := regexp.MustCompile(`<link rel="canonical" href="([^"]*)">`)

	before := visitAs(st, "/pricing-b", "203.0.113.9").Header().Get("ETag")
	sitemap := get(st, "/sitemap.xml", nil).Body.String()
	llms := get(st, "/llms.txt", nil).Body.String()
	for _, variant := range []string{"pricing-b", "thanks"} {
		w := visitAs(st, "/"+variant, "203.0.113.9")
		if w.Code != 200 {
			t.Fatalf("/%s answered %d; a variant still answers at its own address", variant, w.Code)
		}
		if m := canonical.FindStringSubmatch(w.Body.String()); m == nil || m[1] != "https://example.org/pricing" {
			t.Errorf("/%s names %v as canonical, not the page it is served at", variant, m)
		}
		if strings.Contains(sitemap, "https://example.org/"+variant+"<") {
			t.Errorf("the sitemap lists the variant /%s:\n%s", variant, sitemap)
		}
		if strings.Contains(llms, "(/"+variant+".md)") {
			t.Errorf("llms.txt lists the variant /%s:\n%s", variant, llms)
		}
		if l := get(st, "/"+variant+".md", nil).Header().Get("Link"); !strings.Contains(l, "<https://example.org/pricing>") {
			t.Errorf("/%s.md names %q as the address it copies", variant, l)
		}
	}
	// The page itself, the control and the home page are as they were.
	if !strings.Contains(sitemap, "https://example.org/pricing<") || !strings.Contains(sitemap, "https://example.org/<") {
		t.Errorf("the sitemap lost the page tested:\n%s", sitemap)
	}
	if m := canonical.FindStringSubmatch(visitAs(st, "/pricing", "203.0.113.9").Body.String()); m == nil || m[1] != "https://example.org/pricing" {
		t.Errorf("/pricing names %v as canonical", m)
	}

	// Stopping the test and switching the rule off makes the variants pages
	// again, with nothing published, so a crawler holding /pricing-b is not
	// told its copy naming /pricing is still current.
	exps, _ := st.Experiments()
	exps.Experiments[0].Running = false
	rules.Rules[0].Enabled = false
	w := visitAs(st, "/pricing-b", "203.0.113.9")
	if m := canonical.FindStringSubmatch(w.Body.String()); m == nil || m[1] != "https://example.org/pricing-b" {
		t.Errorf("/pricing-b names %v as canonical after its test stopped", m)
	}
	if w.Header().Get("ETag") == before {
		t.Error("/pricing-b kept its tag when what its canonical link names changed")
	}
	if s := get(st, "/sitemap.xml", nil).Body.String(); !strings.Contains(s, "https://example.org/pricing-b<") ||
		!strings.Contains(s, "https://example.org/thanks<") {
		t.Errorf("a page no longer a variant is not listed:\n%s", s)
	}
}

// A sitemap whose list changes when a test starts is not the sitemap a
// crawler holding its tag already has.
func TestTheSitemapTagMovesWhenATestStarts(t *testing.T) {
	st, _ := experimentSite(t)
	running := get(st, "/sitemap.xml", nil).Header().Get("ETag")
	exps, _ := st.Experiments()
	exps.Experiments[0].Running = false
	stopped := get(st, "/sitemap.xml", nil)
	if stopped.Header().Get("ETag") == running {
		t.Fatal("the sitemap kept its tag when a variant came back into it")
	}
	if again := get(st, "/sitemap.xml", map[string]string{"If-None-Match": running}); again.Code != 200 {
		t.Fatalf("a crawler holding the sitemap from while the test ran was answered %d", again.Code)
	}
}

// The home page is a page of its own whatever is tested against it. A test
// of a landing page against the home page (does an advert's traffic do
// better on the page everybody else gets?) names the home page as a variant,
// and so does a rule that serves it at another address. By the rule for
// variants the home page then named that address as canonical and left the
// sitemap and llms.txt: the address every visitor and every crawler arrives
// at said it was a copy of /pricing, and nothing listed it.
func TestTheHomePageIsNeverAVariant(t *testing.T) {
	canonical := regexp.MustCompile(`<link rel="canonical" href="([^"]*)">`)
	asTest, _ := experimentSite(t)
	exps, _ := asTest.Experiments()
	exps.Experiments[0].Variants[1].Page = "index"

	asRule, _ := experimentSite(t)
	stopped, _ := asRule.Experiments()
	stopped.Experiments[0].Running = false
	rules := &personalise.Set{}
	if err := rules.Put(personalise.Rule{Name: "news", Page: "pricing", Variant: "index",
		Enabled: true, When: []personalise.Condition{{Field: personalise.Campaign, Values: []string{"newsletter"}}}}); err != nil {
		t.Fatal(err)
	}
	asRule.Personalise = func() (*personalise.Set, error) { return rules, nil }

	for served, st := range map[string]*Site{"a test": asTest, "a rule": asRule} {
		w := visitAs(st, "/", "203.0.113.9")
		if m := canonical.FindStringSubmatch(w.Body.String()); m == nil || m[1] != "https://example.org/" {
			t.Errorf("served elsewhere by %s, the home page names %v as canonical", served, m)
		}
		if s := get(st, "/sitemap.xml", nil).Body.String(); !strings.Contains(s, "https://example.org/<") {
			t.Errorf("served elsewhere by %s, the home page is not in the sitemap:\n%s", served, s)
		}
		if l := get(st, "/llms.txt", nil).Body.String(); !strings.Contains(l, "(/index.md)") {
			t.Errorf("served elsewhere by %s, the home page is not in llms.txt:\n%s", served, l)
		}
		if l := get(st, "/index.md", nil).Header().Get("Link"); !strings.Contains(l, "<https://example.org/>") {
			t.Errorf("served elsewhere by %s, the home page's copy names %q", served, l)
		}
	}
	// By the one rule the sitemap, llms.txt and IndexNow share, whatever the
	// site calls its home page.
	pages := map[string]any{"home": map[string]any{"title": "Home"}, "landing": map[string]any{"title": "Landing"},
		"landing-b": map[string]any{"title": "Landing B"}}
	set := &experiment.Set{}
	if err := set.Put(experiment.Experiment{Name: "land", Page: "landing", Goal: "form:contact", Running: true,
		Variants: []experiment.Variant{{Name: "a", Page: "landing", Weight: 1}, {Name: "b", Page: "home", Weight: 1},
			{Name: "c", Page: "landing-b", Weight: 1}}}); err != nil {
		t.Fatal(err)
	}
	if v := Variants(set, nil, pages, "home", nil); len(v) != 1 || v["landing-b"] != "landing" {
		t.Errorf("the variants are %v; the home page is none, and landing-b is one of /landing", v)
	}
}

// A page in another of the site's languages is a page of its own, whatever
// serves it elsewhere. A rule that serves fr/about at /about to a browser
// asking for French is "the page in the visitor's own language", the case
// rules are for, and /fr/about is where everybody else reads it: the
// sitemap gives it as the French version of /about. By the rule for
// variants it named /about as canonical and left the sitemap and llms.txt,
// while the sitemap's hreflang still pointed at it, which tells a search
// engine to drop the French page. A version in the same language is still a
// variant.
func TestATranslationARuleServesIsStillAPageOfItsOwn(t *testing.T) {
	st := published(t, map[string]any{
		"index":        map[string]any{"title": "Home"},
		"about":        map[string]any{"title": "About"},
		"fr/about":     map[string]any{"title": "À propos"},
		"fr/index":     map[string]any{"title": "Accueil"},
		"fr/landing":   map[string]any{"title": "Bienvenue"},
		"fr/landing-b": map[string]any{"title": "Bienvenue, en bref"},
	})
	st.BaseURL = "https://example.org"
	st.Locales = &i18n.Config{Default: "en", Locales: []i18n.Locale{"en", "fr"}}
	french := []personalise.Condition{{Field: personalise.Language, Values: []string{"fr"}}}
	rules := &personalise.Set{}
	for _, r := range []personalise.Rule{
		{Name: "about-fr", Page: "about", Variant: "fr/about", Enabled: true, When: french},
		{Name: "home-fr", Page: "index", Variant: "fr/index", Enabled: true, When: french},
		{Name: "brief", Page: "fr/landing", Variant: "fr/landing-b", Enabled: true,
			When: []personalise.Condition{{Field: personalise.Device, Values: []string{"phone"}}}},
	} {
		if err := rules.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	st.Personalise = func() (*personalise.Set, error) { return rules, nil }
	canonical := regexp.MustCompile(`<link rel="canonical" href="([^"]*)">`)
	names := func(page string) string {
		m := canonical.FindStringSubmatch(get(st, "/"+page, nil).Body.String())
		if m == nil {
			return ""
		}
		return m[1]
	}
	sitemap := get(st, "/sitemap.xml", nil).Body.String()
	llms := get(st, "/llms.txt", nil).Body.String()
	for _, page := range []string{"fr/about", "fr/index"} {
		own := "https://example.org/" + page
		if c := names(page); c != own {
			t.Errorf("/%s, a translation, names %q as canonical", page, c)
		}
		if !strings.Contains(sitemap, "<loc>"+own+"</loc>") {
			t.Errorf("the sitemap lost the translation /%s:\n%s", page, sitemap)
		}
		if !strings.Contains(llms, "(/"+page+".md)") {
			t.Errorf("llms.txt lost the translation /%s:\n%s", page, llms)
		}
		if l := get(st, "/"+page+".md", nil).Header().Get("Link"); !strings.Contains(l, "<"+own+">") {
			t.Errorf("/%s.md names %q as the address it copies", page, l)
		}
	}
	if c := names("fr/landing-b"); c != "https://example.org/fr/landing" {
		t.Errorf("/fr/landing-b, a version of /fr/landing in its own language, names %q as canonical", c)
	}
	if strings.Contains(sitemap, "<loc>https://example.org/fr/landing-b</loc>") {
		t.Errorf("the sitemap lists the variant /fr/landing-b:\n%s", sitemap)
	}
	// The home page in another language is a home page: served at a landing
	// page by a test, it is still the address its readers arrive at.
	pages := map[string]any{"index": 1, "fr/index": 1, "fr/landing": 1, "fr/landing-b": 1}
	set := &experiment.Set{}
	if err := set.Put(experiment.Experiment{Name: "land", Page: "fr/landing", Goal: "form:contact", Running: true,
		Variants: []experiment.Variant{{Name: "a", Page: "fr/landing", Weight: 1}, {Name: "b", Page: "fr/index", Weight: 1},
			{Name: "c", Page: "fr/landing-b", Weight: 1}}}); err != nil {
		t.Fatal(err)
	}
	if v := Variants(set, nil, pages, "index", st.Locales); len(v) != 1 || v["fr/landing-b"] != "fr/landing" {
		t.Errorf("the variants are %v; the French home page is none, and fr/landing-b is one of /fr/landing", v)
	}
	// A site in one language has no translations: a page that only looks
	// like one is a variant like any other.
	st.Locales = nil
	if c := names("fr/about"); c != "https://example.org/about" {
		t.Errorf("on a site in one language /fr/about, served at /about, names %q as canonical", c)
	}
}
