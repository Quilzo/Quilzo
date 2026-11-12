// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/experiment"
	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/personalise"
	"github.com/quilzo/quilzo/internal/seo"
)

// A/B tests, served. See internal/experiment for the design and its limits.

// variantFor returns the page to serve at name for this visitor when an
// experiment is running on it: the variant's name and body. Recording that
// the visitor was shown it happens here too, once a day per visitor. A
// variant whose page is not published falls back to the control and records
// nothing, so a missing page cannot pass as a variant nobody converts on.
func (st *Site) variantFor(r *http.Request, name string, pages map[string]any) (string, any, bool) {
	if st.Experiments == nil || st.Analytics == nil {
		return "", nil, false
	}
	set, err := st.Experiments()
	if err != nil {
		return "", nil, false
	}
	e, running := set.RunningOn(name)
	if !running {
		return "", nil, false
	}
	v := e.Variants[st.Analytics.Bucket(r, e.Name, e.Weights())]
	body, published := pages[v.Page]
	if !published {
		return "", nil, false
	}
	st.Analytics.Convert(r, experiment.SeenKey(e.Name, v.Name))
	return v.Page, body, true
}

// convert records a goal, and credits it to the variant of every running
// experiment with that goal that this visitor was shown today.
func (st *Site) convert(r *http.Request, goal string) {
	if st.Analytics == nil {
		return
	}
	st.Analytics.Convert(r, goal)
	if st.Experiments == nil {
		return
	}
	set, err := st.Experiments()
	if err != nil {
		return
	}
	for _, e := range set.Experiments {
		if !e.Running || e.Goal != goal {
			continue
		}
		v := e.Variants[st.Analytics.Bucket(r, e.Name, e.Weights())]
		if st.Analytics.Reached(r, experiment.SeenKey(e.Name, v.Name)) {
			st.Analytics.Convert(r, experiment.WonKey(e.Name, v.Name))
		}
	}
}

// convertPage records reaching a page, for experiments whose goal is it.
// Only those: a goal per page for every page would fill the day's goals with
// what the page counts already say.
//
// The goal is folded as the path was (countedAs), so page:/delivery/ and
// page:/delivery name one page, as they always could be written. Each
// spelling is converted once, because convert credits the experiments whose
// goal is spelled as it was given.
func (st *Site) convertPage(r *http.Request, path string) {
	if st.Experiments == nil || st.Analytics == nil {
		return
	}
	set, err := st.Experiments()
	if err != nil {
		return
	}
	done := map[string]bool{}
	for _, e := range set.Experiments {
		goal, isPage := strings.CutPrefix(e.Goal, "page:")
		if !e.Running || !isPage || done[e.Goal] || st.countedAs(goal) != path {
			continue
		}
		done[e.Goal] = true
		st.convert(r, e.Goal)
	}
}

// personalFor returns the page a personalisation rule serves at name for this
// request, if one matches and its page is published. See
// internal/personalise: only what the request says is looked at.
func (st *Site) personalFor(r *http.Request, name string, pages map[string]any) (string, any, bool) {
	if st.Personalise == nil {
		return "", nil, false
	}
	set, err := st.Personalise()
	if err != nil {
		return "", nil, false
	}
	rule, ok := set.For(name, r, time.Now())
	if !ok {
		return "", nil, false
	}
	body, published := pages[rule.Variant]
	if !published {
		return "", nil, false
	}
	if st.Analytics != nil {
		st.Analytics.Convert(r, personalise.SeenKey(rule.Name))
	}
	return rule.Variant, body, true
}

// Variants maps each page that a running experiment or an enabled
// personalisation rule serves at another page's address to that page, when
// both are among pages.
//
// A variant has to be a published page, so it also answers at its own
// address, and nothing said it was a version of another: it was in the
// sitemap and named itself as canonical, so search engines indexed
// /returns-b as a second copy of /returns, and a visitor from search landed
// on the variant outside the test. Its address keeps answering; it names
// the page it is served at instead (Site.canonicalIn) and is not offered by
// its own (Listed).
//
// A page a test or a rule runs on is a page of its own wherever else it is
// served, since visitors arrive at it by its address: so the control is not
// a variant of itself, and two rules serving each other's page make no
// loop of canonical links.
//
// Nor is the home page, the one named index, for the same reason: it is
// the address every visitor and every crawler arrives at. A test of a
// landing page against the home page made the home page a variant of
// /landing, so the site's own address named /landing as canonical and left
// the sitemap, llms.txt and IndexNow.
//
// Nor is a translation of the page it is served at, on a site published in
// the languages locales names (nil for a site in one). A rule that serves
// fr/about at /about to a browser asking for French is the page in the
// visitor's own language, and /fr/about is where everybody else reads it:
// the sitemap lists it as the French version of /about. Taken for a
// variant, it named /about as canonical and left the sitemap while the
// sitemap's own hreflang still pointed at it, which tells a search engine
// to drop the French page. The home page in another language is a home
// page too.
func Variants(exps *experiment.Set, rules *personalise.Set, pages map[string]any, index string, locales *i18n.Config) map[string]string {
	runs := map[string]bool{}
	if rules != nil {
		for _, r := range rules.Rules {
			if r.Enabled {
				runs[r.Page] = true
			}
		}
	}
	if exps != nil {
		for _, e := range exps.Experiments {
			if e.Running {
				runs[e.Page] = true
			}
		}
	}
	// own reports a page that is one of its own wherever it is served: a
	// home page, or the page it is served at in another language.
	own := func(variant, page string) bool {
		if variant == index {
			return true
		}
		if locales == nil {
			return false
		}
		in, what := locales.Split(variant)
		at, where := locales.Split(page)
		return what == index || (what == where && in != at)
	}
	out := map[string]string{}
	add := func(variant, page string) {
		_, served := pages[page]
		_, published := pages[variant]
		if _, named := out[variant]; named || runs[variant] || own(variant, page) || !served || !published {
			return
		}
		out[variant] = page
	}
	if rules != nil {
		for _, r := range rules.Rules {
			if r.Enabled {
				add(r.Variant, r.Page)
			}
		}
	}
	if exps != nil {
		for _, e := range exps.Experiments {
			if e.Running {
				for _, v := range e.Variants {
					add(v.Page, e.Page)
				}
			}
		}
	}
	return out
}

// Listed reports whether a page is offered to search engines and agents by
// its own address: in the sitemap, in llms.txt and to IndexNow. Not one
// seo.InSitemap leaves out, nor a variant (Variants), unless the variant
// names an address of its own, which an editor who set one has decided.
func Listed(base, name, index string, body any, variants map[string]string) bool {
	if _, variant := variants[name]; variant {
		if _, own := seo.CanonicalOf(body); !own {
			return false
		}
	}
	return seo.InSitemap(base, name, index, body)
}

// variants is Variants for this site now, by the rules the page handler
// serves variants by: an experiment only with the counts that assign its
// visitors, a rule whenever there are rules. Read per call, like them, so
// starting a test takes effect without a publish.
func (st *Site) variants(pages map[string]any) map[string]string {
	var exps *experiment.Set
	if st.Experiments != nil && st.Analytics != nil {
		exps, _ = st.Experiments()
	}
	var rules *personalise.Set
	if st.Personalise != nil {
		rules, _ = st.Personalise()
	}
	return Variants(exps, rules, pages, st.Index, st.Locales)
}

// canonicalIn is the address name's canonical link names: as seo.Canonical
// says, except that a variant names the page it is served at.
func (st *Site) canonicalIn(name string, body any, variants map[string]string) string {
	if of, ok := variants[name]; ok {
		name = of
	}
	return seo.Canonical(st.BaseURL, name, st.Index, body)
}

// variantsTag names what variants says, for a tag on a document that
// depends on it; "" when no page is a variant. A test starts and stops with
// nothing published, so a tag made from the commit alone would tell a
// crawler holding the sitemap, or a variant's page, that what they say
// about the variant had not changed.
func variantsTag(variants map[string]string) string {
	if len(variants) == 0 {
		return ""
	}
	names := make([]string, 0, len(variants))
	for n := range variants {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n + "\x00" + variants[n] + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}
