package public

import (
	"net/http"
	"strings"
)

// Instant navigation on a site that runs no script.
//
// # The obstacle
//
// The Speculation Rules API is normally reached through
// `<script type="speculationrules">`. This site sends `script-src 'none'` and
// a test asserts it, so that element never runs -- and it fails silently,
// which is the worst way for a performance feature to not work: the page is
// correct, the rules are in the markup, and nothing speculates.
//
// There is a second route. A `Speculation-Rules` header names a JSON document,
// no element is involved, and the policy is untouched. That is the one used
// here, and it is a better fit than a workaround: the rules are the same for
// every page, so sending them once as a cacheable document beats repeating
// them in every response body.
//
// # What is speculated, and what is not
//
// Prefetch, at moderate eagerness. Moderate means the browser acts on hover or
// pointer-down -- on a reader who has shown intent -- rather than on every
// link in view. So the bandwidth this spends is roughly proportional to what
// somebody was about to ask for anyway, which is the difference between a
// speed feature and a bill.
//
// Prerender is offered and is not the default. It renders the page, which on a
// site that executes nothing is unusually safe -- no analytics beacon, no
// counter, no side effect to fire early. It still downloads and lays out a
// document nobody may ever read, and a reader on a metered connection did not
// ask for that.
//
// Media is excluded. A prefetched image is a download, not a navigation, and
// the rules only ever match document navigations; naming the exclusion anyway
// keeps a future change to the pattern from quietly widening it.

// SpeculationPath is where the rules document is served.
const SpeculationPath = "/speculationrules.json"

// SpeculationType is the media type the rules must be served as. A browser
// that gets anything else ignores the document, and says nothing about it.
const SpeculationType = "application/speculationrules+json"

// Speculation is what a site speculates.
type Speculation string

const (
	// SpeculateOff sends no rules at all.
	SpeculateOff Speculation = "off"
	// SpeculatePrefetch fetches the document ahead of the click.
	SpeculatePrefetch Speculation = "prefetch"
	// SpeculatePrerender fetches and renders it.
	SpeculatePrerender Speculation = "prerender"
)

// Valid reports whether a configured value is one this understands.
func (s Speculation) Valid() bool {
	switch s {
	case SpeculateOff, SpeculatePrefetch, SpeculatePrerender, "":
		return true
	}
	return false
}

// rules is the JSON document, built rather than templated so the two
// speculation kinds cannot drift into different shapes.
//
// The URL pattern is every path on this origin, minus the ones that are not
// documents. "where" with an href_matches pattern is same-origin by
// construction: a relative pattern matches only this site.
func (s Speculation) rules() string {
	kind := string(s)
	if s == "" || s == SpeculateOff {
		return ""
	}
	return `{
  "` + kind + `": [
    {
      "source": "document",
      "where": {
        "and": [
          { "href_matches": "/*" },
          { "not": { "href_matches": "/media/*" } },
          { "not": { "href_matches": "/*\\?*" } },
          { "not": { "selector_matches": "[rel~=nofollow]" } }
        ]
      },
      "eagerness": "moderate"
    }
  ]
}
`
}

// speculationRules serves the document.
func (st *Site) speculationRules(w http.ResponseWriter, r *http.Request) {
	body := st.speculation().rules()
	if body == "" {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", SpeculationType)
	// Cacheable, because it is the same for every page and every reader. This
	// is the whole reason the header form is better here than the element:
	// the rules are fetched once rather than parsed out of every response.
	h.Set("Cache-Control", "public, max-age=3600")
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(body))
}

// speculation is the configured setting, defaulting to prefetch.
//
// On by default because moderate eagerness spends bandwidth only on a reader
// who has already reached for the link, and because a site whose whole
// argument is that pages are static should not be slower to move around than
// one that ships a router.
func (st *Site) speculation() Speculation {
	if st.Speculate == "" {
		return SpeculatePrefetch
	}
	if !st.Speculate.Valid() {
		return SpeculateOff
	}
	return st.Speculate
}

// setSpeculationHeader points a document response at the rules.
//
// Only on HTML. A browser asking for a stylesheet has nothing to speculate
// about, and the header on every response is bytes spent on nothing.
func (st *Site) setSpeculationHeader(w http.ResponseWriter) {
	if st.speculation() == SpeculateOff {
		return
	}
	if ct := w.Header().Get("Content-Type"); ct != "" &&
		!strings.HasPrefix(ct, "text/html") {
		return
	}
	w.Header().Set("Speculation-Rules", `"`+SpeculationPath+`"`)
}
