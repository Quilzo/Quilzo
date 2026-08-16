// Package public serves the published site.
//
// Until now scrivet could store, review, mark and publish content and then not
// show it to anybody. `serve` was the admin. This is the half that makes it a
// website rather than a filing system.
//
// # Caching falls out of the architecture
//
// Content is immutable and addressed by the hash of its bytes, so a page's ETag
// is its content hash — not derived from it, not a proxy for it, it simply is
// it. Two consequences that a conventional CMS has to work for:
//
// Cache invalidation stops being a problem. The usual difficulty is knowing
// when a URL's content changed; here a change *is* a different hash, so a
// conditional request answers itself.
//
// Nothing has to be purged on publish. Publishing moves a pointer, the next
// request computes a different ETag, and every cache in the path notices on its
// own.
//
// # The Article 50 mark goes in the page
//
// The provenance record was being kept in a file on the server, which is a
// record of the mark rather than the mark. A machine-readable marking has to be
// in the thing a machine reads, so it is injected into the head of every served
// page as meta tags and a JSON-LD block. The store keeps the durable record; the
// page carries the copy that travels.
package public

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/i18n"
	"github.com/rsh1k/scrivet/internal/listing"
	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/search"
	"github.com/rsh1k/scrivet/internal/seo"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
	"github.com/rsh1k/scrivet/internal/tmpl"
)

// Site serves the live ref.
type Site struct {
	Store    *store.Store
	Template string
	// Name and Description describe the site to a browser installing it.
	Name        string
	Description string
	// LoadProvenance supplies the marks injected into each page.
	LoadProvenance func() (*provenance.Index, error)
	// CSP returns the header name to send and whether to send one, and
	// CSPValue returns its value. Two functions rather than a struct so this
	// package does not import the csp package, which would make the dependency
	// point the wrong way: the policy is built from content, and this is what
	// serves content.
	CSP      func() (string, bool)
	CSPValue func() string
	// HSTS is Strict-Transport-Security's max-age. Zero sends no header.
	HSTS time.Duration

	// Ref is the store ref this site serves. Empty means the live ref, which
	// is what every deployment used before environments existed — so a Site
	// constructed without one behaves exactly as it always did.
	Ref string

	// Index is the page served at "/".
	Index string
	// Search is the index over what is published. Nil means the route 404s,
	// which is the honest state for a site that has not built one — a search
	// box that returns nothing is worse than no search box.
	Search *search.Index
	// Licence declares terms for automated crawlers under Really Simple
	// Licensing. Empty means no terms are declared, which is not the same as
	// permitting everything — it is saying nothing, and saying nothing is the
	// honest default until an operator decides.
	Licence *Licence
	// Stylesheet is served at /site.css, held in memory. Empty means the route
	// 404s rather than falling back to something: a site whose stylesheet
	// silently comes from somewhere else is a site whose appearance has an
	// owner nobody named.
	Stylesheet string
	// BaseURL is the absolute origin, needed because a sitemap must carry
	// absolute URLs and a server cannot reliably infer its own public name from
	// a request — Host is attacker-controlled, and trusting it turns the
	// sitemap into a way to make Google crawl somewhere else.
	BaseURL string
	// Redirects preserves old URLs after a migration. Nil is inert.
	Redirects *seo.Map
	// Locales is the site's language configuration, when it has more than one.
	// Nil means a single-language site and nothing about this feature appears
	// in the output.
	Locales *i18n.Config
	// LastChanged supplies each page's real modification time.
	LastChanged func() (map[string]time.Time, error)
	// Listings resolves the queries a page embeds. Nil means a page naming one
	// fails to assemble rather than rendering without it — a listing-shaped
	// hole is not noticed until somebody asks why the table is empty.
	Listings *listing.Resolver
	// Media serves the asset library at /media/. Nil means the route 404s,
	// which is right for a deployment with no library — and was, until this
	// field existed, the behaviour of every deployment including the ones with
	// one.
	Media MediaLookup
}

// New returns a Site with sensible defaults.
func New(s *store.Store, template string) *Site {
	return &Site{Store: s, Template: template, Index: "index", Name: "scrivet site"}
}

// Handler routes the public surface.
func (st *Site) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.webmanifest", st.manifest)
	mux.HandleFunc("/sw.js", st.serviceWorker)
	mux.HandleFunc("/offline", st.offline)
	mux.HandleFunc("/sitemap.xml", st.sitemap)
	mux.HandleFunc("/license.xml", st.licence)
	mux.HandleFunc("/search.json", st.searchAPI)
	mux.HandleFunc("/site.css", st.stylesheet)
	mux.HandleFunc("/robots.txt", st.robots)
	mux.HandleFunc("/llms.txt", st.llms)
	mux.HandleFunc("/media/", st.mediaFile)
	mux.HandleFunc("/", st.page)
	return st.securityHeaders(mux)
}

// stylesheet serves the site's CSS.
//
// Served from memory rather than from disk on each request, and never resolved
// against a caller-supplied path: a public server that maps a URL onto a
// filename is one traversal bug away from serving the token store. There is one
// stylesheet, it was loaded at startup, and the route returns it or 404s.
func (st *Site) stylesheet(w http.ResponseWriter, r *http.Request) {
	if st.Stylesheet == "" {
		http.NotFound(w, r)
		return
	}
	// The stylesheet changes only when the operator restarts, so it can be
	// cached hard — but it is validated by ETag anyway, so a proxy that ignores
	// max-age still cannot serve a stale one after a redeploy.
	sum := sha256.Sum256([]byte(st.Stylesheet))
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.WriteString(w, st.Stylesheet)
}

// sitemap lists the live pages with the date each last actually changed.
func (st *Site) sitemap(w http.ResponseWriter, r *http.Request) {
	if st.BaseURL == "" {
		// Refused rather than guessed from the Host header. Host is
		// attacker-controlled, and a sitemap built from it is a way to make a
		// crawler fetch somebody else's URLs believing they are yours.
		http.Error(w, "no base URL is configured, so absolute URLs cannot be "+
			"produced; run with --base-url https://example.com",
			http.StatusNotFound)
		return
	}
	live := st.Store.GetRef(st.ref())
	if live == "" {
		http.NotFound(w, r)
		return
	}
	pages, err := site.PagesAt(st.Store, live)
	if err != nil {
		http.Error(w, "the site could not be read", http.StatusInternalServerError)
		return
	}

	var changed map[string]time.Time
	if st.LastChanged != nil {
		changed, _ = st.LastChanged()
	}

	names := make([]string, 0, len(pages))
	for name := range pages {
		names = append(names, name)
	}
	sort.Strings(names)

	base := strings.TrimSuffix(st.BaseURL, "/")
	present := map[string]bool{}
	for _, name := range names {
		present[name] = true
	}

	entries := make([]seo.Entry, 0, len(names))
	for _, name := range names {
		loc := base + "/" + name
		if name == st.Index {
			loc = base + "/"
		}
		e := seo.Entry{Loc: loc, LastMod: changed[name]}

		// hreflang, for the languages this page genuinely exists in. Computed
		// from what is actually published rather than from what is configured,
		// because a declared language with no translation is the case that
		// sends a reader to a page that is not there.
		if st.Locales != nil {
			_, page := st.Locales.Split(name)
			for _, a := range st.Locales.Alternates(page, base, present) {
				e.Alternates = append(e.Alternates, seo.Alternate{
					Locale: string(a.Locale), Href: a.Href})
			}
			if len(e.Alternates) < 2 {
				// One alternate is the page pointing at itself, which says
				// nothing and adds bytes to every crawl.
				e.Alternates = nil
			}
		}
		entries = append(entries, e)
	}

	out, err := seo.Sitemap(entries)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	_, _ = io.WriteString(w, out)
}

// redirected sends the response if this path has moved, and reports whether it
// did.
//
// Checked before anything else, because a redirect that only fires when the
// target does not exist is a redirect that stops working the moment somebody
// creates a page with the old name.
func (st *Site) redirected(w http.ResponseWriter, r *http.Request) bool {
	rd, ok := st.Redirects.Lookup(r.URL.Path)
	if !ok {
		return false
	}
	target := rd.To
	// A relative target keeps the query string, so a link with tracking
	// parameters survives the move.
	if r.URL.RawQuery != "" && !strings.Contains(target, "?") &&
		!strings.Contains(target, "://") {
		target += "?" + r.URL.RawQuery
	}
	w.Header().Set("Location", target)
	// A permanent redirect is cached by browsers effectively forever, so it is
	// worth being explicit that this is deliberate.
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(rd.Status())
	return true
}

// Licence is the terms an operator sets for automated use of their content.
//
// Really Simple Licensing, whose 1.0 specification was finalised in December
// 2025. The premise is worth stating because it is a change of shape rather
// than a new file: robots.txt says whether to crawl, and this says on what
// terms — attribution, a licence to point at, or a fee.
//
// Emitted honestly. RSL is young and enforcement depends on crawlers choosing
// to honour it, exactly as robots.txt always has. What it does is make the
// terms machine-readable and explicit, so "we never said they could" becomes a
// document with a date rather than an argument afterwards.
type Licence struct {
	// Permits says what automated use is allowed: "train", "search",
	// "ai-summarize", or "none".
	Permits []string
	// Prohibits is the same vocabulary, for what is refused.
	Prohibits []string
	// Attribution is a URL a crawler should credit.
	Attribution string
	// Contact is where to ask, which is the part that makes a refusal a
	// negotiation rather than a wall.
	Contact string
	// Standard names a well-known licence, if one applies.
	Standard string
}

// licence serves the RSL document.
//
// Refused rather than invented when nothing is configured: a licence file
// asserting terms nobody chose is worse than none, because a crawler will
// honour it and the operator never agreed to it.
func (st *Site) licence(w http.ResponseWriter, r *http.Request) {
	if st.Licence == nil {
		http.NotFound(w, r)
		return
	}
	l := st.Licence

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<rsl xmlns="https://rslstandard.org/rsl">` + "\n")
	b.WriteString(`  <content url="/">` + "\n")
	for _, p := range l.Permits {
		fmt.Fprintf(&b, "    <permits type=%q/>\n", p)
	}
	for _, p := range l.Prohibits {
		fmt.Fprintf(&b, "    <prohibits type=%q/>\n", p)
	}
	if l.Standard != "" {
		fmt.Fprintf(&b, "    <legal type=\"license\">%s</legal>\n",
			escapeXMLText(l.Standard))
	}
	if l.Attribution != "" {
		fmt.Fprintf(&b, "    <copyright>%s</copyright>\n",
			escapeXMLText(l.Attribution))
	}
	if l.Contact != "" {
		fmt.Fprintf(&b, "    <contact>%s</contact>\n", escapeXMLText(l.Contact))
	}
	b.WriteString("  </content>\n</rsl>\n")

	w.Header().Set("Content-Type", "application/rsl+xml; charset=utf-8")
	_, _ = io.WriteString(w, b.String())
}

// escapeXMLText escapes the characters that must be escaped in XML content.
//
// Hand-written rather than reached for, because the set is fixed and a licence
// document that fails to parse because somebody's company name contains an
// ampersand is a licence nothing reads.
func escapeXMLText(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;",
	).Replace(s)
}

// searchAPI answers a query.
//
// JSON rather than a rendered page, because the template language deliberately
// cannot loop over something the server computed at request time — and adding
// that capability to serve a search page would be reintroducing the execution
// this project removed on purpose. A site that wants a rendered results page
// fetches this, which is the one place a published site legitimately needs a
// script.
func (st *Site) searchAPI(w http.ResponseWriter, r *http.Request) {
	if st.Search == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query().Get("q")
	if len(q) > 200 {
		// Bounded before tokenising. A very long query is not a search, and
		// the work of tokenising it is work somebody else chose for this
		// machine to do.
		http.Error(w, "the query is too long", http.StatusBadRequest)
		return
	}

	results := st.Search.Search(q, 20)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// No caching. A results page cached by a proxy is a results page served to
	// somebody who searched for something else.
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"query":   q,
		"results": results,
		"count":   len(results),
	})
}

// securityHeaders for a public site.
//
// The CSP is nearly as strict as the admin's, with one difference: the service
// worker needs to be loadable, and published pages may carry images. Everything
// executable stays forbidden, which costs nothing because the template language
// cannot produce script in the first place.
func (st *Site) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// The generated policy when there is one, and the old fixed policy
		// otherwise.
		//
		// The fixed one contained `img-src 'self' data: https:`, and that last
		// token permits images from every host that speaks TLS — which is
		// every host. It is what a hand-written policy decays into: widened
		// once so a page would render, never narrowed again, because narrowing
		// means knowing what the content references and nobody does. The
		// generator does: it reads the URLs out of the content and names the
		// hosts. The fallback is kept only for a server constructed without
		// one, which is a test.
		name, value := "Content-Security-Policy", defaultCSP
		if st.CSP != nil {
			if n, send := st.CSP(); send {
				name, value = n, st.CSPValue()
			} else {
				name = ""
			}
		}
		if name != "" {
			h.Set(name, value)
		}

		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Vary, whenever this site has more than one language.
		//
		// Not cosmetic and not optional. A response that depends on
		// Accept-Language and does not say so is one a shared cache hands to
		// the next visitor in the wrong language — and the bug is invisible
		// from the origin, which is serving everybody correctly. It is found
		// by a customer in another country, weeks later, and is very hard to
		// believe.
		if st.Locales != nil && len(st.Locales.Locales) > 1 {
			h.Add("Vary", i18n.VaryHeader)
		}
		if st.HSTS > 0 {
			// Only when the operator has said this process is the edge. Set
			// wrongly on a host that later needs plain HTTP, HSTS is not
			// quickly undone — browsers remember it for the max-age whatever
			// the server later says.
			h.Set("Strict-Transport-Security",
				fmt.Sprintf("max-age=%d", int(st.HSTS.Seconds())))
		}
		next.ServeHTTP(w, r)
	})
}

// defaultCSP is what a Site with no generated policy serves.
const defaultCSP = "default-src 'none'; img-src 'self' data:; " +
	"style-src 'self' 'unsafe-inline'; script-src 'self'; manifest-src 'self'; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// pages returns the live content and the tree that names each page's hash.
func (st *Site) pages() (map[string]any, map[string]string, error) {
	live := st.Store.GetRef(st.ref())
	if live == "" {
		return nil, nil, fmt.Errorf("nothing is published")
	}
	c, err := st.Store.GetCommit(live)
	if err != nil {
		return nil, nil, err
	}
	tree, err := st.Store.GetTree(c.Tree)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]any{}
	for name, oid := range tree {
		var body any
		if err := st.Store.GetBlob(oid, &body); err != nil {
			continue
		}
		out[name] = body
	}
	return out, tree, nil
}

func (st *Site) page(w http.ResponseWriter, r *http.Request) {
	// Redirects first. One that only fires when the target is missing stops
	// working the moment somebody creates a page with the old name — which is
	// the most likely thing to happen after a migration.
	if st.redirected(w, r) {
		return
	}

	name := strings.Trim(r.URL.Path, "/")
	if name == "" {
		name = st.Index
	}

	pages, tree, err := st.pages()
	if err != nil {
		http.Error(w, "nothing is published", http.StatusServiceUnavailable)
		return
	}
	body, ok := pages[name]
	if !ok {
		// The site's own 404, not Go's plain-text one. This is the route a
		// visitor reaches from a stale link; the asset and JSON routes above
		// keep the plain response, because a stylesheet request answered with
		// an HTML page is worse than one answered with a string.
		st.notFound(w, r)
		return
	}

	// The ETag is the content hash. Not derived from it — it is it.
	// The page's own content hash is its identity — until the page embeds a
	// listing, and then it is not.
	//
	// A listing reads records, so the rendered output depends on content this
	// page's hash says nothing about. Serving the page's hash as the ETag
	// would mean a listing that never updates: the records change, the page
	// body does not, the conditional request answers 304, and every reader
	// sees yesterday's rows for as long as the page is untouched.
	//
	// So a page with listings mixes in the tree the listings read and the
	// arguments they were given. Both are part of what was rendered, so both
	// belong in the name of it.
	etag := `"` + tree[name] + `"`
	args := firstOf(r.URL.Query())
	if names := listing.On(body); len(names) > 0 {
		etag = `"` + renderTag(tree[name], st.dataTree(), names, args) + `"`
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	ctx := map[string]any{
		"page": body, "site": map[string]any{"name": st.Name},
	}
	if names := listing.On(body); len(names) > 0 && st.Listings == nil {
		// The hole this was written to prevent, and it happened anyway: the
		// admin got a resolver and the public server did not, so a page that
		// showed its listing in preview rendered without it for readers —
		// silently, because a missing section looks like a section with
		// nothing in it. Found by publishing the page and looking at it.
		http.Error(w, "this page could not be assembled",
			http.StatusInternalServerError)
		return
	}
	if st.Listings != nil {
		data, lerr := st.Listings.For(body, args)
		if lerr != nil {
			// A page whose listings cannot be resolved is a broken page, not a
			// page with an empty section. Rendering it without them would ship
			// a listing-shaped hole that nobody notices until somebody asks
			// why the table is empty.
			http.Error(w, "this page could not be assembled",
				http.StatusInternalServerError)
			return
		}
		if data != nil {
			ctx[listing.Data] = data
		}
	}

	html, err := tmpl.Render(st.Template, ctx)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	html = st.injectHead(html, name, tree[name])
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

// injectHead adds the manifest link and the provenance marking.
//
// Inserted before </head> rather than asked of the template author, because a
// legal marking that depends on every template remembering to include a partial
// is a marking that will be missing from the one template nobody checked.
func (st *Site) injectHead(html, page, hash string) string {
	var b strings.Builder
	b.WriteString(`<link rel="manifest" href="/manifest.webmanifest">` + "\n")

	if st.LoadProvenance != nil {
		if idx, err := st.LoadProvenance(); err == nil {
			if rec, ok := idx.Get(page); ok && rec.ContentHash == hash {
				b.WriteString(rec.MetaTags())
				if ld, err := rec.JSONLD(); err == nil && rec.SourceType.RequiresDisclosure() {
					b.WriteString(`<script type="application/ld+json">` + "\n")
					b.WriteString(ld)
					b.WriteString("\n</script>\n")
				}
			}
		}
	}

	head := strings.Index(strings.ToLower(html), "</head>")
	if head < 0 {
		// No head to inject into. Prepending is worse than nothing here — it
		// would put meta tags outside the document — so the page is served as
		// it is and the absence shows up in `provenance check` rather than
		// being papered over.
		return html
	}
	return html[:head] + b.String() + html[head:]
}

// manifest describes the site to a browser being asked to install it.
func (st *Site) manifest(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"name":             st.Name,
		"short_name":       shorten(st.Name),
		"description":      st.Description,
		"start_url":        "/",
		"scope":            "/",
		"display":          "standalone",
		"background_color": "#ffffff",
		"theme_color":      "#0b5c6b",
		// An installable app has to work offline, and this is the page that
		// makes that true rather than a promise.
		"icons": []map[string]any{},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(b)
}

// serviceWorker caches published pages so the site survives losing the network.
//
// Deliberately small and deliberately conservative. A service worker is the one
// piece of script a scrivet site ships, and a caching bug in one is uniquely
// unpleasant: it persists across reloads and serves stale content to somebody
// who cannot work out why. So it is network-first — the network wins whenever it
// answers, and the cache is only consulted when it does not.
//
// That is the opposite of the usual advice for speed, and the right trade for a
// CMS: publishing must take effect immediately, and a stale page is a worse
// failure than a slow one.
func (st *Site) serviceWorker(w http.ResponseWriter, r *http.Request) {
	js := `// scrivet service worker. Network-first: publishing must take effect at once,
// and a stale page is worse than a slow one.
const CACHE = 'scrivet-v1';
const OFFLINE = '/offline';

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.add(OFFLINE)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;

  e.respondWith(
    fetch(e.request)
      .then((res) => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
        }
        return res;
      })
      .catch(() =>
        caches.match(e.request).then((hit) => hit || caches.match(OFFLINE))
      )
  );
});
`
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(js))
}

func (st *Site) offline(w http.ResponseWriter, r *http.Request) {
	// Plain, self-contained, and accessible: it is shown to somebody who has
	// already lost the network, so it cannot fetch anything.
	html := `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Offline — ` + escapeText(st.Name) + `</title>
<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;
line-height:1.6}h1{font-size:1.5rem}</style></head>
<body><main><h1>You are offline</h1>
<p>This page has not been visited on this device, so there is no copy stored here.
Pages you have already opened remain available.</p>
<p><a href="/">Try the home page</a></p></main></body></html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(html))
}

func (st *Site) robots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "User-agent: *\nAllow: /\n\nSitemap: /sitemap.xml\n")
	// One of the channels RSL uses to advertise terms. Pointing at it from
	// robots.txt is what makes it discoverable by a crawler that already reads
	// robots.txt, which is all of them.
	if st.Licence != nil {
		fmt.Fprintf(w, "License: /license.xml\n")
	}
}

// llms is a curated index for language models.
//
// Emitted because it costs a few lines, and labelled honestly because the
// evidence does not support more. Adoption sits around one site in ten, roughly
// four in ten of those files are plugin stubs, and as of early 2026 no major
// crawler — OpenAI, Google, Anthropic, Meta, Mistral — commits to reading it;
// they fetch the HTML instead. It is a community convention with no standards
// body behind it.
//
// So it is here as a cheap bet rather than a feature, and the README says the
// same. Shipping it as "AI-ready" would be selling a file nothing reads.
func (st *Site) llms(w http.ResponseWriter, r *http.Request) {
	pages, _, err := st.pages()
	if err != nil {
		http.Error(w, "nothing is published", http.StatusServiceUnavailable)
		return
	}
	names := make([]string, 0, len(pages))
	for n := range pages {
		names = append(names, n)
	}
	sort.Strings(names)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "# %s\n\n", st.Name)
	if st.Description != "" {
		fmt.Fprintf(w, "> %s\n\n", st.Description)
	}
	fmt.Fprintf(w, "## Pages\n\n")
	for _, n := range names {
		title := n
		if m, ok := pages[n].(map[string]any); ok {
			if t, ok := m["title"].(string); ok && t != "" {
				title = t
			}
		}
		fmt.Fprintf(w, "- [%s](/%s)\n", title, n)
	}
}

func shorten(name string) string {
	if len(name) <= 12 {
		return name
	}
	return name[:12]
}

func escapeText(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// Fingerprint is a stable identifier for the whole published site, for anything
// that wants to know whether it has changed without diffing it.
func (st *Site) Fingerprint() string {
	_, tree, err := st.pages()
	if err != nil {
		return ""
	}
	names := make([]string, 0, len(tree))
	for n := range tree {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte(tree[n]))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

var _ = time.Now // reserved for cache-age reporting

// ref is the store ref this site serves.
func (st *Site) ref() string {
	if st.Ref == "" {
		return site.RefLive
	}
	return st.Ref
}
