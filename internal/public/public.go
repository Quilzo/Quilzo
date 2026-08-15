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

	"github.com/rsh1k/scrivet/internal/provenance"
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
	// Index is the page served at "/".
	Index string
	// Stylesheet is served at /site.css, held in memory. Empty means the route
	// 404s rather than falling back to something: a site whose stylesheet
	// silently comes from somewhere else is a site whose appearance has an
	// owner nobody named.
	Stylesheet string
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
	mux.HandleFunc("/site.css", st.stylesheet)
	mux.HandleFunc("/robots.txt", st.robots)
	mux.HandleFunc("/llms.txt", st.llms)
	mux.HandleFunc("/", st.page)
	return securityHeaders(mux)
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

// securityHeaders for a public site.
//
// The CSP is nearly as strict as the admin's, with one difference: the service
// worker needs to be loadable, and published pages may carry images. Everything
// executable stays forbidden, which costs nothing because the template language
// cannot produce script in the first place.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; manifest-src 'self'; connect-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// pages returns the live content and the tree that names each page's hash.
func (st *Site) pages() (map[string]any, map[string]string, error) {
	live := st.Store.GetRef(site.RefLive)
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
		http.NotFound(w, r)
		return
	}

	// The ETag is the content hash. Not derived from it — it is it.
	etag := `"` + tree[name] + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	html, err := tmpl.Render(st.Template, map[string]any{
		"page": body, "site": map[string]any{"name": st.Name},
	})
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
	fmt.Fprintf(w, "User-agent: *\nAllow: /\n\nSitemap: /sitemap.txt\n")
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
