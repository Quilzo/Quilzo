package public

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/site"
	"github.com/rsh1k/scrivet/internal/store"
)

const pageTemplate = `<!doctype html>
<html lang="en"><head><title>{{ page.title }}</title></head>
<body><h1>{{ page.title }}</h1><p>{{ page.body }}</p></body></html>`

func setup(t *testing.T) (*Site, *store.Store) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index": map[string]any{"title": "Home", "body": "Welcome."},
		"about": map[string]any{"title": "About", "body": "Who we are."},
	}
	if _, err := site.SaveDraft(s, pages, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	st := New(s, pageTemplate)
	st.Name = "Example"
	return st, s
}

func get(st *Site, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	return w
}

func TestServesThePublishedPage(t *testing.T) {
	st, _ := setup(t)
	w := get(st, "/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "<h1>Home</h1>") {
		t.Errorf("the page did not render: %q", w.Body.String()[:80])
	}
	if code := get(st, "/nope", nil).Code; code != http.StatusNotFound {
		t.Errorf("a missing page should 404, got %d", code)
	}
}

// Draft content must never be public. Publishing is the only thing that makes
// something visible, and if serving read the draft the whole review step would
// be decorative.
func TestOnlyPublishedContentIsServed(t *testing.T) {
	st, s := setup(t)
	pages, _ := site.PagesAt(s, site.RefLive)
	pages["secret"] = map[string]any{"title": "Unpublished", "body": "Draft only."}
	if _, err := site.SaveDraft(s, pages, "add a draft", "test"); err != nil {
		t.Fatal(err)
	}

	if code := get(st, "/secret", nil).Code; code != http.StatusNotFound {
		t.Errorf("a draft page was served publicly: %d", code)
	}
}

// The architectural payoff: the ETag is the content hash, so a conditional
// request answers itself and nothing needs purging on publish.
func TestETagIsTheContentHashAndRevalidates(t *testing.T) {
	st, s := setup(t)
	first := get(st, "/", nil)
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}

	again := get(st, "/", map[string]string{"If-None-Match": etag})
	if again.Code != http.StatusNotModified {
		t.Errorf("an unchanged page should 304, got %d", again.Code)
	}

	// Change the content and publish; the ETag must move on its own.
	pages, _ := site.PagesAt(s, site.RefLive)
	pages["index"] = map[string]any{"title": "Home", "body": "Changed."}
	if _, err := site.SaveDraft(s, pages, "edit", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	after := get(st, "/", map[string]string{"If-None-Match": etag})
	if after.Code == http.StatusNotModified {
		t.Error("a changed page still reported 304; caches would serve stale content")
	}
	if after.Header().Get("ETag") == etag {
		t.Error("the ETag did not change with the content")
	}
}

// The Article 50 mark has to be in the thing a machine reads. A record in a
// file on the server is a record of the mark, not the mark.
func TestProvenanceIsInjectedIntoTheServedPage(t *testing.T) {
	st, s := setup(t)
	live := s.GetRef(site.RefLive)
	c, _ := s.GetCommit(live)
	tree, _ := s.GetTree(c.Tree)

	idx := provenance.NewIndex()
	if err := idx.Set("index", provenance.Record{
		ContentHash: tree["index"], SourceType: provenance.TrainedAlgorithmicMedia,
		Model: "gpt-oss:20b", Author: "rsh1k",
	}); err != nil {
		t.Fatal(err)
	}
	st.LoadProvenance = func() (*provenance.Index, error) { return idx, nil }

	body := get(st, "/", nil).Body.String()
	if !strings.Contains(body, `c2pa:digitalSourceType" content="trainedAlgorithmicMedia"`) {
		t.Error("the machine-readable mark is missing from the served page")
	}
	if !strings.Contains(body, "application/ld+json") {
		t.Error("AI content should carry structured data too")
	}
	if !strings.Contains(body, "has not been reviewed by a person") {
		t.Error("the disclosure should reach the reader")
	}

	// A page with no record must carry no claim.
	if strings.Contains(get(st, "/about", nil).Body.String(), "ai-generated") {
		t.Error("an unmarked page was marked as AI-generated")
	}
}

// Stale provenance must not be emitted: it describes bytes that are no longer
// being served, and publishing it would be a false statement about this page.
func TestStaleProvenanceIsNotEmitted(t *testing.T) {
	st, _ := setup(t)
	idx := provenance.NewIndex()
	if err := idx.Set("index", provenance.Record{
		ContentHash: "a-hash-of-some-older-version",
		SourceType:  provenance.TrainedAlgorithmicMedia,
		Model:       "old-model", Author: "rsh1k",
	}); err != nil {
		t.Fatal(err)
	}
	st.LoadProvenance = func() (*provenance.Index, error) { return idx, nil }

	if strings.Contains(get(st, "/", nil).Body.String(), "old-model") {
		t.Error("a record describing different bytes was emitted for this page")
	}
}

func TestManifestMakesTheSiteInstallable(t *testing.T) {
	st, _ := setup(t)
	w := get(st, "/manifest.webmanifest", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("no manifest: %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/manifest+json" {
		t.Errorf("wrong content type: %q", ct)
	}
	for _, want := range []string{`"start_url"`, `"display"`, `"scope"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("the manifest is missing %s", want)
		}
	}
	if !strings.Contains(get(st, "/", nil).Body.String(), `rel="manifest"`) {
		t.Error("pages should link the manifest, or nothing offers to install")
	}
}

// A caching bug in a service worker persists across reloads and serves stale
// content to somebody who cannot work out why, so the strategy matters.
func TestServiceWorkerIsNetworkFirst(t *testing.T) {
	st, _ := setup(t)
	w := get(st, "/sw.js", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("no service worker: %d", w.Code)
	}
	js := w.Body.String()

	// The network is tried first and the cache is the fallback. Reversed, a
	// publish would not reach anyone who had already visited.
	fetchAt := strings.Index(js, "fetch(e.request)")
	catchAt := strings.Index(js, ".catch(")
	if fetchAt < 0 || catchAt < 0 || catchAt < fetchAt {
		t.Error("the worker should try the network before falling back to cache")
	}
	if !strings.Contains(js, "e.request.method !== 'GET'") {
		t.Error("only GETs should be cached; caching a POST would be a bug")
	}
	if strings.Contains(w.Header().Get("Cache-Control"), "max-age=3") {
		t.Error("the worker itself must not be cached hard, or it cannot be replaced")
	}
}

func TestOfflinePageIsSelfContained(t *testing.T) {
	st, _ := setup(t)
	body := get(st, "/offline", nil).Body.String()
	// Shown to somebody who has already lost the network, so it must not fetch.
	if strings.Contains(body, "src=") || strings.Contains(body, `rel="stylesheet"`) {
		t.Error("the offline page fetches something; it cannot")
	}
	if !strings.Contains(body, `lang="en"`) {
		t.Error("the offline page needs a language like any other")
	}
}

func TestLLMsIndexListsPublishedPages(t *testing.T) {
	st, _ := setup(t)
	body := get(st, "/llms.txt", nil).Body.String()
	for _, want := range []string{"# Example", "(/index)", "(/about)"} {
		if !strings.Contains(body, want) {
			t.Errorf("llms.txt is missing %s: %q", want, body)
		}
	}
}

func TestNothingPublishedIsNotAnError(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := New(s, pageTemplate)
	if code := get(st, "/", nil).Code; code != http.StatusServiceUnavailable {
		t.Errorf("an empty site should say so, got %d", code)
	}
}

func TestSecurityHeadersOnPublicPages(t *testing.T) {
	st, _ := setup(t)
	h := get(st, "/", nil).Header()
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP should deny by default: %q", csp)
	}
	if strings.Contains(csp, "unsafe-eval") {
		t.Error("nothing here needs eval")
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
}

// The starter templates link /site.css, so the public server has to serve it or
// every shipped template renders unstyled — which looks like the tool is broken
// rather than like a route is missing.
func TestTheStylesheetIsServedAndCachedByContent(t *testing.T) {
	st, _ := setup(t)
	st.Stylesheet = ":root { --x: 1 }"

	req := httptest.NewRequest(http.MethodGet, "/site.css", nil)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/site.css returned %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("served as %q", ct)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag, so a redeploy cannot invalidate a cached stylesheet")
	}

	// The same ETag must produce a 304, or the cache header is a promise the
	// server does not keep.
	req = httptest.NewRequest(http.MethodGet, "/site.css", nil)
	req.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotModified {
		t.Errorf("a matching ETag returned %d", w.Code)
	}

	// Changing the stylesheet must change the tag, or a redeploy serves stale
	// CSS until every cache expires.
	st.Stylesheet = ":root { --x: 2 }"
	req = httptest.NewRequest(http.MethodGet, "/site.css", nil)
	req.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusNotModified {
		t.Error("an edited stylesheet still matched the old ETag")
	}
}

// No stylesheet means 404, not a fallback. A site whose appearance silently
// comes from somewhere else has an owner nobody named.
func TestNoStylesheetIsANotFoundRatherThanASubstitute(t *testing.T) {
	st, _ := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/site.css", nil)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 with no stylesheet configured, got %d", w.Code)
	}
}

// A licence file asserting terms nobody chose is worse than none, because a
// crawler will honour it and the operator never agreed to it.
func TestNoLicenceMeansNoLicenceFile(t *testing.T) {
	st, _ := setup(t)
	w := get(st, "/license.xml", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("a licence was served with none configured: %d", w.Code)
	}
	// And robots.txt must not point at a file that does not exist.
	if strings.Contains(get(st, "/robots.txt", nil).Body.String(), "License:") {
		t.Error("robots.txt advertises a licence that is not served")
	}
}

func TestTheLicenceIsValidXMLAndCarriesTheTerms(t *testing.T) {
	st, _ := setup(t)
	st.Licence = &Licence{
		Permits:     []string{"search"},
		Prohibits:   []string{"train"},
		Attribution: "Example & Co",
		Contact:     "licensing@example.com",
		Standard:    "CC-BY-4.0",
	}

	w := get(st, "/license.xml", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("returned %d", w.Code)
	}
	body := w.Body.String()

	var parsed struct {
		Content struct {
			Permits []struct {
				Type string `xml:"type,attr"`
			} `xml:"permits"`
			Prohibits []struct {
				Type string `xml:"type,attr"`
			} `xml:"prohibits"`
			Copyright string `xml:"copyright"`
			Contact   string `xml:"contact"`
			Legal     string `xml:"legal"`
		} `xml:"content"`
	}
	if err := xml.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("the licence does not parse: %v\n%s", err, body)
	}
	if len(parsed.Content.Permits) != 1 || parsed.Content.Permits[0].Type != "search" {
		t.Errorf("permits not carried: %#v", parsed.Content.Permits)
	}
	if len(parsed.Content.Prohibits) != 1 || parsed.Content.Prohibits[0].Type != "train" {
		t.Errorf("prohibits not carried: %#v", parsed.Content.Prohibits)
	}
	// An ampersand in a company name must not make the document unparseable —
	// a licence nothing can read is a licence nobody honours.
	if parsed.Content.Copyright != "Example & Co" {
		t.Errorf("the attribution did not survive escaping: %q",
			parsed.Content.Copyright)
	}
	if parsed.Content.Contact == "" {
		t.Error("no contact, so a refusal is a wall rather than a negotiation")
	}

	// And robots.txt points at it, which is how a crawler that already reads
	// robots.txt finds it.
	if !strings.Contains(get(st, "/robots.txt", nil).Body.String(), "/license.xml") {
		t.Error("robots.txt does not advertise the licence")
	}
}

// -- the 404 a visitor actually reaches --------------------------------------

// Go's http.NotFound writes "404 page not found" as plain text. On a site
// whose every other surface is designed, that is the page a visitor is most
// likely to reach — from a stale link, a search result, a typo — rendered as a
// debugging string.
func TestAMissingPageGetsTheSitesOwn404(t *testing.T) {
	st, _ := setup(t)
	st.Name = "Acme"
	st.Stylesheet = "body{}"

	w := get(st, "/nothing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("the 404 is %q", w.Header().Get("Content-Type"))
	}
	for _, want := range []string{"<!doctype html>", "Page not found", "Acme",
		`href="/site.css"`, `content="noindex"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the 404 page does not contain %q:\n%s", want, body)
		}
	}
}

// It must not reflect the requested path. That is the standard way a 404 page
// becomes cross-site scripting, and the path is in the visitor's address bar
// already — showing it back adds nothing they cannot see.
func TestThe404PageDoesNotReflectTheRequestedPath(t *testing.T) {
	st, _ := setup(t)
	// Built by hand rather than through httptest.NewRequest, which parses the
	// target and rejects the hostile forms before the server sees them —
	// which is the harness refusing the input, not the server.
	for _, path := range []string{
		"/<script>alert(1)</script>",
		"/%3Cscript%3Ealert(1)%3C/script%3E",
		`/"><img src=x onerror=alert(1)>`,
	} {
		req := httptest.NewRequest(http.MethodGet, "/placeholder", nil)
		req.URL.Path = path
		req.URL.RawPath = path
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, req)
		body := w.Body.String()
		for _, bad := range []string{"<script>", "onerror=", "<img src=x"} {
			if strings.Contains(body, bad) {
				t.Errorf("requesting %q put %q in the 404 body", path, bad)
			}
		}
	}
}

// A stylesheet request answered with an HTML page is worse than one answered
// with a string, so the asset and JSON routes keep the plain response.
func TestAssetRoutesStillAnswerPlainly(t *testing.T) {
	st, _ := setup(t)
	st.Stylesheet = "" // so /site.css 404s
	w := get(st, "/site.css", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "<!doctype html>") {
		t.Error("a missing stylesheet was answered with an HTML page")
	}
}

// A HEAD must carry the status and the headers without the body.
func TestAHeadRequestForAMissingPageHasNoBody(t *testing.T) {
	st, _ := setup(t)
	r := httptest.NewRequest("HEAD", "http://h/nothing", nil)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("a HEAD returned %d bytes of body", w.Body.Len())
	}
}
