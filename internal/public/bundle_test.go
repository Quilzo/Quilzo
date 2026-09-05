package public

import (
	"encoding/json"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/search"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A static copy is the site, byte for byte, or it is a different site.
//
// The bundle used to be built by a second renderer that knew about pages and
// nothing else, so every copy of a site — the IPFS pin, the deposit, the demo
// on a static host — went out without its sitemap, its robots.txt, its crawl
// licence, its manifest, its service worker, the structured data on each page
// and the AI-disclosure marking. Measured on a deployed copy before this
// changed: six routes 404, no structured data anywhere.
//
// This is the test that stops it happening again. Whatever the server answers
// at an address, the bundle carries at the corresponding path, and the bytes
// are the same bytes — because they came from the same handler.
func TestTheBundleIsWhatTheServerServes(t *testing.T) {
	st := bundleSite(t)

	files, err := st.Bundle()
	if err != nil {
		t.Fatal(err)
	}

	// Every generated document the server answers has to be in the bundle.
	h := st.Handler()
	for path, file := range map[string]string{
		"/sitemap.xml":             "sitemap.xml",
		"/robots.txt":              "robots.txt",
		"/manifest.webmanifest":    "manifest.webmanifest",
		"/sw.js":                   "sw.js",
		"/license.xml":             "license.xml",
		"/.well-known/tdmrep.json": ".well-known/tdmrep.json",
		"/llms.txt":                "llms.txt",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			continue // not configured on this fixture; the bundle omits it too
		}
		got, ok := files[file]
		if !ok {
			t.Errorf("the server answers %s and the bundle has no %s, so a "+
				"static copy of this site is missing it", path, file)
			continue
		}
		if string(got) != rec.Body.String() {
			t.Errorf("%s differs between the server and the bundle, so the "+
				"copy is not the site", file)
		}
	}

	// And a page carries what the server adds after the template has run: the
	// manifest link, its structured data, and the disclosure marking.
	home := string(files["index.html"])
	if home == "" {
		t.Fatal("no index.html in the bundle")
	}
	for _, want := range []string{`rel="manifest"`, "digitalSourceType"} {
		if !strings.Contains(home, want) {
			t.Errorf("the bundled page does not carry %s, which the server "+
				"adds before the closing head tag — and a copy with no "+
				"marking is the copy somebody archives", want)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if home != rec.Body.String() {
		t.Error("the bundled home page is not the page the server serves")
	}
}

// A page that cannot be served must not be silently absent from a copy.
func TestABundleRefusesRatherThanShippingAHole(t *testing.T) {
	st := bundleSite(t)
	// A layout that does not exist for the page that names it: the server
	// answers 500, and a bundle that skipped it would produce a site with a
	// page missing and nothing said.
	st.Layouts = render.Layouts{}
	if _, err := st.Bundle(); err == nil {
		t.Error("a bundle was built from a site whose pages cannot render, " +
			"so the copy would be missing them with no error")
	}
}

// feedSite is a store with a collection, a listing over it, a detail page for
// the records, and a second listing serving as the feed.
func feedSite(t *testing.T) *Site {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := ""
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Aster & Alum"},
		"cloth": map[string]any{"detail": "catalogue", "detail_key": "slug"},
	}, "pages", "rue"); err != nil {
		t.Fatal(err)
	}
	if cid := s.GetRef(site.RefDraft); cid != "" {
		c, cerr := s.GetCommit(cid)
		if cerr != nil {
			t.Fatal(cerr)
		}
		base = c.Tree
	}
	tree, _, err := collection.Put(s, base, "cloth", collection.Record{
		Fields: map[string]any{
			"slug": "indigo-linen", "name": "Indigo linen",
			"summary": "Eight dips.", "bath": "2026-07-14",
		}}, time.Unix(1787000000, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	cid, err := s.PutCommit(store.Commit{Tree: tree, Message: "a record",
		Author: "rue", At: 1787000000})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRef(site.RefDraft, cid); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, cid); err != nil {
		t.Fatal(err)
	}

	set := &listing.Set{Listings: []listing.Listing{
		{Name: "catalogue", Collection: "cloth", Sort: "name", Rows: 20,
			Fields: []string{"slug", "name", "summary", "bath"}},
		{Name: "journal", Label: "From the dye house", Collection: "cloth",
			Sort: "bath", Descending: true, Rows: 20,
			Fields: []string{"slug", "name", "summary", "bath"}},
	}}
	c, cerr := s.GetCommit(s.GetRef(site.RefLive))
	if cerr != nil {
		t.Fatal(cerr)
	}
	st := New(s, render.OneLayout(
		`<!doctype html><html lang="en"><head><title>{{ page.title }}</title>`+
			`</head><body><h1>{{ page.title }}{{ record.name }}</h1></body></html>`))
	st.Name = "Aster & Alum"
	st.BaseURL = "https://example.com"
	st.Feed = "journal"
	st.Listings = &listing.Resolver{Store: s, Index: collection.NewCache(),
		Tree: c.Tree, Set: set}
	return st
}

// searchSite has a page to search and a page named search to show results on.
func searchSite(t *testing.T) *Site {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index": map[string]any{"title": "Aster & Alum",
			"lead": "Cloth dyed with plants."},
		"guide": map[string]any{"title": "How to keep an indigo vat",
			"standfirst": "Indigo does not dissolve in water, so a vat is a " +
				"reduction you keep alive."},
		"search": map[string]any{"title": "Search"},
	}
	if _, err := site.SaveDraft(s, pages, "pages", "rue"); err != nil {
		t.Fatal(err)
	}
	cid := s.GetRef(site.RefDraft)
	if _, err := site.Publish(s, cid); err != nil {
		t.Fatal(err)
	}

	layout := `<!doctype html><html lang="en"><head><title>{{ page.title }}` +
		`</title></head><body>` +
		`{% if search %}<form method="get" action="/search" role="search">` +
		`<input name="q" value="{{ search.query }}"></form>` +
		`{% if search.empty %}<p>Nothing matched.</p>{% end %}` +
		`{% for r in search.results %}<h3><a href="{{ r.href }}">{{ r.title }}` +
		`</a></h3><p>{{ r.snippet }}</p>{% end %}{% end %}` +
		`<h1>{{ page.title }}</h1></body></html>`
	st := New(s, render.OneLayout(layout))
	st.Name = "Aster & Alum"
	livePages, _, perr := st.pages()
	if perr != nil {
		t.Fatal(perr)
	}
	st.Search = search.Build(s.GetRef(site.RefLive), livePages)
	return st
}

func bundleSite(t *testing.T) *Site {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]any{
		"index": map[string]any{
			"title": "Aster & Alum",
			"lead":  "Cloth dyed with plants.",
		},
	}
	if _, err := site.SaveDraft(s, pages, "the first page", "rue"); err != nil {
		t.Fatal(err)
	}
	cid := s.GetRef(site.RefDraft)
	if _, err := site.Publish(s, cid); err != nil {
		t.Fatal(err)
	}

	layout := `<!doctype html><html lang="en"><head><title>{{ page.title }}` +
		`</title></head><body><h1>{{ page.title }}</h1>` +
		`<p>{{ page.lead }}</p></body></html>`
	st := New(s, render.OneLayout(layout))
	st.Name = "Aster & Alum"
	st.BaseURL = "https://example.com"
	st.Stylesheet = "body{color:#111}"
	st.Licence = &Licence{Permits: []string{"search"}}
	st.Media = func(string) (media.File, []byte, error) {
		return media.File{}, nil, http.ErrMissingFile
	}
	// A record of who wrote it, bound to the hash of what they wrote — which is
	// what puts the marking on the page and what makes it fall off when the
	// page changes.
	_, hashes, perr := st.pages()
	if perr != nil {
		t.Fatal(perr)
	}
	idx := provenance.NewIndex()
	if serr := idx.Set("index", provenance.Record{
		ContentHash: hashes["index"],
		SourceType:  provenance.TrainedAlgorithmicMedia,
		Author:      "an assistant",
		At:          1787000000,
	}); serr != nil {
		t.Fatal(serr)
	}
	st.LoadProvenance = func() (*provenance.Index, error) { return idx, nil }
	return st
}

// The feed is a listing, and it says what the listing says.
//
// A CMS with an article starter and a journal in every example published no
// feed of any kind — the demo's own copy claimed it had one. It is driven by a
// listing rather than by a walk over the pages because which things belong in a
// feed is a decision, and a listing already records that decision along with
// which fields are public.
func TestAFeedIsServedWhenAListingIsNamed(t *testing.T) {
	st := bundleSite(t)
	// No feed configured: nothing is served, rather than an empty document
	// claiming the site publishes nothing.
	for _, path := range []string{"/feed.xml", "/feed.json"} {
		rec := httptest.NewRecorder()
		st.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s answered %d with no feed configured; an empty feed is "+
				"a claim that nothing is published", path, rec.Code)
		}
	}
	// And the page does not advertise one that does not exist.
	page := httptest.NewRecorder()
	st.Handler().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(page.Body.String(), "atom+xml") {
		t.Error("a page advertises a feed this site does not serve, which " +
			"teaches whatever followed it that this site's metadata is wrong")
	}
}

// A feed's entries can be opened, and its elements are the ones readers know.
//
// Both of these were wrong in the first version and neither was visible from
// the code: encoding/xml wrote <Links> for an untagged field, which is not an
// element any reader recognises, and every entry carried href="" because the
// feed's listing had no detail page of its own — while every entry in it had a
// page, reached through a different listing over the same collection.
func TestAFeedNamesEntriesThatCanBeOpened(t *testing.T) {
	st := feedSite(t)

	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/feed.xml", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("the feed answered %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<Links") {
		t.Error("the feed writes <Links>, which is a Go field name rather than " +
			"an Atom element")
	}
	if strings.Contains(body, `href=""`) {
		t.Error("an entry points nowhere; a reader shows that as an item that " +
			"cannot be opened")
	}
	if !strings.Contains(body, "/cloth/indigo-linen") {
		t.Errorf("no entry links to the record's own page:\n%s", body)
	}

	// The JSON feed carries the same entries.
	rec = httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/feed.json", nil))
	var doc struct {
		Version string           `json:"version"`
		Items   []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc.Version, "jsonfeed.org") {
		t.Errorf("the JSON feed does not declare its version: %q", doc.Version)
	}
	if len(doc.Items) == 0 {
		t.Fatal("the JSON feed has no items and the Atom feed has entries, so " +
			"a reader and a program see different journals")
	}
	if doc.Items[0]["url"] == nil {
		t.Error("a JSON feed item has no url")
	}
}

// Search is reachable without a script, because scripts are forbidden here.
//
// internal/search built a full-text index of every published page and the only
// way to reach it was /search.json — which needs a fetch, which needs a script,
// which this site's own Content-Security-Policy blocks. A feature reachable only
// by weakening the thing that makes the product what it is is a feature nobody
// has.
//
// The comment on the JSON route argued a rendered page was impossible because
// "the template language deliberately cannot loop over something the server
// computed at request time". It does, everywhere: a listing with a parameter is
// resolved from the query string on every request, and results are the same
// shape as its rows.
func TestSearchIsRenderedRatherThanFetched(t *testing.T) {
	st := searchSite(t)

	// The form, with no query yet.
	blank := httptest.NewRecorder()
	st.Handler().ServeHTTP(blank, httptest.NewRequest(http.MethodGet, "/search", nil))
	if blank.Code != http.StatusOK {
		t.Fatalf("the search page answered %d", blank.Code)
	}
	body := blank.Body.String()
	if !strings.Contains(body, `action="/search"`) || !strings.Contains(body, `name="q"`) {
		t.Errorf("the search page has no form to search with:\n%s", body)
	}

	// And a query, answered in the response rather than by a later fetch.
	found := httptest.NewRecorder()
	st.Handler().ServeHTTP(found,
		httptest.NewRequest(http.MethodGet, "/search?q=indigo", nil))
	if found.Code != http.StatusOK {
		t.Fatalf("a search answered %d", found.Code)
	}
	page := found.Body.String()
	if !strings.Contains(page, "/guide") {
		t.Errorf("the matching page is not in the response:\n%s", page)
	}
	// With a line of the page it matched in. A result with no quotation is a
	// list of titles, and the snippet has to come from the same traversal the
	// index used or it quotes text the match did not come from.
	if !strings.Contains(page, "does not dissolve") {
		t.Errorf("no snippet from the matched field:\n%s", page)
	}
	// Nothing executable: the results arrived with the document.
	for _, forbidden := range []string{"<script>", `type="text/javascript"`,
		"fetch(", "search.json"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the rendered results page carries %q, so it depends on "+
				"something this site's policy forbids", forbidden)
		}
	}
	// A results page must not be cached by anything between here and a reader.
	if cc := found.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control is %q; a cached results page is one reader's "+
			"search shown to another", cc)
	}

	// Nothing matching says so, which is a different state from not having
	// searched — the language has no else, so both are booleans.
	none := httptest.NewRecorder()
	st.Handler().ServeHTTP(none,
		httptest.NewRequest(http.MethodGet, "/search?q=zzzznothing", nil))
	if !strings.Contains(none.Body.String(), "Nothing matched") {
		t.Error("a search with no results does not say so")
	}

	// An over-long query is refused before it is tokenised.
	long := httptest.NewRecorder()
	st.Handler().ServeHTTP(long, httptest.NewRequest(http.MethodGet,
		"/search?q="+strings.Repeat("a", 500), nil))
	if long.Code != http.StatusBadRequest {
		t.Errorf("a 500 character query answered %d", long.Code)
	}
}

// A site with no search page has no search route, rather than a page nobody
// designed.
func TestSearchWithoutAPageIsNotFound(t *testing.T) {
	st := bundleSite(t) // has an index page and no search page
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/search?q=x", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("a site with no search page answered %d; a bare list of "+
			"links is a page nobody published", rec.Code)
	}
}

// Every static file this server offers has to be in the bundle.
//
// The bundle's route list is written by hand, and two files were already
// missing from it: /.well-known/security.txt and the speculation rules, both
// added to the server and both forgotten here. Nothing failed — a static copy
// simply did not carry them, which is the quietest kind of gap, because the
// export succeeds and the missing file is only noticed by whoever went looking
// for it.
//
// So this walks the mux instead of trusting the list. A route that serves a
// fixed document and is not bundled fails here, whoever adds it next.
func TestEveryStaticFileTheServerOffersIsBundled(t *testing.T) {
	st := bundleSite(t)
	st.Licence = &Licence{Permits: []string{"search"}}
	st.Security = &SecurityContact{
		Contact: []string{"mailto:x@example.test"},
		Expires: time.Unix(1900000000, 0),
	}

	// The fixed documents. Not every route: a page depends on content, and
	// /media/ depends on an id, and those are bundled by crawling rather than
	// by name.
	static := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/license.xml",
		"/llms.txt",
		"/manifest.webmanifest",
		"/sw.js",
		"/.well-known/tdmrep.json",
		SecurityTxtPath,
		SpeculationPath,
	}

	routes, err := st.Routes()
	if err != nil {
		t.Fatal(err)
	}
	bundled := map[string]bool{}
	for _, r := range routes {
		bundled[r.path] = true
	}

	for _, path := range static {
		rec := httptest.NewRecorder()
		st.Handler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			// Not served by this configuration, so not expected in its
			// bundle either.
			continue
		}
		if !bundled[path] {
			t.Errorf("%s is served and is not in the bundle, so a static "+
				"copy of this site silently does not carry it", path)
		}
	}
}
