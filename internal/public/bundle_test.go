package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
