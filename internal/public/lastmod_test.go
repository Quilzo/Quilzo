// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/seo"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// sitemap is /sitemap.xml as a crawler gets it.
func sitemap(t *testing.T, st *Site) string {
	t.Helper()
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/sitemap.xml answered %d", w.Code)
	}
	return w.Body.String()
}

// The sitemap's dates are worked out once per publish, not once per crawl.
//
// Each page's lastmod is found by walking back through up to five thousand
// commits of history and reading the tree of each, and the sitemap did that
// on every request: about 11 ms for a one-page site after five hundred
// publishes and rising with every one, on the address crawlers ask for most,
// unauthenticated. The dates are a fact about the commit the site serves, as
// fixed as the commit is, and only a publish changes which commit that is.
func TestTheSitemapWalksTheHistoryOncePerPublish(t *testing.T) {
	st := published(t, map[string]any{"index": map[string]any{"title": "Home"}})
	var walks atomic.Int32
	st.LastChanged = func(head string) (map[string]time.Time, error) {
		walks.Add(1)
		return seo.LastChanged(st.Store, head, 5000)
	}

	for i := 0; i < 5; i++ {
		sitemap(t, st)
	}
	if n := walks.Load(); n != 1 {
		t.Errorf("five requests for the sitemap walked the history %d times", n)
	}

	// A publish is a different commit, and the walk is done again for it.
	if _, err := site.SaveDraft(st.Store, map[string]any{
		"index": map[string]any{"title": "Home, again"}}, "second", "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(st.Store, ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		sitemap(t, st)
	}
	if n := walks.Load(); n != 2 {
		t.Errorf("after a publish, ten requests walked the history %d times; expected 2", n)
	}
}

// The date a crawler is given after a publish is the publish's. Remembering
// the dates is only safe because a publish is a new key, and this is the
// test that says so: a page changed and republished is never listed with the
// date it had before. The first version is dated 2020, because the sitemap
// gives a day and both publishes would otherwise be today.
func TestThePageChangedByAPublishCarriesItsDateAtOnce(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tree, err := store.BuildTree(s, map[string]any{
		"index": map[string]any{"title": "Home"},
		"about": map[string]any{"title": "About"},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.PutCommit(store.Commit{Tree: tree, Message: "first", Author: "t",
		At: time.Date(2020, 3, 1, 12, 0, 0, 0, time.UTC).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRef(site.RefDraft, first); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, first); err != nil {
		t.Fatal(err)
	}
	st := New(s, render.OneLayout(tpl))
	st.BaseURL = "https://example.org"
	st.LastChanged = func(head string) (map[string]time.Time, error) {
		return seo.LastChanged(s, head, 5000)
	}

	entry := func(xml, loc string) string {
		t.Helper()
		i := strings.Index(xml, "<loc>"+loc+"</loc>")
		if i < 0 {
			t.Fatalf("%s is not in the sitemap:\n%s", loc, xml)
		}
		rest := xml[i:]
		if j := strings.Index(rest, "</url>"); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
	before := sitemap(t, st)
	if got := entry(before, "https://example.org/about"); !strings.Contains(got, "2020-03-01") {
		t.Fatalf("about was published in 2020 and is listed as %s", got)
	}

	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"},
		"about": map[string]any{"title": "About us"},
	}, "about changed", "t"); err != nil {
		t.Fatal(err)
	}
	pub, err := site.Publish(s, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCommit(pub.Published)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(c.At, 0).UTC().Format("2006-01-02")
	after := sitemap(t, st)
	if got := entry(after, "https://example.org/about"); !strings.Contains(got, want) {
		t.Errorf("about changed in a publish on %s and the sitemap lists %s", want, got)
	}
	if got := entry(after, "https://example.org/"); !strings.Contains(got, "2020-03-01") {
		t.Errorf("index did not change and is listed as %s", got)
	}
}
