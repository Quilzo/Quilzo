// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"net/http"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// emptyStore is a store with nothing published.
func emptyStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The sitemap is fetched by every search engine that indexes the site, and it
// served a kilobyte with no ETag and no Cache-Control at all — so every
// crawler took all of it every time, whatever it already had.
//
// Found by listing the validators across every route on a running server.
func TestTheSitemapHasAValidator(t *testing.T) {
	st, _ := setup(t)
	st.BaseURL = "https://example.test"

	first := get(st, "/sitemap.xml", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("the sitemap returned %d", first.Code)
	}
	tag := first.Header().Get("ETag")
	if tag == "" {
		t.Fatal("the sitemap serves no ETag, so every crawl is a full transfer")
	}
	if first.Header().Get("Cache-Control") == "" {
		t.Error("the sitemap serves no Cache-Control")
	}

	again := get(st, "/sitemap.xml", map[string]string{"If-None-Match": tag})
	if again.Code != http.StatusNotModified {
		t.Fatalf("a crawler holding the sitemap was sent it again (%d)", again.Code)
	}
	if again.Body.Len() != 0 {
		t.Errorf("a 304 carried %d bytes", again.Body.Len())
	}
}

// And it moves when the content does, or it is a sitemap that never updates.
func TestTheSitemapTagMovesWithAPublish(t *testing.T) {
	st, s := setup(t)
	st.BaseURL = "https://example.test"
	before := get(st, "/sitemap.xml", nil).Header().Get("ETag")

	pages, _ := site.PagesAt(s, site.RefLive)
	pages["extra"] = map[string]any{"title": "Extra", "body": "New."}
	if _, err := site.SaveDraft(s, pages, "add a page", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	after := get(st, "/sitemap.xml", nil).Header().Get("ETag")
	if after == before {
		t.Fatalf("a page was published and the sitemap tag did not move (%s)",
			before)
	}
	if stale := get(st, "/sitemap.xml",
		map[string]string{"If-None-Match": before}); stale.Code == http.StatusNotModified {
		t.Error("a stale tag still answered 304 after a publish")
	}
}

// Two documents built from the same commit are not the same bytes, so they
// must not carry the same tag: a cache holding one would be told the other had
// not changed.
func TestDocumentsFromOneCommitDoNotShareATag(t *testing.T) {
	st, _ := setup(t)

	seen := map[string]string{}
	for _, what := range []string{"sitemap", "feed-atom", "feed-json"} {
		tag := st.contentTag(what)
		if tag == "" {
			t.Fatalf("%s has no tag", what)
		}
		if other, clash := seen[tag]; clash {
			t.Errorf("%s and %s carry the same tag %s", what, other, tag)
		}
		seen[tag] = what
	}
}

// Nothing published is no version to name, so no validator is sent — rather
// than one that would claim an empty document had a version.
func TestNothingPublishedSendsNoValidator(t *testing.T) {
	st := &Site{Store: emptyStore(t)}
	if tag := st.contentTag("sitemap"); tag != "" {
		t.Errorf("an unpublished site produced the tag %s", tag)
	}
}
