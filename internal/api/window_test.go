// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/vector"
)

// windowed publishes a page whose window opens in twenty minutes and one
// whose window closes in ten, beside the fixture's three, and gives the
// server a vector index of what is live, as `quilzo site --api` does.
func windowed(t *testing.T) (*Server, string, time.Time) {
	t.Helper()
	s, tok, _ := setup(t)
	start := time.Now()
	pages, err := site.PagesAt(s.Store, site.RefLive)
	if err != nil {
		t.Fatal(err)
	}
	pages["embargoed"] = map[string]any{"title": "Merger",
		"body":   "The merger is announced at noon.",
		"starts": start.Add(20 * time.Minute).UTC().Format(time.RFC3339)}
	pages["expiring"] = map[string]any{"title": "Offer",
		"body":    "The offer ends soon.",
		"expires": start.Add(10 * time.Minute).UTC().Format(time.RFC3339)}
	if _, err := site.SaveDraft(s.Store, pages, "windows", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s.Store, ""); err != nil {
		t.Fatal(err)
	}
	words := func(text string) []string { return strings.Fields(strings.ToLower(text)) }
	s.Tokenise = words
	s.Vectors = func() *vector.Index {
		live := s.Store.GetRef(site.RefLive)
		all, err := site.PagesAt(s.Store, live)
		if err != nil {
			t.Fatal(err)
		}
		return vector.Build(live, all, words)
	}
	return s, tok, start
}

// listed is the names a listing answered with, and its validator.
func listed(t *testing.T, s *Server, tok string, headers map[string]string) (map[string]bool, Listing, *http.Response) {
	t.Helper()
	w := req(t, s, "GET", "/api/v1/pages", tok, nil, headers)
	got := map[string]bool{}
	var l Listing
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		for _, p := range l.Pages {
			got[p.Name] = true
		}
	}
	return got, l, w.Result()
}

// A page is not served before its publish window opens, or after it closes.
//
// The public site asks every page's window at the moment it is asked for
// it, so an embargo cannot lift because a job was wedged. The content API
// asked nothing: a page set to start at noon was in the listing, readable
// by name and named among the similar pages from the moment it was
// published, to any read token, and a page past its expires date stayed
// there. The window is a property of the content, so it holds on every
// surface that serves the content as published.
func TestAPageOutsideItsPublishWindowIsNotServedByTheAPI(t *testing.T) {
	s, tok, start := windowed(t)
	s.Now = func() time.Time { return time.Now() }

	if w := req(t, s, "GET", "/api/v1/pages/embargoed", tok, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("an embargoed page answered %d: %s", w.Code, w.Body)
	}
	if w := req(t, s, "GET", "/api/v1/pages/expiring", tok, nil, nil); w.Code != http.StatusOK {
		t.Errorf("a page inside its window answered %d", w.Code)
	}
	names, before, res := listed(t, s, tok, nil)
	if names["embargoed"] {
		t.Error("the listing named an embargoed page")
	}
	if !names["expiring"] || before.Total != 4 {
		t.Errorf("the listing is %v with a total of %d; want the four pages "+
			"inside their windows", names, before.Total)
	}
	etag := res.Header.Get("ETag")
	for _, path := range []string{"/api/v1/search/vector?q=merger", "/api/v1/similar/expiring"} {
		if w := req(t, s, "GET", path, tok, nil, nil); strings.Contains(w.Body.String(), "embargoed") {
			t.Errorf("%s named an embargoed page: %s", path, w.Body)
		}
	}
	if w := req(t, s, "GET", "/api/v1/similar/embargoed", tok, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("similar pages to an embargoed one answered %d, which says it exists", w.Code)
	}

	// Half an hour on, the one window has opened and the other closed, and
	// nothing was published in between: the commit is the same.
	s.Now = func() time.Time { return start.Add(30 * time.Minute) }
	if w := req(t, s, "GET", "/api/v1/pages/expiring", tok, nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("an expired page answered %d", w.Code)
	}
	if w := req(t, s, "GET", "/api/v1/pages/embargoed", tok, nil, nil); w.Code != http.StatusOK {
		t.Errorf("a page whose window has opened answered %d", w.Code)
	}
	names, _, _ = listed(t, s, tok, nil)
	if names["expiring"] || !names["embargoed"] {
		t.Errorf("half an hour on the listing is %v", names)
	}
	// And the listing's validator moved with it, or a client holding the
	// earlier one is told 304 and keeps the expired page and never sees
	// the one that opened.
	if _, _, res := listed(t, s, tok, map[string]string{"If-None-Match": etag}); res.StatusCode != http.StatusOK {
		t.Errorf("a listing whose pages changed with the clock answered %d to "+
			"the validator of what it was before", res.StatusCode)
	}
}
