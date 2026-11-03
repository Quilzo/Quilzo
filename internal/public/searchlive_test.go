// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
)

// A page published while the server runs is found by its search, and one
// taken down is not: the index follows the live commit.
func TestSearchFollowsWhatIsPublished(t *testing.T) {
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Home", "body": "Paper made in small runs."},
	})
	st.IndexLive = true
	ask := func(q string) string {
		w := httptest.NewRecorder()
		st.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/search.json?q="+q, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("search answered %d", w.Code)
		}
		return w.Body.String()
	}
	if !strings.Contains(ask("paper"), `"index"`) {
		t.Fatal("the page published before the first search was not found")
	}
	if _, err := site.SaveDraft(st.Store, map[string]any{
		"index":    map[string]any{"title": "Home", "body": "Paper made in small runs."},
		"inkwells": map[string]any{"title": "Inkwells", "body": "Brass inkwells, filled by hand."},
	}, "add inkwells", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(st.Store, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ask("brass"), `"inkwells"`) {
		t.Error("a page published while the server ran was not found")
	}
	first := st.searchIndex()
	if st.searchIndex() != first {
		t.Error("the index was built again with nothing published since")
	}
}

// What a visitor's search scores say depends only on the pages they may
// read. The index counted pages behind a publish window and pages for
// members, and /search.json and /ask return each result's score, so a
// visible page's score for "merger" fell when an embargoed press release
// mentioning one was published: the hidden page was never named, and its
// words changed the number.
func TestSearchScoresSayNothingOfPagesAVisitorCannotRead(t *testing.T) {
	scores := func(t *testing.T, hidden map[string]any) (float64, float64) {
		t.Helper()
		pages := map[string]any{
			"index": map[string]any{"title": "Home", "body": "Welcome to Acme, makers of tools."},
			"about": map[string]any{"title": "About", "body": "Acme began with the merger of two workshops."},
			"shop":  map[string]any{"title": "Shop", "body": "Tools, parts and repairs."},
		}
		for k, v := range hidden {
			pages[k] = v
		}
		st := published(t, pages)
		st.IndexLive = true
		found := askJSON(t, st, "/search.json?q=merger")["results"].([]any)
		asked := askJSON(t, st, "/ask?query=merger&streaming=false")["results"].([]any)
		if len(found) != 1 || len(asked) != 1 || found[0].(map[string]any)["page"] != "about" {
			t.Fatalf("results: %v / %v", found, asked)
		}
		return found[0].(map[string]any)["score"].(float64), asked[0].(map[string]any)["score"].(float64)
	}
	plain, plainAsked := scores(t, map[string]any{
		"later": map[string]any{"title": "Later", "body": "Opening hours change in the spring.", site.Starts: "2099-01-01"}})
	for name, hidden := range map[string]map[string]any{
		"an embargoed page": {"later": map[string]any{"title": "Later", "body": "The merger is announced today.",
			site.Starts: "2099-01-01"}},
		"a page for members": {"lounge": map[string]any{"title": "Lounge", "body": "Members talk of the merger.",
			MembersOnlyField: true}},
	} {
		found, asked := scores(t, hidden)
		if found != plain || asked != plainAsked {
			t.Errorf("with %s mentioning the word, the visible page scored %.4f and %.4f, not %.4f and %.4f",
				name, found, asked, plain, plainAsked)
		}
	}
}

// The visible pages' index follows the set a visitor may read, which a
// publish window changes with nothing published: a page whose window has
// opened is found, and the index is built once per set, not per search.
func TestSearchFollowsAPublishWindowOpening(t *testing.T) {
	st := published(t, map[string]any{
		"index": map[string]any{"title": "Home", "body": "Paper made in small runs."},
		"later": map[string]any{"title": "Inkwells", "body": "Brass inkwells, filled by hand."},
	})
	st.IndexLive = true
	all, oids, err := st.pages()
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]any{"index": all["index"]}
	if got := st.searchVisible("brass", before, oids, 10); len(got) != 0 {
		t.Fatalf("a page outside the visible set was found: %v", got)
	}
	idx := st.visibleSearch(before, oids)
	if st.visibleSearch(before, oids) != idx {
		t.Error("the index was built again for the same pages")
	}
	if got := st.searchVisible("brass", all, oids, 10); len(got) != 1 || got[0].Page != "later" {
		t.Fatalf("a page whose window opened was not found: %v", got)
	}
}
