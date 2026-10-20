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
